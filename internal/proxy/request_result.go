package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

type RequestResultReporter interface {
	ReportRequestResult(context.Context, domain.ProxyRequestResult) (domain.RequestResultReceipt, error)
}

type RequestResultReporterFunc func(context.Context, domain.ProxyRequestResult) (domain.RequestResultReceipt, error)

func (f RequestResultReporterFunc) ReportRequestResult(ctx context.Context, result domain.ProxyRequestResult) (domain.RequestResultReceipt, error) {
	return f(ctx, result)
}

func (authorizer IPCRequestAuthorizer) ReportRequestResult(ctx context.Context, result domain.ProxyRequestResult) (domain.RequestResultReceipt, error) {
	if authorizer.Client == nil || authorizer.Generation != 0 && result.ConfigGeneration != authorizer.Generation {
		return domain.RequestResultReceipt{}, ErrGateDecisionInvalid
	}
	result.EngineInstanceID = authorizer.EngineInstanceID
	var receipt domain.RequestResultReceipt
	meta, err := authorizer.Client.CallAtGeneration(ctx, gateipc.ReportRequestResult, result, &receipt, result.ConfigGeneration)
	if err != nil {
		return domain.RequestResultReceipt{}, err
	}
	if meta.DecisionID != result.DecisionID || meta.ConfigGeneration != result.ConfigGeneration ||
		receipt.DecisionID != result.DecisionID || receipt.RequestID != result.RequestID || receipt.ConfigGeneration != result.ConfigGeneration {
		return domain.RequestResultReceipt{}, ErrGateDecisionInvalid
	}
	return receipt, nil
}

// Reporting has its own bounded deadline, including when the downstream
// canceled. It never retries a request, changes a verdict or spawns a backlog.
func (gate *HTTP1RequestGate) reportResult(ctx context.Context, result domain.ProxyRequestResult) {
	if gate.ResultReporter == nil {
		return
	} // standalone library gates may omit telemetry
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if _, err := gate.ResultReporter.ReportRequestResult(ctx, result); err != nil {
		gate.counters.resultReportFail.Add(1)
	}
}

type gateUpstreamTransport struct {
	*http.Transport
	tlsStates upstreamTLSRegistry
	secure    bool
}

// GotConn binds metadata to the socket actually used, including keep-alive/H2
// reuse. The per-request slot also covers a TLS 1.3 alert racing GotConn before
// the transport has handed over its just-closed connection.
func (transport *gateUpstreamTransport) roundTrip(request *http.Request) (*http.Response, bool, error) {
	var auth atomic.Pointer[upstreamClientAuth]
	ctx := context.WithValue(request.Context(), upstreamAuthContextKey{}, &auth)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if state := transport.tlsStates.get(info.Conn); state != nil {
			auth.Store(state)
		}
	}})
	response, err := transport.Transport.RoundTrip(request.WithContext(ctx))
	state := auth.Load()
	requested := state != nil && state.requested.Load()
	if err != nil && transport.secure {
		err = classifyUpstreamTLSFailure(err, requested)
	}
	return response, requested, err
}

func upstreamFailureCode(err error, secure bool) string {
	switch {
	case errors.Is(err, ErrUpstreamMTLS):
		return "TLS_UPSTREAM_MTLS_UNSUPPORTED"
	case errors.Is(err, ErrUpstreamVerify):
		return "TLS_UPSTREAM_VERIFY_FAILED"
	case errors.Is(err, ErrUpstreamHandshake):
		return "TLS_UPSTREAM_HANDSHAKE_FAILED"
	case secure:
		return "TLS_UPSTREAM_CONNECT_FAILED"
	default:
		return "UPSTREAM_CONNECT_FAILED"
	}
}
