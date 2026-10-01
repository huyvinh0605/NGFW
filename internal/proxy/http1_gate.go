package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/requestworker"
	"golang.org/x/net/http2"
)

// RequestInspector returns evidence, never an ALLOW/BLOCK verdict.
type RequestInspector interface {
	InspectRequest(context.Context, string, inspection.GateHTTPRequest) (domain.RequestInspectionResult, error)
}

type RequestInspectorFunc func(context.Context, string, inspection.GateHTTPRequest) (domain.RequestInspectionResult, error)

func (f RequestInspectorFunc) InspectRequest(ctx context.Context, id string, request inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
	return f(ctx, id, request)
}

// SuricataRequestInspector is the production adapter from a bounded worker
// pool to normalized, job-correlated evidence. It owns no policy decision.
type SuricataRequestInspector struct {
	Pool        *requestworker.Pool
	RulesetID   string
	RulesetHash string
}

func (inspector SuricataRequestInspector) InspectRequest(ctx context.Context, id string, request inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
	if inspector.Pool == nil {
		return domain.RequestInspectionResult{}, requestworker.ErrUnavailable
	}
	job, err := inspector.Pool.Inspect(ctx, id, request)
	if err != nil {
		return domain.RequestInspectionResult{}, err
	}
	return requestworker.NormalizeEVE(job, inspector.RulesetID, inspector.RulesetHash), nil
}

type RequestAuthorizer interface {
	EvaluateRequest(context.Context, domain.ProxyRequestEvaluation, uint64) (domain.RequestDecision, error)
}

type RequestAuthorizerFunc func(context.Context, domain.ProxyRequestEvaluation, uint64) (domain.RequestDecision, error)

func (f RequestAuthorizerFunc) EvaluateRequest(ctx context.Context, evaluation domain.ProxyRequestEvaluation, generation uint64) (domain.RequestDecision, error) {
	return f(ctx, evaluation, generation)
}

// IPCRequestAuthorizer validates the authoritative engine response. A proxy
// cannot turn a missing, stale or malformed engine reply into an ALLOW.
type IPCRequestAuthorizer struct{ Client *gateipc.Client }

func (authorizer IPCRequestAuthorizer) EvaluateRequest(ctx context.Context, evaluation domain.ProxyRequestEvaluation, generation uint64) (domain.RequestDecision, error) {
	if authorizer.Client == nil {
		return domain.RequestDecision{}, ErrGateDecisionInvalid
	}
	var decision domain.RequestDecision
	meta, err := authorizer.Client.CallAtGeneration(ctx, gateipc.EvaluateRequest, evaluation, &decision, generation)
	if err != nil {
		return domain.RequestDecision{}, err
	}
	if meta.DecisionID != decision.DecisionID || meta.ConfigGeneration != decision.ConfigGeneration || !validRequestDecision(evaluation.Context, decision, generation) {
		return domain.RequestDecision{}, ErrGateDecisionInvalid
	}
	return decision, nil
}

func validRequestDecision(request domain.RequestContext, decision domain.RequestDecision, minimumGeneration uint64) bool {
	if decision.DecisionID == "" || decision.RequestID != request.RequestID || decision.ConfigGeneration < minimumGeneration || !decision.Coverage.Valid() || decision.ReasonCode == "" {
		return false
	}
	switch decision.Verdict {
	case domain.RequestAllow:
		return decision.HTTPStatus == 0
	case domain.RequestBlock:
		return decision.HTTPStatus == http.StatusForbidden || decision.HTTPStatus == http.StatusRequestEntityTooLarge || decision.HTTPStatus == http.StatusServiceUnavailable || decision.HTTPStatus == http.StatusBadRequest
	default:
		return false
	}
}

// HTTP1RequestGate keeps a single downstream HTTP/1.1 connection in the Go
// server parser. One bounded inspection and engine verdict gates each request.
// TLS HTTP/1.1 uses verified upstream TLS. HTTP/2 streams reuse only the
// connection-scoped identity allocator; each request has its own gate state.
type HTTP1RequestGate struct {
	Limits       domain.RequestGateConfig
	Inspector    RequestInspector
	Authorizer   RequestAuthorizer
	DialContext  func(context.Context, string, string) (net.Conn, error)
	Roots        *x509.CertPool
	counters     requestGateCounters
	requestSlots chan struct{}
	mu           sync.Mutex
}

func (gate *HTTP1RequestGate) acquire() bool {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.requestSlots == nil {
		gate.requestSlots = make(chan struct{}, gate.Limits.WithDefaults().MaxConcurrentRequests)
	}
	select {
	case gate.requestSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (gate *HTTP1RequestGate) release() { <-gate.requestSlots }

func (gate *HTTP1RequestGate) ServeHTTPConnection(ctx context.Context, downstream net.Conn, value ConnectionContext, connectionDecision domain.ProxyConnectionDecision) error {
	if gate == nil || ctx == nil || downstream == nil || gate.Authorizer == nil || !value.OriginalDestination.IsValid() || connectionDecision.ConfigGeneration == 0 || connectionDecision.UpstreamIP != value.OriginalDestination.Addr().Unmap().String() || connectionDecision.UpstreamPort != int(value.OriginalDestination.Port()) {
		return ErrGateHandlerMissing
	}
	if value.TLS {
		secure, ok := downstream.(*tls.Conn)
		if !ok || !secure.ConnectionState().HandshakeComplete || connectionDecision.Action != domain.TLSGateDecrypt {
			return ErrGateHandlerMissing
		}
		protocol := secure.ConnectionState().NegotiatedProtocol
		if protocol != "" && protocol != "http/1.1" && protocol != "h2" {
			return ErrGateHandlerMissing
		}
	} else if connectionDecision.Action != domain.TLSGateInspectHTTP {
		return ErrGateHandlerMissing
	}
	limits := gate.Limits.WithDefaults()
	if limits.MaxConcurrentRequests < 1 || limits.MaxConcurrentRequests > 4096 || limits.MaxHTTP2Streams < 1 || limits.MaxHTTP2Streams > 256 || limits.MaxPerClientRequests < 1 || limits.MaxPerClientRequests > 256 || limits.MaxHeaderBytes < 1 || limits.MaxHeaderBytes > 64<<10 || limits.MaxRawBodyBytes < 1 || limits.MaxRawBodyBytes > 1<<20 || limits.RequestTimeoutMillis < 100 || limits.RequestTimeoutMillis > 30000 {
		return inspection.ErrGateHTTPMalformed
	}
	allocator, err := NewRequestIdentityAllocator(value.ConnectionID)
	if err != nil {
		return err
	}
	server := &http.Server{
		MaxHeaderBytes:    limits.MaxHeaderBytes,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			gate.handleRequest(w, request, downstream, value, connectionDecision, allocator, limits)
		}),
	}
	if value.TLS && downstream.(*tls.Conn).ConnectionState().NegotiatedProtocol == "h2" {
		stop := context.AfterFunc(ctx, func() { _ = downstream.Close() })
		defer stop()
		streams := min(limits.MaxHTTP2Streams, limits.MaxPerClientRequests)
		h2 := &http2.Server{
			MaxConcurrentStreams: uint32(streams), MaxDecoderHeaderTableSize: 4096,
			MaxEncoderHeaderTableSize: 4096, MaxReadFrameSize: 16 << 10,
			MaxUploadBufferPerConnection: 256 << 10, MaxUploadBufferPerStream: 64 << 10,
			IdleTimeout: 30 * time.Second,
		}
		h2.ServeConn(downstream, &http2.ServeConnOpts{Context: ctx, BaseConfig: server, Handler: server.Handler})
		return nil
	}
	listener := newOneConnectionListener(downstream)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close(); _ = downstream.Close() })
	defer stop()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (gate *HTTP1RequestGate) handleRequest(w http.ResponseWriter, request *http.Request, downstream net.Conn, connection ConnectionContext, connectionDecision domain.ProxyConnectionDecision, allocator *RequestIdentityAllocator, limits domain.RequestGateConfig) {
	gate.counters.intercepted.Add(1)
	if request.ProtoMajor != 1 && request.ProtoMajor != 2 || request.ProtoMajor == 1 && request.ProtoMinor != 1 || request.ProtoMajor == 2 && request.ProtoMinor != 0 || request.Method == http.MethodConnect || request.Header.Get("Upgrade") != "" {
		writeGateStatus(w, request, http.StatusBadRequest)
		return
	}
	if !gate.acquire() {
		gate.counters.capacityRejected.Add(1)
		writeGateStatus(w, request, http.StatusServiceUnavailable)
		return
	}
	defer gate.release()
	gate.counters.activeRequests.Add(1)
	defer gate.counters.activeRequests.Add(-1)
	requestCtx, cancel := context.WithTimeout(request.Context(), time.Duration(limits.RequestTimeoutMillis)*time.Millisecond)
	defer cancel()
	// HTTP/1.1 has one active body reader per connection. A network read
	// deadline makes a slow/truncated body release its bounded request slot.
	// HTTP/2 streams share the TCP connection, so the stream body is canceled
	// through its own context instead of setting a connection-wide deadline.
	if request.ProtoMajor == 1 {
		if err := downstream.SetReadDeadline(deadlineOf(requestCtx)); err != nil {
			writeGateStatus(w, request, http.StatusServiceUnavailable)
			return
		}
	}
	body, err := ReadGateRequestBody(requestCtx, request.Body, limits.MaxRawBodyBytes)
	if request.ProtoMajor == 1 {
		_ = downstream.SetReadDeadline(time.Time{})
	}
	if err != nil {
		status := http.StatusBadRequest
		var networkError net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() || !time.Now().Before(deadlineOf(requestCtx)) {
			gate.counters.inspectionTimeout.Add(1)
			status = http.StatusServiceUnavailable
		}
		writeGateStatus(w, request, status)
		return
	}
	defer body.Close()
	requestContext, normalized, err := allocator.NormalizeBufferedRequest(request, body, connectionDecision.SessionID, connection.TLS, limits)
	if err != nil {
		writeGateStatus(w, request, gateParseStatus(err))
		return
	}
	if requestContext.Truncated && len(request.Trailer) != 0 {
		writeGateStatus(w, request, http.StatusBadRequest)
		return
	}
	evidence := domain.RequestInspectionResult{RequestID: requestContext.RequestID, Coverage: domain.RequestCoverageUnavailable, ErrorCode: "GATE_SENSOR_UNAVAILABLE"}
	if requestContext.Truncated {
		gate.counters.bodyLimit.Add(1)
		evidence.Coverage = domain.RequestCoveragePartial
		evidence.ErrorCode = "GATE_REQUEST_TOO_LARGE"
	} else {
		decoded, decodeErr := inspection.DecodeGateBody(requestCtx, normalized.ContentEncoding, normalized.Body, false, limits.MaxDecompressedBodyBytes, limits.MaxDecompressionRatio)
		if decodeErr != nil {
			evidence.ErrorCode = inspectionFailureCode(decodeErr)
		} else {
			requestContext.DecodedBodyBytes = len(decoded)
			normalized.Body = decoded
			if gate.Inspector != nil {
				// Reserve the final quarter of the request deadline for the engine.
				remaining := time.Until(deadlineOf(requestCtx))
				inspectCtx, inspectCancel := context.WithTimeout(requestCtx, max(time.Millisecond, remaining*3/4))
				result, inspectErr := gate.Inspector.InspectRequest(inspectCtx, requestContext.RequestID, normalized)
				inspectCancel()
				if inspectErr != nil {
					evidence.ErrorCode = inspectionFailureCode(inspectErr)
				} else if result.RequestID == requestContext.RequestID && result.Coverage.Valid() {
					evidence = result
				}
			}
		}
	}
	switch evidence.ErrorCode {
	case "GATE_INSPECTION_TIMEOUT":
		gate.counters.inspectionTimeout.Add(1)
	case "GATE_QUEUE_FULL":
		gate.counters.queueRejected.Add(1)
	case "GATE_DECOMPRESSION_LIMIT":
		gate.counters.decompressionLimit.Add(1)
	}
	decision, err := gate.Authorizer.EvaluateRequest(requestCtx, domain.ProxyRequestEvaluation{Context: requestContext, Inspection: evidence}, connectionDecision.ConfigGeneration)
	if err != nil || !validRequestDecision(requestContext, decision, connectionDecision.ConfigGeneration) {
		gate.counters.engineUnavailable.Add(1)
		writeGateStatus(w, request, http.StatusServiceUnavailable)
		return
	}
	if decision.Verdict != domain.RequestAllow {
		gate.counters.requestBlocked.Add(1)
		if decision.HTTPStatus == http.StatusServiceUnavailable || decision.HTTPStatus == http.StatusRequestEntityTooLarge {
			gate.counters.failClose.Add(1)
		}
		writeGateStatus(w, request, decision.HTTPStatus)
		return
	}
	gate.counters.requestAllowed.Add(1)
	if decision.Coverage != domain.CoverageComplete {
		gate.counters.failOpen.Add(1)
	}
	replay, err := body.ReplayAfterAllow(decision, requestContext.RequestID)
	if err != nil {
		writeGateStatus(w, request, http.StatusServiceUnavailable)
		return
	}
	defer replay.Close()
	gate.forwardAllowed(w, request, replay, connection.OriginalDestination, connection.TLS, connectionDecision.UpstreamHost)
}

func deadlineOf(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline
}

func gateParseStatus(err error) int {
	switch {
	case errors.Is(err, inspection.ErrGateHeadersTooLarge):
		return http.StatusRequestHeaderFieldsTooLarge
	case errors.Is(err, inspection.ErrGateURLTooLong):
		return http.StatusRequestURITooLong
	case errors.Is(err, inspection.ErrGateBodyTooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusBadRequest
	}
}

func inspectionFailureCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "GATE_INSPECTION_TIMEOUT"
	case errors.Is(err, requestworker.ErrQueueFull):
		return "GATE_QUEUE_FULL"
	case errors.Is(err, inspection.ErrGateUnsupportedEncoding):
		return "GATE_UNSUPPORTED_ENCODING"
	case errors.Is(err, inspection.ErrGateDecompressionInvalid):
		return "GATE_REQUEST_MALFORMED"
	case errors.Is(err, inspection.ErrGateDecompressionLimit):
		return "GATE_DECOMPRESSION_LIMIT"
	default:
		return "GATE_SENSOR_UNAVAILABLE"
	}
}

func writeGateStatus(w http.ResponseWriter, request *http.Request, status int) {
	if request.ProtoMajor == 1 {
		request.Close = true // A denied/partial HTTP/1 body must not become the next request.
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}

func (gate *HTTP1RequestGate) forwardAllowed(w http.ResponseWriter, inbound *http.Request, body io.ReadCloser, target netip.AddrPort, secure bool, hostname string) {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	requestURL := &url.URL{Scheme: scheme, Host: target.String(), Path: inbound.URL.Path, RawPath: inbound.URL.RawPath, RawQuery: inbound.URL.RawQuery, ForceQuery: inbound.URL.ForceQuery}
	upstream, err := http.NewRequestWithContext(inbound.Context(), inbound.Method, requestURL.String(), body)
	if err != nil {
		writeGateStatus(w, inbound, http.StatusBadRequest)
		return
	}
	upstream.URL = requestURL
	upstream.Host = inbound.Host
	upstream.Header = inbound.Header.Clone()
	stripHopHeaders(upstream.Header)
	upstream.ContentLength = inbound.ContentLength
	upstream.Trailer = inbound.Trailer.Clone()
	upstream.Close = true
	dial := gate.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: dial, DisableKeepAlives: true,
		DisableCompression: true, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	if secure {
		transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			if inbound.ProtoMajor == 2 {
				return DialVerifiedUpstream(ctx, target, hostname, gate.Roots, dial)
			}
			return DialVerifiedUpstreamHTTP1(ctx, target, hostname, gate.Roots, dial)
		}
		if inbound.ProtoMajor == 2 {
			h2, err := http2.ConfigureTransports(transport)
			if err != nil {
				writeGateStatus(w, inbound, http.StatusBadGateway)
				return
			}
			h2.MaxHeaderListSize = 64 << 10
			h2.MaxReadFrameSize = 16 << 10
			h2.MaxDecoderHeaderTableSize = 4096
			h2.MaxEncoderHeaderTableSize = 4096
			h2.StrictMaxConcurrentStreams = true
			h2.IdleConnTimeout = 5 * time.Second
		}
	}
	defer transport.CloseIdleConnections()
	forwardCtx, cancel := context.WithTimeout(inbound.Context(), 30*time.Second)
	defer cancel()
	response, err := transport.RoundTrip(upstream.WithContext(forwardCtx))
	if err != nil {
		if errors.Is(err, ErrUpstreamVerify) {
			gate.counters.upstreamVerifyFail.Add(1)
		} else {
			gate.counters.upstreamConnectFail.Add(1)
		}
		writeGateStatus(w, inbound, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		writeGateStatus(w, inbound, http.StatusBadGateway)
		return
	}
	responseHeaders := response.Header.Clone()
	stripHopHeaders(responseHeaders)
	for name, values := range responseHeaders {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		// A truncated upstream response must not be reused as a valid keep-alive
		// response to another downstream request.
		panic(http.ErrAbortHandler)
	}
}

func stripHopHeaders(headers http.Header) {
	for _, item := range headers.Values("Connection") {
		for _, token := range strings.Split(item, ",") {
			headers.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Expect"} {
		headers.Del(name)
	}
}

type oneConnectionListener struct {
	conn     net.Conn
	mu       sync.Mutex
	accepted bool
	done     chan struct{}
	once     sync.Once
}

func newOneConnectionListener(conn net.Conn) *oneConnectionListener {
	return &oneConnectionListener{conn: conn, done: make(chan struct{})}
}

func (listener *oneConnectionListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	if !listener.accepted {
		listener.accepted = true
		listener.mu.Unlock()
		return &observedConnection{Conn: listener.conn, done: listener.Close}, nil
	}
	listener.mu.Unlock()
	<-listener.done
	return nil, net.ErrClosed
}

func (listener *oneConnectionListener) Close() error {
	listener.once.Do(func() { close(listener.done) })
	return nil
}

func (listener *oneConnectionListener) Addr() net.Addr { return listener.conn.LocalAddr() }

type observedConnection struct {
	net.Conn
	done func() error
}

func (connection *observedConnection) Close() error {
	err := connection.Conn.Close()
	_ = connection.done()
	return err
}
