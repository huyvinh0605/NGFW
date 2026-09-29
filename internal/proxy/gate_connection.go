package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
	"github.com/kltngfw/ngfw/internal/inspection"
)

var (
	ErrGateDecisionInvalid = errors.New("GATE_ENGINE_UNAVAILABLE")
	ErrGatePolicyBlocked   = errors.New("GATE_POLICY_NOT_ALLOWED")
	ErrGateHandlerMissing  = errors.New("GATE_REQUEST_HANDLER_UNAVAILABLE")
	ErrTLSHandshake        = errors.New("TLS_CLIENT_HANDSHAKE_FAILED")
	ErrUpstreamConnect     = errors.New("TLS_UPSTREAM_CONNECT_FAILED")
)

type ConnectionAuthorizer interface {
	OpenConnection(context.Context, domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error)
}

type ConnectionAuthorizerFunc func(context.Context, domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error)

func (f ConnectionAuthorizerFunc) OpenConnection(ctx context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
	return f(ctx, open)
}

// IPCConnectionAuthorizer forwards the connection context to ngfw-engine.
// It contains no local policy/profile evaluation.
type IPCConnectionAuthorizer struct{ Client *gateipc.Client }

func (authorizer IPCConnectionAuthorizer) OpenConnection(ctx context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
	if authorizer.Client == nil {
		return domain.ProxyConnectionDecision{}, ErrGateDecisionInvalid
	}
	var decision domain.ProxyConnectionDecision
	meta, err := authorizer.Client.Call(ctx, gateipc.OpenConnection, open, &decision)
	if err != nil {
		return domain.ProxyConnectionDecision{}, err
	}
	if meta.DecisionID != decision.DecisionID || meta.ConfigGeneration != decision.ConfigGeneration {
		return domain.ProxyConnectionDecision{}, ErrGateDecisionInvalid
	}
	return decision, nil
}

// HTTPConnectionGate will be supplied by the request-gate tasks. It must hold
// each request until the engine returns its final per-request verdict.
type HTTPConnectionGate interface {
	ServeHTTPConnection(context.Context, net.Conn, ConnectionContext, domain.ProxyConnectionDecision) error
}

type HTTPConnectionGateFunc func(context.Context, net.Conn, ConnectionContext, domain.ProxyConnectionDecision) error

func (f HTTPConnectionGateFunc) ServeHTTPConnection(ctx context.Context, connection net.Conn, value ConnectionContext, decision domain.ProxyConnectionDecision) error {
	return f(ctx, connection, value, decision)
}

type GateConnectionHandler struct {
	Authorizer          ConnectionAuthorizer
	HTTPGate            HTTPConnectionGate
	CA                  *inspection.MITMCA
	DialContext         func(context.Context, string, string) (net.Conn, error)
	ClientHelloBytes    int
	ClientHelloTimeout  time.Duration
	TLSHandshakeTimeout time.Duration
}

func (handler *GateConnectionHandler) ServeProxyConnection(ctx context.Context, downstream net.Conn, value ConnectionContext) error {
	if handler == nil || handler.Authorizer == nil || downstream == nil || !value.ClientAddress.IsValid() || !value.OriginalDestination.IsValid() || value.ConnectionID == "" {
		return ErrGateDecisionInvalid
	}
	var buffered []byte
	var metadata domain.TLSContext
	if value.TLS {
		var err error
		metadata, buffered, err = PeekClientHello(ctx, downstream, handler.ClientHelloBytes, handler.ClientHelloTimeout)
		if err != nil {
			return err // T26 will map partial/timeout to engine-owned failure policy
		}
	}
	isTLS := value.TLS
	open := domain.ProxyConnectionOpen{
		ConnectionID: value.ConnectionID,
		SourceIP:     value.ClientAddress.Addr().Unmap().String(), SourcePort: int(value.ClientAddress.Port()),
		OriginalIP: value.OriginalDestination.Addr().Unmap().String(), OriginalPort: int(value.OriginalDestination.Port()),
		Protocol: "tcp", IsTLS: &isTLS, TLS: metadata,
	}
	decision, err := handler.Authorizer.OpenConnection(ctx, open)
	if err != nil {
		return err
	}
	if err := validateConnectionDecision(value, decision); err != nil {
		return err
	}
	switch decision.Action {
	case domain.TLSGateBlock:
		return ErrGatePolicyBlocked
	case domain.TLSGateBypass, domain.TLSGateMetadataOnly:
		return handler.rawTunnel(ctx, downstream, value.OriginalDestination, buffered)
	case domain.TLSGateInspectHTTP:
		if handler.HTTPGate == nil {
			return ErrGateHandlerMissing
		}
		return handler.HTTPGate.ServeHTTPConnection(ctx, downstream, value, decision)
	case domain.TLSGateDecrypt:
		if handler.HTTPGate == nil || handler.CA == nil {
			return ErrGateHandlerMissing
		}
		return handler.serveDecrypted(ctx, downstream, value, decision, buffered)
	default:
		return ErrGateDecisionInvalid
	}
}

func validateConnectionDecision(value ConnectionContext, decision domain.ProxyConnectionDecision) error {
	if decision.DecisionID == "" || decision.ConfigGeneration == 0 || !decision.Action.Valid() || !decision.FailMode.Valid() || decision.UpstreamIP != value.OriginalDestination.Addr().Unmap().String() || decision.UpstreamPort != int(value.OriginalDestination.Port()) {
		return ErrGateDecisionInvalid
	}
	if value.TLS && decision.Action == domain.TLSGateInspectHTTP || !value.TLS && (decision.Action == domain.TLSGateMetadataOnly || decision.Action == domain.TLSGateDecrypt) {
		return ErrGateDecisionInvalid
	}
	return nil
}

func (handler *GateConnectionHandler) rawTunnel(ctx context.Context, downstream net.Conn, target netip.AddrPort, buffered []byte) error {
	dial := handler.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	upstream, err := dial(ctx, "tcp", target.String())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstreamConnect, err)
	}
	defer upstream.Close()
	if len(buffered) > 0 {
		if _, err := io.Copy(upstream, bytes.NewReader(buffered)); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = downstream.Close(); _ = upstream.Close() })
	defer stop()
	responseDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(downstream, upstream)
		closeWrite(downstream)
		closeRead(upstream)
		responseDone <- copyErr
	}()
	_, requestErr := io.Copy(upstream, downstream)
	closeWrite(upstream)
	closeRead(downstream)
	responseErr := <-responseDone
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if requestErr != nil && !errors.Is(requestErr, net.ErrClosed) {
		return requestErr
	}
	if responseErr != nil && !errors.Is(responseErr, net.ErrClosed) {
		return responseErr
	}
	return nil
}

func closeWrite(connection net.Conn) {
	if half, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}

func closeRead(connection net.Conn) {
	if half, ok := connection.(interface{ CloseRead() error }); ok {
		_ = half.CloseRead()
	}
}

type replayConn struct {
	net.Conn
	buffer *bytes.Reader
}

func (connection *replayConn) Read(target []byte) (int, error) {
	if connection.buffer.Len() > 0 {
		return connection.buffer.Read(target)
	}
	return connection.Conn.Read(target)
}

func (handler *GateConnectionHandler) serveDecrypted(ctx context.Context, downstream net.Conn, value ConnectionContext, decision domain.ProxyConnectionDecision, buffered []byte) error {
	wrapped := &replayConn{Conn: downstream, buffer: bytes.NewReader(buffered)}
	secure := tls.Server(wrapped, handler.CA.TLSConfig([]string{"h2", "http/1.1"}))
	defer secure.Close()
	timeout := handler.TLSHandshakeTimeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := secure.HandshakeContext(handshakeCtx); err != nil {
		return fmt.Errorf("%w: %v", ErrTLSHandshake, err)
	}
	return handler.HTTPGate.ServeHTTPConnection(ctx, secure, value, decision)
}
