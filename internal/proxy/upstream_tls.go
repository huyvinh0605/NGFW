package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrUpstreamVerify    = errors.New("TLS_UPSTREAM_VERIFY_FAILED")
	ErrUpstreamMTLS      = errors.New("TLS_UPSTREAM_MTLS_UNSUPPORTED")
	ErrUpstreamHandshake = errors.New("TLS_UPSTREAM_HANDSHAKE_FAILED")
)

type upstreamClientAuth struct{ requested atomic.Bool }
type upstreamAuthContextKey struct{}

// This registry belongs to one bounded downstream transport. Its entries live
// only as long as the corresponding pooled TLS sockets, not for every request.
type upstreamTLSRegistry struct {
	mu          sync.Mutex
	connections map[*tls.Conn]*upstreamClientAuth
}

func (registry *upstreamTLSRegistry) get(connection net.Conn) *upstreamClientAuth {
	secure, ok := connection.(*tls.Conn)
	if !ok {
		return nil
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.connections[secure]
}

type upstreamObservedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (connection *upstreamObservedConn) Close() error {
	connection.once.Do(connection.onClose)
	return connection.Conn.Close()
}

// DialVerifiedUpstream dials the engine-authorized original IP/port, then
// verifies the upstream certificate against the SNI hostname or destination
// IP. A trust or handshake error always closes the connection; it never
// retries as plaintext or with InsecureSkipVerify.
func DialVerifiedUpstream(ctx context.Context, target netip.AddrPort, hostname string, roots *x509.CertPool, dial func(context.Context, string, string) (net.Conn, error)) (*tls.Conn, error) {
	return dialVerifiedUpstream(ctx, target, hostname, roots, dial, []string{"h2", "http/1.1"})
}

// DialVerifiedUpstreamHTTP1 forces HTTP/1.1 ALPN for the T24 round tripper.
func DialVerifiedUpstreamHTTP1(ctx context.Context, target netip.AddrPort, hostname string, roots *x509.CertPool, dial func(context.Context, string, string) (net.Conn, error)) (*tls.Conn, error) {
	return dialVerifiedUpstream(ctx, target, hostname, roots, dial, []string{"http/1.1"})
}

func dialVerifiedUpstream(ctx context.Context, target netip.AddrPort, hostname string, roots *x509.CertPool, dial func(context.Context, string, string) (net.Conn, error), protocols []string) (*tls.Conn, error) {
	return dialTrackedUpstream(ctx, target, hostname, roots, dial, protocols, nil)
}

func dialTrackedUpstream(ctx context.Context, target netip.AddrPort, hostname string, roots *x509.CertPool, dial func(context.Context, string, string) (net.Conn, error), protocols []string, registry *upstreamTLSRegistry) (*tls.Conn, error) {
	if ctx == nil || !target.IsValid() || target.Port() == 0 || target.Addr().IsUnspecified() || target.Addr().IsMulticast() {
		return nil, ErrUpstreamConnect
	}
	if hostname == "" {
		hostname = target.Addr().String()
	}
	if hostname != strings.TrimSpace(hostname) || strings.ContainsAny(hostname, "\x00/\\") || strings.HasPrefix(hostname, "*.") {
		return nil, ErrUpstreamVerify
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	callCtx := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		callCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	}
	defer cancel()
	raw, err := dial(callCtx, "tcp", target.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamConnect, err)
	}
	deadline, _ := callCtx.Deadline()
	if !deadline.IsZero() {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("%w: %v", ErrUpstreamConnect, err)
		}
	}
	auth := &upstreamClientAuth{}
	if slot, ok := ctx.Value(upstreamAuthContextKey{}).(*atomic.Pointer[upstreamClientAuth]); ok {
		slot.Store(auth)
	}
	var secure *tls.Conn
	if registry != nil {
		raw = &upstreamObservedConn{Conn: raw, onClose: func() {
			registry.mu.Lock()
			delete(registry.connections, secure)
			registry.mu.Unlock()
		}}
	}
	secure = tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: hostname, RootCAs: roots,
		NextProtos: protocols,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			auth.requested.Store(true)
			// Requesting a certificate is not proof that it is mandatory. Send
			// the normal empty certificate; optional client authentication must
			// still work. Never impersonate the downstream client's identity.
			return &tls.Certificate{}, nil
		},
	})
	if err := secure.HandshakeContext(callCtx); err != nil {
		_ = secure.Close()
		return nil, classifyUpstreamTLSFailure(err, auth.requested.Load())
	}
	if len(secure.ConnectionState().VerifiedChains) == 0 {
		_ = secure.Close()
		return nil, ErrUpstreamVerify
	}
	_ = raw.SetDeadline(time.Time{})
	if registry != nil {
		registry.mu.Lock()
		if registry.connections == nil {
			registry.connections = make(map[*tls.Conn]*upstreamClientAuth)
		}
		registry.connections[secure] = auth
		registry.mu.Unlock()
	}
	return secure, nil
}

// Go exposes AlertError for QUIC, but its TCP implementation still wraps the
// scalar crypto/tls.alert in net.OpError. This guarded compatibility adapter
// reads only that scalar's numeric value, never private struct fields or error
// text. If Go changes that representation, classification falls back to a
// generic handshake/connect failure; verification and enforcement stay closed.
func upstreamPeerAlert(err error) (uint8, bool) {
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return uint8(alert), true
	}
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" || remote.Err == nil {
		return 0, false
	}
	value := reflect.ValueOf(remote.Err)
	if value.Kind() == reflect.Uint8 && value.Type().PkgPath() == "crypto/tls" && value.Type().Name() == "alert" {
		return uint8(value.Uint()), true
	}
	return 0, false
}

// A certificate request alone is not an mTLS failure. Only a peer certificate
// rejection after our empty certificate is classified as unsupported mTLS.
// Optional client auth, network faults and unrelated TLS alerts retain their
// own outcomes. No classification depends on a free-form error string.
func classifyUpstreamTLSFailure(err error, clientAuthRequested bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrUpstreamVerify) || errors.Is(err, ErrUpstreamMTLS) ||
		errors.Is(err, ErrUpstreamHandshake) || errors.Is(err, ErrUpstreamConnect) {
		return err
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return fmt.Errorf("%w: %w", ErrUpstreamVerify, err)
	}
	alert, peerAlert := upstreamPeerAlert(err)
	// RFC 5246 / RFC 8446: handshake_failure, bad_certificate, certificate_required.
	if peerAlert && clientAuthRequested && (alert == 40 || alert == 42 || alert == 116) {
		return fmt.Errorf("%w: %w", ErrUpstreamMTLS, err)
	}
	if peerAlert {
		return fmt.Errorf("%w: %w", ErrUpstreamHandshake, err)
	}
	return fmt.Errorf("%w: %w", ErrUpstreamConnect, err)
}
