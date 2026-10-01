package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

var ErrUpstreamVerify = errors.New("TLS_UPSTREAM_VERIFY_FAILED")

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
	secure := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: hostname, RootCAs: roots,
		NextProtos: protocols,
	})
	if err := secure.HandshakeContext(callCtx); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("%w: %v", ErrUpstreamVerify, err)
	}
	if len(secure.ConnectionState().VerifiedChains) == 0 {
		_ = secure.Close()
		return nil, ErrUpstreamVerify
	}
	_ = raw.SetDeadline(time.Time{})
	return secure, nil
}
