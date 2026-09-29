package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

func testVerifiedTLSServer(t *testing.T, cert tls.Certificate) (netip.AddrPort, func()) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				if secure, ok := connection.(*tls.Conn); ok {
					if secure.Handshake() != nil {
						return
					}
				}
				_, _ = connection.Write([]byte("OK"))
			}()
		}
	}()
	return netip.MustParseAddrPort(listener.Addr().String()), func() {
		_ = listener.Close()
		<-done
	}
}

func TestDialVerifiedUpstreamUsesOriginalIPAndHostname(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	ca, err := inspection.InitMITMCA(certPath, filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.CertificateFor("good.example")
	if err != nil {
		t.Fatal(err)
	}
	target, stop := testVerifiedTLSServer(t, leaf)
	defer stop()
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("test CA root could not be loaded")
	}
	dialed := ""
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	connection, err := DialVerifiedUpstream(context.Background(), target, "good.example", roots, dial)
	if err != nil {
		t.Fatal(err)
	}
	if dialed != target.String() || connection.ConnectionState().NegotiatedProtocol != "h2" || len(connection.ConnectionState().VerifiedChains) == 0 {
		t.Fatalf("upstream dial/verification/ALPN drift: dialed %s, state %+v", dialed, connection.ConnectionState())
	}
	_ = connection.Close()
	if connection, err := DialVerifiedUpstream(context.Background(), target, "wrong.example", roots, nil); !errors.Is(err, ErrUpstreamVerify) || connection != nil {
		t.Fatalf("hostname mismatch was accepted: %v", err)
	}
	if connection, err := DialVerifiedUpstream(context.Background(), target, "good.example", nil, nil); !errors.Is(err, ErrUpstreamVerify) || connection != nil {
		t.Fatalf("untrusted CA was accepted: %v", err)
	}
	if connection, err := DialVerifiedUpstream(context.Background(), target, "", roots, nil); !errors.Is(err, ErrUpstreamVerify) || connection != nil {
		t.Fatalf("IP fallback accepted a DNS-only certificate: %v", err)
	}
}

func TestDialVerifiedUpstreamIPCertificateAndConnectFailure(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	ca, err := inspection.InitMITMCA(certPath, filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.CertificateFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	target, stop := testVerifiedTLSServer(t, leaf)
	defer stop()
	pemBytes, _ := os.ReadFile(certPath)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemBytes)
	connection, err := DialVerifiedUpstream(context.Background(), target, "", roots, nil)
	if err != nil || connection == nil {
		t.Fatalf("verified IP SAN failed: %v", err)
	}
	_ = connection.Close()
	if connection, err := DialVerifiedUpstream(context.Background(), target, "good/invalid", roots, nil); !errors.Is(err, ErrUpstreamVerify) || connection != nil {
		t.Fatalf("invalid hostname was sent upstream: %v", err)
	}
	if connection, err := DialVerifiedUpstream(context.Background(), target, "127.0.0.1", roots, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial refused")
	}); !errors.Is(err, ErrUpstreamConnect) || connection != nil {
		t.Fatalf("connect failure became a verified connection: %v", err)
	}
}
