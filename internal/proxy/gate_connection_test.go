package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func testGateDecision(value ConnectionContext, action domain.TLSGateAction) domain.ProxyConnectionDecision {
	return domain.ProxyConnectionDecision{
		DecisionID: "decision", ConfigGeneration: 1, Action: action, FailMode: domain.GateFailClose,
		UpstreamIP: value.OriginalDestination.Addr().String(), UpstreamPort: int(value.OriginalDestination.Port()),
	}
}

func TestGateConnectionPlainHTTPOnlyCallsRequestHandlerAfterEngineAction(t *testing.T) {
	client, downstream := net.Pipe()
	defer client.Close()
	defer downstream.Close()
	value := ConnectionContext{
		ConnectionID: "0123456789abcdef0123456789abcdef", ClientAddress: netip.MustParseAddrPort("192.0.2.10:50000"),
		OriginalDestination: netip.MustParseAddrPort("203.0.113.10:80"),
	}
	var authorizations, requests, dials atomic.Int32
	handler := &GateConnectionHandler{
		Authorizer: ConnectionAuthorizerFunc(func(_ context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
			authorizations.Add(1)
			if open.IsTLS == nil || *open.IsTLS || open.TLS.Available {
				t.Error("plain HTTP was misclassified as TLS")
			}
			return testGateDecision(value, domain.TLSGateInspectHTTP), nil
		}),
		HTTPGate: HTTPConnectionGateFunc(func(_ context.Context, connection net.Conn, _ ConnectionContext, decision domain.ProxyConnectionDecision) error {
			requests.Add(1)
			if authorizations.Load() != 1 || decision.Action != domain.TLSGateInspectHTTP {
				t.Error("request handler ran before authoritative INSPECT_HTTP")
			}
			buffer := make([]byte, 4)
			_, err := io.ReadFull(connection, buffer)
			if err != nil || string(buffer) != "GET " {
				t.Errorf("plain HTTP bytes changed: %q, %v", buffer, err)
			}
			return err
		}),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		},
	}
	done := make(chan error, 1)
	go func() { done <- handler.ServeProxyConnection(context.Background(), downstream, value) }()
	if _, err := client.Write([]byte("GET ")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || authorizations.Load() != 1 || requests.Load() != 1 || dials.Load() != 0 {
		t.Fatalf("plain HTTP dispatch: auth=%d handler=%d dials=%d err=%v", authorizations.Load(), requests.Load(), dials.Load(), err)
	}
}

func TestGateConnectionInvalidClientHelloDelegatesFailModeToEngine(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan string, 1)
	go func() {
		connection, err := upstream.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		wire := make([]byte, len("HELLODATA"))
		_, _ = io.ReadFull(connection, wire)
		accepted <- string(wire)
		_, _ = connection.Write([]byte("OK"))
	}()
	value := ConnectionContext{
		ConnectionID: "0123456789abcdef0123456789abcdef", TLS: true,
		ClientAddress:       netip.MustParseAddrPort("127.0.0.1:50000"),
		OriginalDestination: netip.MustParseAddrPort(upstream.Addr().String()),
	}
	client, downstream := net.Pipe()
	defer client.Close()
	defer downstream.Close()
	var opens atomic.Int32
	handler := &GateConnectionHandler{
		Authorizer: ConnectionAuthorizerFunc(func(_ context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
			opens.Add(1)
			if open.TLSFailureCode != "TLS_CLIENTHELLO_INVALID" || open.TLS.Available || open.IsTLS == nil || !*open.IsTLS {
				t.Errorf("failed ClientHello was not sent to engine: %+v", open)
			}
			return testGateDecision(value, domain.TLSGateBypass), nil // engine-owned fail OPEN
		}),
	}
	finished := make(chan error, 1)
	go func() { finished <- handler.ServeProxyConnection(context.Background(), downstream, value) }()
	_ = client.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := client.Write([]byte("HELLODATA")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "OK" {
		t.Fatalf("engine-authorized bypass failed: %q %v", reply, err)
	}
	if wire := <-accepted; wire != "HELLODATA" || opens.Load() != 1 {
		t.Fatalf("partial ClientHello was not replayed exactly: %q opens=%d", wire, opens.Load())
	}
	if stats := handler.Stats(); stats.Counters["client_hello_invalid"] != 1 || stats.Counters["tls_handshake_fail"] != 0 {
		t.Fatalf("ClientHello failure counters wrong: %+v", stats)
	}
	_ = client.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bypass did not stop")
	}
}

func TestGateConnectionTLSTunnelReplaysExactClientHello(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamListener.Close()
	hello := testClientHello(true)
	wire := append(testTLSRecord(hello[:9]), testTLSRecord(hello[9:])...)
	upstreamBytes := make(chan []byte, 1)
	go func() {
		connection, err := upstreamListener.Accept()
		if err != nil {
			upstreamBytes <- nil
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		captured := make([]byte, len(wire))
		if _, err := io.ReadFull(connection, captured); err != nil {
			upstreamBytes <- nil
			return
		}
		upstreamBytes <- captured
		_, _ = connection.Write([]byte("OK"))
	}()
	downstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer downstreamListener.Close()
	value := ConnectionContext{
		ConnectionID: "0123456789abcdef0123456789abcdef", ClientAddress: netip.MustParseAddrPort("127.0.0.1:50000"),
		OriginalDestination: netip.MustParseAddrPort(upstreamListener.Addr().String()), TLS: true,
	}
	handler := &GateConnectionHandler{Authorizer: ConnectionAuthorizerFunc(func(_ context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
		if open.IsTLS == nil || !*open.IsTLS || !open.TLS.Available || open.TLS.SNI != "api.example.com" {
			t.Errorf("TLS metadata not forwarded to engine: %+v", open)
		}
		return testGateDecision(value, domain.TLSGateBypass), nil
	})}
	done := make(chan error, 1)
	go func() {
		connection, err := downstreamListener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		done <- handler.ServeProxyConnection(context.Background(), connection, value)
	}()
	client, err := net.Dial("tcp", downstreamListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(wire); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "OK" {
		t.Fatalf("raw tunnel response failed: %q, %v", response, err)
	}
	_ = client.Close()
	if captured := <-upstreamBytes; !bytes.Equal(captured, wire) {
		t.Fatalf("buffered ClientHello was not replayed byte-for-byte: got %d want %d", len(captured), len(wire))
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("raw tunnel did not stop")
	}
}

func TestGateConnectionDecryptTerminatesTLSWithoutUpstreamDial(t *testing.T) {
	dir := t.TempDir()
	ca, err := inspection.InitMITMCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("CA certificate could not be trusted by test client")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	value := ConnectionContext{
		ConnectionID: "0123456789abcdef0123456789abcdef", ClientAddress: netip.MustParseAddrPort("127.0.0.1:50000"),
		OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"), TLS: true,
	}
	var dials atomic.Int32
	handler := &GateConnectionHandler{
		CA: ca,
		Authorizer: ConnectionAuthorizerFunc(func(_ context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
			if open.TLS.SNI != "app.example" || !open.TLS.Available {
				t.Errorf("TLS ClientHello metadata missing: %+v", open.TLS)
			}
			return testGateDecision(value, domain.TLSGateDecrypt), nil
		}),
		HTTPGate: HTTPConnectionGateFunc(func(_ context.Context, connection net.Conn, _ ConnectionContext, decision domain.ProxyConnectionDecision) error {
			secure, ok := connection.(*tls.Conn)
			if !ok || secure.ConnectionState().NegotiatedProtocol != "h2" || decision.Action != domain.TLSGateDecrypt {
				t.Error("DECRYPT did not terminate TLS/ALPN before HTTP gate")
			}
			_, err := connection.Write([]byte("OK"))
			return err
		}),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("upstream must wait for request verdict")
		},
	}
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		done <- handler.ServeProxyConnection(context.Background(), connection, value)
	}()
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "app.example", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "OK" || dials.Load() != 0 {
		t.Fatalf("decrypted request path failed without verdict: %q, %v, dials=%d", response, err, dials.Load())
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handler did not finish")
	}
}

func TestGateConnectionRejectsInvalidAndBlockedActionsBeforeDial(t *testing.T) {
	value := ConnectionContext{
		ConnectionID: "0123456789abcdef0123456789abcdef", ClientAddress: netip.MustParseAddrPort("192.0.2.10:50000"),
		OriginalDestination: netip.MustParseAddrPort("203.0.113.10:80"),
	}
	for _, action := range []domain.TLSGateAction{domain.TLSGateBlock, domain.TLSGateDecrypt, domain.TLSGateMetadataOnly} {
		client, downstream := net.Pipe()
		var dials atomic.Int32
		handler := &GateConnectionHandler{
			Authorizer: ConnectionAuthorizerFunc(func(context.Context, domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
				return testGateDecision(value, action), nil
			}),
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected dial")
			},
		}
		err := handler.ServeProxyConnection(context.Background(), downstream, value)
		_ = client.Close()
		_ = downstream.Close()
		if dials.Load() != 0 || action == domain.TLSGateBlock && !errors.Is(err, ErrGatePolicyBlocked) || action != domain.TLSGateBlock && !errors.Is(err, ErrGateDecisionInvalid) {
			t.Fatalf("action %s opened unauthorized path: dials=%d err=%v", action, dials.Load(), err)
		}
	}
}
