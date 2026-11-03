package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

// Keep the failed server socket open until the client has observed its TLS
// alert. Otherwise Windows can discard the alert on close with unread H2
// preface bytes and report only a TCP reset. Reset/EOF classification is tested
// separately and must remain a transport error, never guessed to be mTLS.
type alertDrainingListener struct {
	net.Listener
	release <-chan struct{}
}

func (listener alertDrainingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &alertDrainingConn{Conn: connection, release: listener.release}, nil
}

type alertDrainingConn struct {
	net.Conn
	release <-chan struct{}
	once    sync.Once
}

func (connection *alertDrainingConn) Close() error {
	connection.once.Do(func() {
		select {
		case <-connection.release:
		case <-time.After(2 * time.Second):
		}
	})
	return connection.Conn.Close()
}

// Real TLS handshakes exercise both the TLS 1.2 handshake rejection and the
// TLS 1.3 alert that can arrive after HandshakeContext already returned.
func TestUpstreamClientAuthenticationRequiredAndOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca", "ca.crt")
	ca, err := inspection.InitMITMCA(path, filepath.Join(filepath.Dir(path), "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.CertificateFor("good.example")
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := os.ReadFile(path)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, h2 := range []bool{false, true} {
			for _, auth := range []tls.ClientAuthType{tls.NoClientCert, tls.RequestClientCert, tls.RequireAndVerifyClientCert} {
				name := tls.VersionName(version) + "/" + auth.String()
				if h2 {
					name += "/h2"
				} else {
					name += "/h1"
				}
				t.Run(name, func(t *testing.T) {
					var arrivals atomic.Int32
					origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						arrivals.Add(1)
						_, _ = io.Copy(io.Discard, r.Body)
						_, _ = io.WriteString(w, "optional-auth-still-works")
					}))
					origin.EnableHTTP2 = h2
					release := make(chan struct{})
					if auth == tls.RequireAndVerifyClientCert {
						origin.Listener = alertDrainingListener{Listener: origin.Listener, release: release}
					}
					origin.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: version, MaxVersion: version,
						ClientAuth: auth, ClientCAs: roots}
					origin.StartTLS()
					defer origin.Close()
					defer close(release)
					gate := &HTTP1RequestGate{Roots: roots}
					transport, err := gate.newUpstreamTransport(netip.MustParseAddrPort(origin.Listener.Addr().String()), true, h2, "good.example")
					if err != nil {
						t.Fatal(err)
					}
					defer transport.CloseIdleConnections()
					for attempt := 0; attempt < 2; attempt++ {
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						request, _ := http.NewRequestWithContext(ctx, "GET", "https://good.example/real-tls", nil)
						response, requested, err := transport.roundTrip(request)
						if auth == tls.RequireAndVerifyClientCert {
							cancel()
							if !errors.Is(err, ErrUpstreamMTLS) || !requested || response != nil || arrivals.Load() != 0 {
								t.Fatalf("mTLS failure misclassified/leaked: err=%v requested=%v response=%v arrivals=%d", err, requested, response, arrivals.Load())
							}
						} else {
							if err != nil {
								cancel()
								t.Fatal(err)
							}
							body, readErr := io.ReadAll(response.Body)
							_ = response.Body.Close()
							cancel()
							if readErr != nil || response.StatusCode != 200 || string(body) != "optional-auth-still-works" ||
								requested != (auth == tls.RequestClientCert) || h2 && response.ProtoMajor != 2 {
								t.Fatalf("optional/no-auth or reused transport failed: requested=%v response=%+v body=%q err=%v", requested, response, body, readErr)
							}
						}
					}
					transport.CloseIdleConnections()
					deadline := time.Now().Add(time.Second)
					for {
						transport.tlsStates.mu.Lock()
						n := len(transport.tlsStates.connections)
						transport.tlsStates.mu.Unlock()
						if n == 0 {
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("closed TLS metadata leaked: %d entries", n)
						}
						time.Sleep(time.Millisecond)
					}
				})
			}
		}
	}
}

func TestUpstreamFailureClassificationDoesNotGuessFromErrorText(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		requested bool
		want      error
	}{
		{"TLS13 required", tls.AlertError(116), true, ErrUpstreamMTLS},
		{"TLS12 rejected", tls.AlertError(42), true, ErrUpstreamMTLS},
		{"OpenSSL TLS12", tls.AlertError(40), true, ErrUpstreamMTLS},
		{"no certificate request", tls.AlertError(42), false, ErrUpstreamHandshake},
		{"unrelated peer alert", tls.AlertError(80), true, ErrUpstreamHandshake},
		{"timeout after optional cert", context.DeadlineExceeded, true, ErrUpstreamConnect},
		{"reset after optional cert", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("reset")}, true, ErrUpstreamConnect},
		{"EOF after optional cert", io.EOF, true, ErrUpstreamConnect},
		{"untrusted certificate", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, true, ErrUpstreamVerify},
		{"untrusted error text", errors.New("remote error: tls: certificate required"), true, ErrUpstreamConnect},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyUpstreamTLSFailure(test.err, test.requested); !errors.Is(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestForwardResultReportsMismatchedCertificateAndReportingOutage(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unverified upstream request") }))
	defer origin.Close()
	result := make(chan domain.ProxyRequestResult, 1)
	gate := &HTTP1RequestGate{ResultReporter: RequestResultReporterFunc(func(ctx context.Context, input domain.ProxyRequestResult) (domain.RequestResultReceipt, error) {
		if ctx.Err() != nil {
			t.Error("result inherited cancellation")
		}
		result <- input
		return domain.RequestResultReceipt{}, errors.New("report socket down")
	})}
	target := netip.MustParseAddrPort(origin.Listener.Addr().String())
	transport, _ := gate.newUpstreamTransport(target, true, false, "wrong.example")
	defer transport.CloseIdleConnections()
	request := httptest.NewRequest("GET", "https://wrong.example/test", nil)
	context := domain.RequestContext{RequestID: strings.Repeat("a", 32), ConnectionID: strings.Repeat("b", 32)}
	decision := domain.RequestDecision{DecisionID: strings.Repeat("c", 32), ConfigGeneration: 7}
	w := httptest.NewRecorder()
	gate.forwardAllowed(w, request, io.NopCloser(strings.NewReader("")), target, true, transport, context, decision)
	got := <-result
	if w.Code != 502 || got.ReasonCode != "TLS_UPSTREAM_VERIFY_FAILED" || got.RequestID != context.RequestID ||
		got.ConnectionID != context.ConnectionID || got.DecisionID != decision.DecisionID || got.ConfigGeneration != 7 ||
		gate.Stats().Counters["result_report_fail"] != 1 || gate.Stats().Counters["upstream_verify_fail"] != 1 {
		t.Fatalf("request result or reporting failure altered enforcement: status=%d result=%+v stats=%+v", w.Code, got, gate.Stats())
	}
}
