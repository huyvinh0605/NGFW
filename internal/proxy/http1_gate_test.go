package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/requestworker"
	"golang.org/x/net/http2"
)

func http1GateFixture(t *testing.T, upstream http.HandlerFunc, gate *HTTP1RequestGate) (net.Conn, <-chan error, *atomic.Int32) {
	t.Helper()
	var arrivals atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		upstream(w, r)
	}))
	t.Cleanup(server.Close)
	client, downstream := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = downstream.Close() })
	target := netip.MustParseAddrPort(server.Listener.Addr().String())
	value := ConnectionContext{
		ConnectionID:  "0123456789abcdef0123456789abcdef",
		ClientAddress: netip.MustParseAddrPort("192.0.2.1:50000"), OriginalDestination: target,
	}
	decision := domain.ProxyConnectionDecision{
		DecisionID: "connection", ConfigGeneration: 1, Action: domain.TLSGateInspectHTTP,
		SessionID: "session", UpstreamIP: target.Addr().String(), UpstreamPort: int(target.Port()),
	}
	finished := make(chan error, 1)
	go func() { finished <- gate.ServeHTTPConnection(context.Background(), downstream, value, decision) }()
	return client, finished, &arrivals
}

func allowRequestForTest(evaluation domain.ProxyRequestEvaluation) domain.RequestDecision {
	return domain.RequestDecision{
		DecisionID: "verdict", RequestID: evaluation.Context.RequestID,
		ConfigGeneration: 1, Verdict: domain.RequestAllow,
		Coverage: evaluation.Inspection.Coverage, ReasonCode: "GATE_INSPECTION_COMPLETE",
	}
}

func completeEvidenceForTest(id string) domain.RequestInspectionResult {
	return domain.RequestInspectionResult{RequestID: id, Completed: true, Coverage: domain.CoverageComplete}
}

func TestHTTP1RequestGateHoldsBlockedRequestBeforeUpstream(t *testing.T) {
	inspecting := make(chan struct{})
	release := make(chan struct{})
	gate := &HTTP1RequestGate{
		Inspector: RequestInspectorFunc(func(ctx context.Context, id string, request inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
			close(inspecting)
			select {
			case <-release:
				return completeEvidenceForTest(id), nil
			case <-ctx.Done():
				return domain.RequestInspectionResult{}, ctx.Err()
			}
		}),
		Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, generation uint64) (domain.RequestDecision, error) {
			if generation != 1 || !evaluation.Inspection.Completed {
				t.Errorf("engine was called without completed evidence: %+v", evaluation.Inspection)
			}
			return domain.RequestDecision{
				DecisionID: "verdict", RequestID: evaluation.Context.RequestID,
				ConfigGeneration: 1, Verdict: domain.RequestBlock,
				Coverage: domain.CoverageComplete, HTTPStatus: 403, ReasonCode: "GATE_SIGNATURE_BLOCK",
			}, nil
		}),
	}
	client, finished, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(client, "POST /blocked HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9\r\n\r\nmalicious"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-inspecting:
	case <-time.After(2 * time.Second):
		t.Fatal("inspection did not start")
	}
	if count := arrivals.Load(); count != 0 {
		t.Fatalf("upstream received request before verdict: %d", count)
	}
	close(release)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 403 || arrivals.Load() != 0 {
		t.Fatalf("blocked request leaked upstream: status=%d arrivals=%d", response.StatusCode, arrivals.Load())
	}
	if stats := gate.Stats(); stats.Counters["request_blocked"] != 1 || stats.Counters["fail_close"] != 0 || stats.ActiveRequests != 0 {
		t.Fatalf("malicious block counters changed: %+v", stats)
	}
	_ = client.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP1 gate did not stop")
	}
}

func TestHTTP1RequestGateReplaysChunkedBodyAndKeepsConnectionSafe(t *testing.T) {
	var decisions atomic.Int32
	seen := make(chan string, 2)
	gate := &HTTP1RequestGate{
		Inspector: RequestInspectorFunc(func(ctx context.Context, id string, request inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
			return completeEvidenceForTest(id), nil
		}),
		Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, generation uint64) (domain.RequestDecision, error) {
			decisions.Add(1)
			if evaluation.Context.ConnectionID != "0123456789abcdef0123456789abcdef" || evaluation.Context.RequestOrdinal != uint64(decisions.Load()) || evaluation.Context.BodyBytes > 64<<10 {
				t.Errorf("wrong request identity or body metadata: %+v", evaluation.Context)
			}
			return allowRequestForTest(evaluation), nil
		}),
	}
	client, finished, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- fmt.Sprintf("%s|%s|%s|%s|%s|%s", r.Method, r.URL.RequestURI(), r.Host, body, r.Header.Get("X-Debug"), r.Header.Get("X-End"))
		w.Header().Set("Connection", "X-Secret")
		w.Header().Set("Proxy-Connection", "remove")
		w.Header().Set("X-Secret", "remove")
		w.Header().Set("X-Visible", "keep")
		_, _ = io.WriteString(w, "ok")
	}, gate)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if _, err := io.WriteString(client, "POST /one?q=1 HTTP/1.1\r\nHost: virtual.test\r\nTransfer-Encoding: chunked\r\nConnection: X-Debug\r\nX-Debug: remove\r\nX-End: keep\r\n\r\n5\r\nhello\r\n0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	first, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, first.Body)
	_ = first.Body.Close()
	// net/http's upstream test server removes Connection itself. The proxy
	// must still remove proxy-only response fields before returning to client.
	if first.StatusCode != 200 || first.Header.Get("Proxy-Connection") != "" || first.Header.Get("X-Visible") != "keep" {
		t.Fatalf("unexpected first response: %d headers=%v", first.StatusCode, first.Header)
	}
	if _, err := io.WriteString(client, "GET /two HTTP/1.1\r\nHost: virtual.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	second, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, second.Body)
	_ = second.Body.Close()
	if second.StatusCode != 200 || arrivals.Load() != 2 || decisions.Load() != 2 {
		t.Fatalf("keepalive failed: status=%d arrivals=%d decisions=%d", second.StatusCode, arrivals.Load(), decisions.Load())
	}
	if got := <-seen; got != "POST|/one?q=1|virtual.test|hello||keep" {
		t.Fatalf("raw body, host or hop headers changed: %q", got)
	}
	if got := <-seen; got != "GET|/two|virtual.test|||" {
		t.Fatalf("second request changed: %q", got)
	}
	_ = client.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gate did not stop")
	}
}

func TestHTTP1RequestGateOnlyEngineCanAllowUnavailableInspection(t *testing.T) {
	var evidenceCode string
	gate := &HTTP1RequestGate{
		Inspector: RequestInspectorFunc(func(context.Context, string, inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
			return domain.RequestInspectionResult{}, context.DeadlineExceeded
		}),
		Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, _ uint64) (domain.RequestDecision, error) {
			evidenceCode = evaluation.Inspection.ErrorCode
			return allowRequestForTest(evaluation), nil // engine-owned fail OPEN
		}),
	}
	client, _, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }, gate)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || arrivals.Load() != 1 || evidenceCode != "GATE_INSPECTION_TIMEOUT" {
		t.Fatalf("unavailable evidence path: status=%d arrivals=%d code=%q", response.StatusCode, arrivals.Load(), evidenceCode)
	}
	if stats := gate.Stats(); stats.Counters["inspection_timeout"] != 1 || stats.Counters["fail_open"] != 1 {
		t.Fatalf("timeout was not counted as degraded allow: %+v", stats)
	}
}

func TestHTTP1RequestGateRejectsInvalidEngineAllow(t *testing.T) {
	gate := &HTTP1RequestGate{
		Inspector: RequestInspectorFunc(func(_ context.Context, id string, _ inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
			return completeEvidenceForTest(id), nil
		}),
		Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, _ uint64) (domain.RequestDecision, error) {
			decision := allowRequestForTest(evaluation)
			decision.RequestID = strings.Repeat("a", 32)
			return decision, nil
		}),
	}
	client, _, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 503 || arrivals.Load() != 0 {
		t.Fatalf("invalid engine response escaped: status=%d arrivals=%d", response.StatusCode, arrivals.Load())
	}
	if stats := gate.Stats(); stats.Counters["engine_unavailable"] != 1 {
		t.Fatalf("invalid engine reply was not counted: %+v", stats)
	}
}

func TestHTTP1RequestGateVerifiedHTTPSHTTP1(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "ca.crt")
	ca, err := inspection.InitMITMCA(certPath, filepath.Join(directory, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.CertificateFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		t.Fatal("could not load test CA")
	}
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprintf("trusted=%v", trusted), func(t *testing.T) {
			var arrivals atomic.Int32
			upstream, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2", "http/1.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				arrivals.Add(1)
				if r.Proto != "HTTP/1.1" || r.URL.Path != "/secure" {
					t.Errorf("wrong verified upstream HTTP request: %s %s", r.Proto, r.URL.Path)
				}
				_, _ = io.WriteString(w, "secure")
			})}
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.Serve(upstream) }()
			defer func() { _ = server.Close(); <-serverDone }()

			clientRaw, proxyRaw := net.Pipe()
			defer clientRaw.Close()
			defer proxyRaw.Close()
			proxyTLS := tls.Server(proxyRaw, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
			clientTLS := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
			handshake := make(chan error, 1)
			go func() { handshake <- proxyTLS.Handshake() }()
			if err := clientTLS.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-handshake; err != nil {
				t.Fatal(err)
			}
			value := ConnectionContext{
				ConnectionID: "0123456789abcdef0123456789abcdef", TLS: true,
				ClientAddress:       netip.MustParseAddrPort("192.0.2.1:50000"),
				OriginalDestination: netip.MustParseAddrPort(upstream.Addr().String()),
			}
			decision := domain.ProxyConnectionDecision{
				DecisionID: "connection", ConfigGeneration: 1, Action: domain.TLSGateDecrypt,
				UpstreamHost: "127.0.0.1", UpstreamIP: value.OriginalDestination.Addr().String(),
				UpstreamPort: int(value.OriginalDestination.Port()),
			}
			gate := &HTTP1RequestGate{
				Inspector: RequestInspectorFunc(func(_ context.Context, id string, _ inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
					return completeEvidenceForTest(id), nil
				}),
				Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, _ uint64) (domain.RequestDecision, error) {
					if evaluation.Context.Scheme != "https" {
						t.Errorf("decrypted request was not marked HTTPS: %+v", evaluation.Context)
					}
					return allowRequestForTest(evaluation), nil
				}),
			}
			if trusted {
				gate.Roots = roots
			}
			finished := make(chan error, 1)
			go func() { finished <- gate.ServeHTTPConnection(context.Background(), proxyTLS, value, decision) }()
			_ = clientTLS.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(clientTLS, "GET /secure HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(clientTLS), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if trusted && (response.StatusCode != 200 || arrivals.Load() != 1) {
				t.Fatalf("verified upstream was not forwarded: status=%d arrivals=%d", response.StatusCode, arrivals.Load())
			}
			if !trusted && (response.StatusCode != 502 || arrivals.Load() != 0) {
				t.Fatalf("unverified upstream was forwarded: status=%d arrivals=%d", response.StatusCode, arrivals.Load())
			}
			if !trusted && gate.Stats().Counters["upstream_verify_fail"] != 1 {
				t.Fatalf("TLS verification failure not counted: %+v", gate.Stats())
			}
			_ = clientTLS.Close()
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("HTTPS HTTP/1.1 gate did not stop")
			}
		})
	}
}

func TestHTTP1RequestGateOversizeUsesEngineVerdictAndRawReplay(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_partial=%v", allow), func(t *testing.T) {
			gate := &HTTP1RequestGate{
				Limits: domain.RequestGateConfig{MaxRawBodyBytes: 4},
				Inspector: RequestInspectorFunc(func(context.Context, string, inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
					t.Error("oversize request must not be called CLEAN by the inspector")
					return domain.RequestInspectionResult{}, nil
				}),
				Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, _ uint64) (domain.RequestDecision, error) {
					if !evaluation.Context.Truncated || evaluation.Inspection.Coverage != domain.RequestCoveragePartial {
						t.Errorf("missing partial body evidence: %+v", evaluation)
					}
					decision := allowRequestForTest(evaluation)
					if !allow {
						decision.Verdict = domain.RequestBlock
						decision.HTTPStatus = 413
					}
					return decision, nil
				}),
			}
			upstreamBody := make(chan string, 1)
			client, _, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				upstreamBody <- string(body)
				w.WriteHeader(200)
			}, gate)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(client, "POST /oversize HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\n\r\nhello-world")
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if allow {
				if response.StatusCode != 200 || arrivals.Load() != 1 || <-upstreamBody != "hello-world" {
					t.Fatalf("partial replay failed: status=%d arrivals=%d", response.StatusCode, arrivals.Load())
				}
			} else if response.StatusCode != 413 || arrivals.Load() != 0 {
				t.Fatalf("oversize block leaked: status=%d arrivals=%d", response.StatusCode, arrivals.Load())
			}
			if stats := gate.Stats(); stats.Counters["body_limit"] != 1 {
				t.Fatalf("oversize request was not counted: %+v", stats)
			}
		})
	}
}

func TestHTTP2RequestGateIsolatesConcurrentStreamsBeforeUpstream(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "ca.crt")
	ca, err := inspection.InitMITMCA(certPath, filepath.Join(directory, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.CertificateFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		t.Fatal("could not load test CA")
	}
	var arrivals atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Proto != "HTTP/2.0" || r.URL.Path != "/clean" {
			t.Errorf("wrong HTTP/2 upstream request: %s %s", r.Proto, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "clean-body" {
			t.Errorf("clean stream body changed: %q", body)
		}
		_, _ = io.WriteString(w, "clean-response")
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, NextProtos: []string{"h2", "http/1.1"}}
	upstream.StartTLS()
	defer upstream.Close()
	target := netip.MustParseAddrPort(upstream.Listener.Addr().String())
	clientRaw, proxyRaw := net.Pipe()
	defer clientRaw.Close()
	defer proxyRaw.Close()
	proxyTLS := tls.Server(proxyRaw, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	clientTLS := tls.Client(clientRaw, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	handshake := make(chan error, 1)
	go func() { handshake <- proxyTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	if clientTLS.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("downstream did not negotiate h2")
	}
	value := ConnectionContext{
		ConnectionID: "0123456789abcdef0123456789abcdef", TLS: true,
		ClientAddress: netip.MustParseAddrPort("192.0.2.1:50000"), OriginalDestination: target,
	}
	connectionDecision := domain.ProxyConnectionDecision{
		DecisionID: "connection", ConfigGeneration: 1, Action: domain.TLSGateDecrypt,
		UpstreamHost: "127.0.0.1", UpstreamIP: target.Addr().String(), UpstreamPort: int(target.Port()),
	}
	inspectStarted := make(chan struct{}, 2)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	contexts := make(chan domain.RequestContext, 2)
	gate := &HTTP1RequestGate{
		Roots: roots,
		Inspector: RequestInspectorFunc(func(ctx context.Context, id string, request inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
			inspectStarted <- struct{}{}
			select {
			case <-release:
				return completeEvidenceForTest(id), nil
			case <-ctx.Done():
				return domain.RequestInspectionResult{}, ctx.Err()
			}
		}),
		Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, generation uint64) (domain.RequestDecision, error) {
			contexts <- evaluation.Context.Clone()
			decision := allowRequestForTest(evaluation)
			if evaluation.Context.Path == "/blocked" {
				decision.Verdict, decision.HTTPStatus, decision.ReasonCode = domain.RequestBlock, 403, "GATE_SIGNATURE_BLOCK"
			}
			return decision, nil
		}),
	}
	finished := make(chan error, 1)
	go func() {
		finished <- gate.ServeHTTPConnection(context.Background(), proxyTLS, value, connectionDecision)
	}()
	_ = clientTLS.SetDeadline(time.Now().Add(9 * time.Second))
	h2Client := &http2.Transport{}
	clientConnection, err := h2Client.NewClientConn(clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	responses := make(chan string, 2)
	for _, path := range []string{"/blocked", "/clean"} {
		go func(path string) {
			body := "malicious-body"
			if path == "/clean" {
				body = "clean-body"
			}
			request, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1"+path, strings.NewReader(body))
			response, roundErr := clientConnection.RoundTrip(request)
			if roundErr != nil {
				responses <- path + ":error:" + roundErr.Error()
				return
			}
			defer response.Body.Close()
			result, _ := io.ReadAll(response.Body)
			responses <- fmt.Sprintf("%s:%d:%s", path, response.StatusCode, result)
		}(path)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-inspectStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("two HTTP/2 streams did not inspect concurrently")
		}
	}
	if arrivals.Load() != 0 {
		t.Fatal("HTTP/2 request reached upstream before verdict")
	}
	close(release)
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case result := <-responses:
			got[result] = true
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP/2 stream response timed out")
		}
	}
	if !got["/blocked:403:Forbidden\n"] || !got["/clean:200:clean-response"] || arrivals.Load() != 1 {
		t.Fatalf("HTTP/2 stream isolation failed: responses=%v upstream=%d", got, arrivals.Load())
	}
	first, second := <-contexts, <-contexts
	if first.ConnectionID != second.ConnectionID || first.RequestID == second.RequestID || first.RequestOrdinal == second.RequestOrdinal || first.StreamID != nil || second.StreamID != nil || first.HTTPVersion != "HTTP/2.0" || second.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("HTTP/2 request identity collision: %+v %+v", first, second)
	}
	// A third stream leaves its body unfinished. Its own deadline must free
	// capacity without terminating the already-used HTTP/2 connection.
	slowReader, slowWriter := io.Pipe()
	defer slowWriter.Close()
	slowRequest, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1/slow", slowReader)
	slowResult := make(chan int, 1)
	go func() {
		response, err := clientConnection.RoundTrip(slowRequest)
		if err != nil {
			slowResult <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		slowResult <- response.StatusCode
	}()
	select {
	case status := <-slowResult:
		if status != 503 || gate.Stats().ActiveRequests != 0 || arrivals.Load() != 1 {
			t.Fatalf("slow HTTP/2 stream did not release only its own slot: status=%d stats=%+v upstream=%d", status, gate.Stats(), arrivals.Load())
		}
	case <-time.After(4 * time.Second):
		t.Fatal("stalled HTTP/2 body was not bounded by the request deadline")
	}
	afterSlow, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1/clean", strings.NewReader("clean-body"))
	remaining, err := clientConnection.RoundTrip(afterSlow)
	if err != nil {
		t.Fatalf("stalled stream closed unrelated HTTP/2 connection: %v", err)
	}
	_, _ = io.Copy(io.Discard, remaining.Body)
	_ = remaining.Body.Close()
	if remaining.StatusCode != 200 || arrivals.Load() != 2 {
		t.Fatalf("connection did not survive stalled stream: status=%d arrivals=%d", remaining.StatusCode, arrivals.Load())
	}
	_ = clientConnection.Close()
	_ = clientTLS.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/2 gate did not stop")
	}
}

func TestHTTPRequestGateFailureEvidenceNeverBecomesClean(t *testing.T) {
	for _, test := range []struct {
		name, encoding, body, code string
		inspectorErr               error
		status                     int
		counter                    string
	}{
		{"unsupported", "br", "body", "GATE_UNSUPPORTED_ENCODING", nil, 503, "fail_close"},
		{"malformed-gzip", "gzip", "not-gzip", "GATE_REQUEST_MALFORMED", nil, 400, "request_blocked"},
		{"queue-full", "", "body", "GATE_QUEUE_FULL", requestworker.ErrQueueFull, 503, "queue_rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := &HTTP1RequestGate{
				Inspector: RequestInspectorFunc(func(context.Context, string, inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
					if test.inspectorErr == nil {
						t.Error("unsupported or malformed body reached detector")
					}
					return domain.RequestInspectionResult{}, test.inspectorErr
				}),
				Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, _ uint64) (domain.RequestDecision, error) {
					if evaluation.Inspection.Completed || evaluation.Inspection.ErrorCode != test.code || evaluation.Inspection.Coverage != domain.RequestCoverageUnavailable {
						t.Errorf("bad failure evidence: %+v", evaluation.Inspection)
					}
					return domain.RequestDecision{
						DecisionID: "verdict", RequestID: evaluation.Context.RequestID,
						ConfigGeneration: 1, Verdict: domain.RequestBlock,
						Coverage: domain.RequestCoverageUnavailable, HTTPStatus: test.status,
						ReasonCode: test.code,
					}, nil
				}),
			}
			client, _, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = fmt.Fprintf(client, "POST /bad HTTP/1.1\r\nHost: example.test\r\nContent-Encoding: %s\r\nContent-Length: %d\r\n\r\n%s", test.encoding, len(test.body), test.body)
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != test.status || arrivals.Load() != 0 || gate.Stats().Counters[test.counter] != 1 {
				t.Fatalf("failure escaped: status=%d arrivals=%d stats=%+v", response.StatusCode, arrivals.Load(), gate.Stats())
			}
		})
	}
}

func TestHTTPRequestGateConcurrentRequestCapacityIsBounded(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	gate := &HTTP1RequestGate{
		Limits: domain.RequestGateConfig{MaxConcurrentRequests: 1},
		Inspector: RequestInspectorFunc(func(ctx context.Context, id string, request inspection.GateHTTPRequest) (domain.RequestInspectionResult, error) {
			started <- struct{}{}
			select {
			case <-release:
				return completeEvidenceForTest(id), nil
			case <-ctx.Done():
				return domain.RequestInspectionResult{}, ctx.Err()
			}
		}),
		Authorizer: RequestAuthorizerFunc(func(_ context.Context, evaluation domain.ProxyRequestEvaluation, _ uint64) (domain.RequestDecision, error) {
			return allowRequestForTest(evaluation), nil
		}),
	}
	firstClient, _, firstArrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
	_ = firstClient.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(firstClient, "GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not occupy gate slot")
	}
	secondClient, _, secondArrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
	_ = secondClient.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(secondClient, "GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n")
	second, err := http.ReadResponse(bufio.NewReader(secondClient), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Body.Close()
	if second.StatusCode != 503 || secondArrivals.Load() != 0 || gate.Stats().Counters["capacity_rejected"] != 1 || gate.Stats().ActiveRequests != 1 {
		t.Fatalf("overload escaped bound: status=%d arrivals=%d stats=%+v", second.StatusCode, secondArrivals.Load(), gate.Stats())
	}
	close(release)
	first, err := http.ReadResponse(bufio.NewReader(firstClient), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Body.Close()
	if first.StatusCode != 200 || firstArrivals.Load() != 1 {
		t.Fatalf("in-flight request was damaged by overload: status=%d arrivals=%d", first.StatusCode, firstArrivals.Load())
	}
}

func TestHTTPRequestGateSlowHTTP1BodyReleasesCapacity(t *testing.T) {
	gate := &HTTP1RequestGate{
		Limits: domain.RequestGateConfig{RequestTimeoutMillis: 100, MaxConcurrentRequests: 1},
		Authorizer: RequestAuthorizerFunc(func(context.Context, domain.ProxyRequestEvaluation, uint64) (domain.RequestDecision, error) {
			t.Error("incomplete request body must not reach engine as clean evidence")
			return domain.RequestDecision{}, nil
		}),
	}
	client, _, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(client, "POST /slow HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 503 || arrivals.Load() != 0 || gate.Stats().Counters["inspection_timeout"] != 1 || gate.Stats().ActiveRequests != 0 {
		t.Fatalf("slow body did not fail boundedly: status=%d arrivals=%d stats=%+v", response.StatusCode, arrivals.Load(), gate.Stats())
	}
}

func TestHTTPRequestGateRejectsOversizeHeadersURLAndMalformedFraming(t *testing.T) {
	for _, test := range []struct {
		name, wire string
		limits     domain.RequestGateConfig
		status     int
	}{
		{"headers", "GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: " + strings.Repeat("x", 1500) + "\r\n\r\n", domain.RequestGateConfig{MaxHeaderBytes: 1024}, 431},
		{"url", "GET /abcdefghij HTTP/1.1\r\nHost: example.test\r\n\r\n", domain.RequestGateConfig{MaxURLBytes: 8}, 414},
		{"malformed", "GET / HTTP/1.1\r\nBadHeader\r\n\r\n", domain.RequestGateConfig{}, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := &HTTP1RequestGate{
				Limits: test.limits,
				Authorizer: RequestAuthorizerFunc(func(context.Context, domain.ProxyRequestEvaluation, uint64) (domain.RequestDecision, error) {
					t.Error("invalid request reached engine as normalized traffic")
					return domain.RequestDecision{}, nil
				}),
			}
			client, _, arrivals := http1GateFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, gate)
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.WriteString(client, test.wire)
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != test.status || arrivals.Load() != 0 {
				t.Fatalf("bad framing escaped: status=%d want=%d arrivals=%d", response.StatusCode, test.status, arrivals.Load())
			}
		})
	}
}
