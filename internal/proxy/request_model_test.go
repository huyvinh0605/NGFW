package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestNormalizeRequestHasDetachedSensitiveInspectionData(t *testing.T) {
	allocator, err := NewRequestIdentityAllocator("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.example/private?token=secret", nil)
	request.Header.Set("Authorization", "Bearer secret-token")
	body := []byte("secret-body")
	context, normalized, err := allocator.NormalizeRequest(request, body, "session-1", true, domain.DefaultRequestGateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if context.RequestOrdinal != 1 || context.RequestID == "" || context.StreamID != nil || context.Scheme != "https" || !context.QueryPresent || context.BodyBytes != len(body) || context.BodySHA256 == "" {
		t.Fatalf("request metadata missing or fabricated: %+v", context)
	}
	if normalized.RawQuery != "token=secret" || normalized.Headers.Get("Authorization") != "Bearer secret-token" || !bytes.Equal(normalized.Body, body) {
		t.Fatal("in-memory detector view lost request semantics")
	}
	encodedContext, _ := json.Marshal(context)
	encodedView, _ := json.Marshal(normalized)
	for _, encoded := range [][]byte{encodedContext, encodedView} {
		if bytes.Contains(encoded, []byte("secret-token")) || bytes.Contains(encoded, []byte("token=secret")) || bytes.Contains(encoded, body) {
			t.Fatalf("sensitive request content escaped through JSON: %s", encoded)
		}
	}
	body[0] = 'X'
	request.Header.Set("Authorization", "changed")
	if string(normalized.Body) != "secret-body" || normalized.Headers.Get("Authorization") != "Bearer secret-token" {
		t.Fatal("normalized request aliases input body or headers")
	}
	copy := normalized.Clone()
	copy.Body[0] = 'X'
	copy.Headers.Set("Authorization", "changed")
	if string(normalized.Body) != "secret-body" || normalized.Headers.Get("Authorization") != "Bearer secret-token" {
		t.Fatal("normalized clone shares mutable request data")
	}
}

func TestNormalizeRequestConcurrentHTTP2StreamsRemainIsolated(t *testing.T) {
	type seen struct {
		context domain.RequestContext
		view    inspection.GateHTTPRequest
		remote  string
		err     error
	}
	allocator, err := NewRequestIdentityAllocator("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan seen, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			started <- seen{err: readErr}
			return
		}
		context, view, normalizeErr := allocator.NormalizeRequest(request, body, "session-1", true, domain.DefaultRequestGateConfig())
		started <- seen{context: context, view: view, remote: request.RemoteAddr, err: normalizeErr}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	responses := make(chan error, 2)
	send := func(path, body string) {
		request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+body)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
		responses <- err
	}
	go send("/one?token=alpha", "first-body")
	receive := func() seen {
		select {
		case value := <-started:
			return value
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP/2 request did not reach normalization")
			return seen{}
		}
	}
	first := receive()
	go send("/two?token=beta", "second-body")
	second := receive()
	releaseOnce.Do(func() { close(release) })
	if err := <-responses; err != nil {
		t.Fatal(err)
	}
	if err := <-responses; err != nil {
		t.Fatal(err)
	}
	if first.err != nil || second.err != nil || first.context.HTTPVersion != "HTTP/2.0" || second.context.HTTPVersion != "HTTP/2.0" || first.remote != second.remote {
		t.Fatalf("requests were not isolated on one HTTP/2 connection: %+v %+v", first, second)
	}
	if first.context.RequestID == second.context.RequestID || first.context.RequestOrdinal == second.context.RequestOrdinal || first.context.StreamID != nil || second.context.StreamID != nil || first.context.ConnectionID != second.context.ConnectionID {
		t.Fatalf("HTTP/2 request identities collided or fabricated stream IDs: %+v %+v", first.context, second.context)
	}
	if string(first.view.Body) != "first-body" || string(second.view.Body) != "second-body" || first.view.Headers.Get("Authorization") == second.view.Headers.Get("Authorization") {
		t.Fatal("HTTP/2 streams shared mutable body or header data")
	}
}
