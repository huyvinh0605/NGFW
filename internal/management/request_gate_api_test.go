package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

type gateAPIFake struct{ *runtimeAPIFake }

func (gateAPIFake) RequestGateHealth(context.Context) (domain.RequestGateHealth, error) {
	return domain.RequestGateHealth{Enabled: true, Status: "down", ProxyReachable: false, Generation: 4}, nil
}
func (gateAPIFake) RequestGateCapabilities(context.Context) (domain.RequestGateCapabilities, error) {
	return domain.RequestGateCapabilities{Supported: true, ProductionReady: false}, nil
}
func (gateAPIFake) ListRequestGateEvidence(_ context.Context, after uint64, limit int) (domain.RequestGateEvidencePage, error) {
	return domain.RequestGateEvidencePage{Items: []domain.RequestGateEvidence{{EventID: "m4-1", Sequence: after + 1}}, NextSequence: after + 1, HasMore: limit == 1}, nil
}

func TestRequestGateAPIReadsEngineOnlyAndBoundsEvidence(t *testing.T) {
	base := &runtimeAPIFake{}
	a := newRuntimeAPIForTest(t, base)
	a.Runtime = gateAPIFake{base}
	a.Token = "m4-test-token"
	server := httptest.NewServer(a.Handler())
	defer server.Close()
	for _, path := range []string{"/api/v1/request-gate/health", "/api/v1/request-gate/capabilities", "/api/v1/request-gate/evidence?after_sequence=8&limit=1"} {
		request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if path == "/api/v1/request-gate/evidence?after_sequence=8&limit=1" {
			request.Header.Set("Authorization", "Bearer m4-test-token")
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Success bool            `json:"success"`
			Data    json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !envelope.Success {
			t.Fatalf("%s: status=%d envelope=%+v", path, response.StatusCode, envelope)
		}
		if path == "/api/v1/request-gate/health" {
			var h domain.RequestGateHealth
			_ = json.Unmarshal(envelope.Data, &h)
			if h.Status != "down" || h.ProxyReachable {
				t.Fatalf("false ready: %+v", h)
			}
		}
		if path == "/api/v1/request-gate/capabilities" {
			var c domain.RequestGateCapabilities
			_ = json.Unmarshal(envelope.Data, &c)
			if c.ProductionReady {
				t.Fatalf("false production-ready: %+v", c)
			}
		}
		if path == "/api/v1/request-gate/evidence?after_sequence=8&limit=1" {
			var p domain.RequestGateEvidencePage
			_ = json.Unmarshal(envelope.Data, &p)
			if p.NextSequence != 9 || len(p.Items) != 1 {
				t.Fatalf("page=%+v", p)
			}
		}
	}
	for _, path := range []string{"/api/v1/request-gate/evidence?limit=129", "/api/v1/request-gate/evidence?after_sequence=-1", "/api/v1/request-gate/evidence?unknown=1"} {
		request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer m4-test-token")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %d", path, response.StatusCode)
		}
	}
	unauthenticated, err := http.Get(server.URL + "/api/v1/request-gate/evidence")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("evidence exposed without auth: %d", unauthenticated.StatusCode)
	}
	if base.commitCalls != 0 {
		t.Fatalf("read-only gate API committed config %d times", base.commitCalls)
	}
}
