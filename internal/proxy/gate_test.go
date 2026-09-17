package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/enforcement"
	"github.com/kltngfw/ngfw/internal/engine"
)

type fakeML struct{}

func (fakeML) Classify(context.Context, string) (domain.MLContext, error) {
	return domain.MLContext{Available: true, PredictedClass: "SQL_INJECTION", Confidence: .95, ModelVersion: "test"}, nil
}

func TestGateBlocksBeforeUpstream(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	cfg := config.Defaults()
	cfg.Profiles = []domain.SecurityProfile{{ID: "web", MinimumBlockRisk: 80, MLDetectionEnabled: true, URLFilteringEnabled: true}}
	cfg.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 1, SecurityProfileID: "web", Action: domain.DecisionAllow, Scope: "REQUEST", Enabled: true}}
	m, err := config.NewManager(t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGate(engine.New(m, enforcement.NewMemory()), u.String())
	if err != nil {
		t.Fatal(err)
	}
	g.ML = fakeML{}
	server := httptest.NewServer(g)
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/search?q=1%20union%20select%20password", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream received blocked request: %d", hits.Load())
	}
}

func TestGateAcceptsHTTP2Request(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	cfg := config.Defaults()
	cfg.Policies = []domain.SecurityPolicy{{ID: "allow", Priority: 1, Action: domain.DecisionAllow, Enabled: true}}
	m, err := config.NewManager(t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGate(engine.New(m, enforcement.NewMemory()), u.String())
	if err != nil {
		t.Fatal(err)
	}
	var protocol atomic.Value
	original := g.Engine
	_ = original
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { protocol.Store(r.Proto); g.ServeHTTP(w, r) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/ok", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got, _ := protocol.Load().(string); got != "HTTP/2.0" {
		t.Fatalf("request was not HTTP/2: %q", got)
	}
}
