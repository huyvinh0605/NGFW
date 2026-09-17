package engine

import (
	"context"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/enforcement"
)

func TestFlowDecisionFastPathAndInvalidation(t *testing.T) {
	cfg := config.Defaults()
	cfg.DefaultDeny = true
	cfg.Profiles = []domain.SecurityProfile{{ID: "protect", Name: "protect", MinimumBlockRisk: 30}}
	cfg.Policies = []domain.SecurityPolicy{{ID: "allow-all", Name: "allow all", Priority: 1, SecurityProfileID: "protect", Action: domain.DecisionAllow, Enabled: true}}
	m, err := config.NewManager(t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	mem := enforcement.NewMemory()
	e := New(m, mem)
	obs := FlowObservation{Key: domain.FlowKey{SrcIP: "10.0.0.2", DstIP: "1.1.1.1", SrcPort: 40000, DstPort: 443, Protocol: "tcp"}, Application: "HTTPS", ApplicationConfidence: 0.99}
	s, _, decision, err := e.EvaluateFlow(context.Background(), obs)
	if err != nil || decision.Action != domain.DecisionAllow {
		t.Fatalf("initial decision=%v err=%v", decision, err)
	}
	if !s.FastPathEligible {
		t.Fatal("low-risk allowed flow did not become fast path eligible")
	}
	_, _, cached, err := e.EvaluateFlow(context.Background(), obs)
	if err != nil || cached.Reason != "cached fast-path decision" {
		t.Fatalf("expected cached decision: %+v %v", cached, err)
	}
	if err := e.IngestEvent(domain.SecurityEvent{SessionID: s.ID, Detector: "IPS", Category: "SQL_INJECTION", Severity: domain.SeverityCritical, Confidence: 1, Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	updated, _, next, err := e.EvaluateFlow(context.Background(), obs)
	if err != nil {
		t.Fatal(err)
	}
	if next.Action != domain.DecisionDrop || updated.FastPathEligible {
		t.Fatalf("dangerous event was not enforced: decision=%+v session=%+v", next, updated)
	}
}

func TestTemporaryBlockExpires(t *testing.T) {
	m, _ := config.NewManager(t.TempDir(), config.Defaults())
	e := New(m, enforcement.NewMemory())
	block := domain.TemporaryBlock{ID: "b1", Indicator: "10.0.0.9", Reason: "scan", ExpiresAt: time.Now().Add(time.Minute)}
	if err := e.AddTemporaryBlock(context.Background(), block); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.ActiveBlock("10.0.0.9", time.Now()); !ok {
		t.Fatal("block not active")
	}
	e.SweepBlocks(time.Now().Add(2 * time.Minute))
	if _, ok := e.ActiveBlock("10.0.0.9", time.Now()); ok {
		t.Fatal("expired block remained")
	}
}
