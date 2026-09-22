package policy

import (
	"github.com/kltngfw/ngfw/internal/domain"
	"testing"
)

func TestFirstMatchAndRiskOverride(t *testing.T) {
	ps := []domain.SecurityPolicy{{ID: "allow", Name: "allow", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, SecurityProfileID: "web", Action: domain.DecisionAllow, Enabled: true}, {ID: "deny", Name: "deny", Priority: 20, Action: domain.DecisionDrop, Enabled: true}}
	ctx := &domain.SecurityContext{Network: domain.NetworkContext{SrcZone: "lan", DstZone: "wan"}, Risk: domain.RiskContext{Score: 10}}
	d := NewEvaluator(true).Evaluate(ctx, ps, map[string]domain.SecurityProfile{"web": {ID: "web", MinimumBlockRisk: 80}}, 1)
	if d.Action != domain.DecisionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}
	ctx.Risk.Score = 90
	d = NewEvaluator(true).Evaluate(ctx, ps, map[string]domain.SecurityProfile{"web": {ID: "web", MinimumBlockRisk: 80}}, 1)
	if d.Action != domain.DecisionDrop {
		t.Fatalf("expected risk drop, got %s", d.Action)
	}
}
func TestDefaultDeny(t *testing.T) {
	d := NewEvaluator(true).Evaluate(&domain.SecurityContext{}, nil, nil, 1)
	if d.Action != domain.DecisionDrop {
		t.Fatal("default deny not applied")
	}
}

func TestServiceMatcherUsesSharedRangeAndCaseSemantics(t *testing.T) {
	policies := []domain.SecurityPolicy{{ID: "web", Name: "web", Priority: 1, Services: []string{"TCP:80-90"}, Action: domain.DecisionAllow, Enabled: true}}
	inside := &domain.SecurityContext{Network: domain.NetworkContext{Protocol: "tcp", DstPort: 85}}
	if got := NewEvaluator(true).Evaluate(inside, policies, nil, 1); got.Action != domain.DecisionAllow {
		t.Fatalf("range service did not match: %#v", got)
	}
	outside := &domain.SecurityContext{Network: domain.NetworkContext{Protocol: "tcp", DstPort: 443}}
	if got := NewEvaluator(true).Evaluate(outside, policies, nil, 1); got.Action != domain.DecisionDrop {
		t.Fatalf("out-of-range service unexpectedly matched: %#v", got)
	}
}
