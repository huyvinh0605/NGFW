package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func TestRuntimeServiceRejectsShadowedPolicyBeforeReplacingCandidate(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	desired := manager.Candidate()
	desired.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	desired.Interfaces = []domain.Interface{
		{ID: "lan0", SystemName: "eth1", ZoneID: "lan", Mode: domain.InterfaceL3},
		{ID: "wan0", SystemName: "eth0", ZoneID: "wan", Mode: domain.InterfaceL3},
	}
	desired.Policies = []domain.SecurityPolicy{
		{ID: "allow-web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
		{ID: "allow-https", Priority: 20, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
	}
	service := NewRuntimeServiceAdapter(nil, manager, func(context.Context, domain.Config) error { return nil })
	if _, err := service.CommitConfig(context.Background(), desired, 0, "test", "shadow", "op-shadow"); err == nil || !strings.Contains(err.Error(), "policy allow-https is unreachable") {
		t.Fatalf("expected shadowed-policy rejection, got %v", err)
	}
	if len(manager.Candidate().Policies) != 0 {
		t.Fatalf("rejected candidate replaced manager state: %#v", manager.Candidate().Policies)
	}
}
