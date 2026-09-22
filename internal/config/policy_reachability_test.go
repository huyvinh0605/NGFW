package config

import (
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func l3Policy(id string, priority int, services []string) domain.SecurityPolicy {
	return domain.SecurityPolicy{
		ID:               id,
		Name:             id,
		Priority:         priority,
		SourceZones:      []string{"lan"},
		DestinationZones: []string{"wan"},
		Services:         services,
		Action:           domain.DecisionAllow,
		Scope:            "SESSION",
		Enabled:          true,
	}
}

func TestUnreachablePolicyErrorsDetectsFullyShadowedHigherPriorityRule(t *testing.T) {
	earlier := l3Policy("allow-lan-web", 10, []string{"tcp:80", "tcp:443", "udp:53"})
	later := l3Policy("test-lan-http", 50, []string{"tcp:80", "tcp:443"})
	errs := UnreachablePolicyErrors([]domain.SecurityPolicy{earlier, later})
	message := strings.Join(errs, "\n")
	if !strings.Contains(message, "policy test-lan-http is unreachable") || !strings.Contains(message, "allow-lan-web (priority 10)") {
		t.Fatalf("expected shadowed-policy validation error, got: %s", message)
	}
}

func TestUnreachablePolicyErrorsAllowsPartiallyOverlappingPolicy(t *testing.T) {
	earlier := l3Policy("allow-http", 10, []string{"tcp:80"})
	later := l3Policy("allow-https", 20, []string{"tcp:443"})
	if errs := UnreachablePolicyErrors([]domain.SecurityPolicy{earlier, later}); len(errs) != 0 {
		t.Fatalf("partially overlapping policy was incorrectly rejected: %v", errs)
	}
}

func TestUnreachablePolicyErrorsRecognizesNetworkAndAction(t *testing.T) {
	earlier := l3Policy("allow-lan-web", 10, []string{"tcp"})
	earlier.SourceAddresses = []string{"192.168.0.0/16"}
	later := l3Policy("drop-subnet-web", 20, []string{"tcp:443"})
	later.SourceAddresses = []string{"192.168.10.0/24"}
	later.Action = domain.DecisionDrop
	errs := UnreachablePolicyErrors([]domain.SecurityPolicy{earlier, later})
	if !strings.Contains(strings.Join(errs, "\n"), "policy drop-subnet-web is unreachable") {
		t.Fatalf("expected higher-priority allow to shadow later drop, got: %v", errs)
	}
}
