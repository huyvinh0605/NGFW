package config

import (
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestPolicyEffectiveKeyIgnoresOrderIdentityAndPriority(t *testing.T) {
	left := domain.SecurityPolicy{ID: "a", Name: "A", Priority: 10, Enabled: true, SourceZones: []string{"lan", "dmz"}, DestinationZones: []string{"wan"}, Services: []string{"TCP:443", "tcp:80"}, Action: domain.DecisionAllow, Scope: "session"}
	right := left
	right.ID = "b"
	right.Name = "B"
	right.Priority = 99
	right.SourceZones = []string{"dmz", "LAN"}
	right.Services = []string{"tcp:80", "tcp:443", "tcp:80"}
	a, err := PolicyEffectiveKey(left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PolicyEffectiveKey(right)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("effective keys differ:\n%s\n%s", a, b)
	}
}

func TestExactDuplicatePolicyErrorsDoNotRejectPartialOverlap(t *testing.T) {
	base := domain.SecurityPolicy{ID: "a", Priority: 10, Enabled: true, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION"}
	duplicate := base
	duplicate.ID = "b"
	duplicate.Priority = 20
	if errs := ExactDuplicatePolicyErrors([]domain.SecurityPolicy{base, duplicate}); len(errs) != 1 || !strings.Contains(errs[0], "exact duplicate") {
		t.Fatalf("expected exact duplicate diagnostic, got %v", errs)
	}
	partial := base
	partial.ID = "c"
	partial.Services = []string{"tcp:443"}
	if errs := ExactDuplicatePolicyErrors([]domain.SecurityPolicy{base, partial}); len(errs) != 0 {
		t.Fatalf("partial overlap was mislabeled duplicate: %v", errs)
	}
}

func TestM3DuplicateIncludesApplicationModeAndProfileSemantics(t *testing.T) {
	c := m3Config()
	duplicate := c.Policies[0]
	duplicate.ID = "web-copy"
	duplicate.Priority = 20
	c.Policies = append(c.Policies, duplicate)
	if errs := ExactDuplicatePolicyErrorsForConfig(c); len(errs) != 1 {
		t.Fatalf("expected M3 duplicate, got %v", errs)
	}
	c.Policies[1].ApplicationMatchMode = ""
	if errs := ExactDuplicatePolicyErrorsForConfig(c); len(errs) != 0 {
		t.Fatal("application match mode was not part of effective key")
	}
}
