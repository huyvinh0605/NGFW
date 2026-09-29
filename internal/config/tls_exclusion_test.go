package config

import (
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestTLSExclusionCanonicalKeyIgnoresSelectorOrderAndSpelling(t *testing.T) {
	c := m4Config()
	c.TLSExclusions[0].Domains = []string{"*.Example.COM.", "api.other.example", "*.example.com"}
	c.TLSExclusions[0].DestinationCIDRs = []string{"203.0.113.25/24", "192.0.2.0/24"}
	c.TLSExclusions[0].Ports = []int{8443, 443, 443}
	first, err := TLSExclusionEffectiveKey(c)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSExclusions[0].Domains = []string{"api.other.example", "*.example.com"}
	c.TLSExclusions[0].DestinationCIDRs = []string{"192.0.2.0/24", "203.0.113.0/24"}
	c.TLSExclusions[0].Ports = []int{443, 8443}
	second, err := TLSExclusionEffectiveKey(c)
	if err != nil || first != second {
		t.Fatalf("equivalent exclusions have different keys: %s / %s; %v", first, second, err)
	}
}

func TestTLSExclusionDuplicateAndShadowRules(t *testing.T) {
	base := domain.TLSExclusion{ID: "first", Enabled: true, Domains: []string{"*.example.com"}, DestinationCIDRs: []string{"203.0.113.0/24"}, Ports: []int{443}, Reason: "test"}
	tests := []struct {
		name    string
		second  domain.TLSExclusion
		wantErr string
	}{
		{"duplicate", domain.TLSExclusion{ID: "copy", Enabled: true, Domains: []string{"*.EXAMPLE.COM."}, DestinationCIDRs: []string{"203.0.113.20/24"}, Ports: []int{443}, Reason: "other"}, "exact duplicate"},
		{"exact subdomain shadow", domain.TLSExclusion{ID: "api", Enabled: true, Domains: []string{"api.example.com"}, DestinationCIDRs: []string{"203.0.113.42/32"}, Ports: []int{443}, Reason: "other"}, "shadowed"},
		{"nested wildcard shadow", domain.TLSExclusion{ID: "nested", Enabled: true, Domains: []string{"*.api.example.com"}, DestinationCIDRs: []string{"203.0.113.42/32"}, Ports: []int{443}, Reason: "other"}, "shadowed"},
		{"apex not shadowed", domain.TLSExclusion{ID: "apex", Enabled: true, Domains: []string{"example.com"}, DestinationCIDRs: []string{"203.0.113.42/32"}, Ports: []int{443}, Reason: "other"}, ""},
		{"different port", domain.TLSExclusion{ID: "other-port", Enabled: true, Domains: []string{"api.example.com"}, DestinationCIDRs: []string{"203.0.113.42/32"}, Ports: []int{8443}, Reason: "other"}, ""},
		{"different CIDR", domain.TLSExclusion{ID: "other-net", Enabled: true, Domains: []string{"api.example.com"}, DestinationCIDRs: []string{"192.0.2.0/24"}, Ports: []int{443}, Reason: "other"}, ""},
		{"any port not shadowed", domain.TLSExclusion{ID: "any-port", Enabled: true, Domains: []string{"api.example.com"}, DestinationCIDRs: []string{"203.0.113.42/32"}, Reason: "other"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := m4Config()
			c.TLSExclusions = []domain.TLSExclusion{base, tc.second}
			errs := TLSExclusionSemanticErrors(c)
			if tc.wantErr == "" && len(errs) != 0 {
				t.Fatalf("unexpected semantic error: %v", errs)
			}
			if tc.wantErr != "" && !errorsContain(errs, tc.wantErr) {
				t.Fatalf("expected %q, got %v", tc.wantErr, errs)
			}
		})
	}
}

func TestTLSExclusionIdentityAndInactiveRules(t *testing.T) {
	c := m4Config()
	c.TLSExclusions = append(c.TLSExclusions, domain.TLSExclusion{ID: "bank", Enabled: false})
	if errs := ValidateRequestGate(c); !errorsContain(errs, "duplicate tls_exclusion ID") {
		t.Fatalf("duplicate ID was accepted: %v", errs)
	}
	c.TLSExclusions[1].ID = "inactive"
	if errs := ValidateRequestGate(c); len(errs) != 0 {
		t.Fatalf("inactive rule affected behavior: %v", errs)
	}
}

func TestM4PolicyKeyIncludesGateSemanticsOnlyWhenEnabled(t *testing.T) {
	c := m4Config()
	policy := c.Policies[0]
	before, err := EffectivePolicyKey(c, policy)
	if err != nil {
		t.Fatal(err)
	}
	c.Profiles[0].RequestGate.FailMode = domain.GateFailOpen
	afterFailMode, err := EffectivePolicyKey(c, policy)
	if err != nil || before == afterFailMode {
		t.Fatalf("fail mode omitted from effective policy key: %v", err)
	}
	c.Profiles[0].RequestGate.FailMode = domain.GateFailClose
	c.TLSExclusions[0].Ports = []int{8443}
	afterExclusion, err := EffectivePolicyKey(c, policy)
	if err != nil || before == afterExclusion {
		t.Fatalf("TLS exclusions omitted from effective policy key: %v", err)
	}
	c.RequestGate.Enabled = false
	inactive, err := EffectivePolicyKey(c, policy)
	if err != nil {
		t.Fatal(err)
	}
	c.Profiles[0].RequestGate.FailMode = domain.GateFailOpen
	c.TLSExclusions[0].Ports = []int{9443}
	inactiveAfter, err := EffectivePolicyKey(c, policy)
	if err != nil || inactive != inactiveAfter {
		t.Fatalf("disabled M4 changed legacy policy key: %v", err)
	}
}

func TestM4GateCannotRescuePolicyShadowedByEarlierDeny(t *testing.T) {
	c := m4Config()
	deny := c.Policies[0]
	deny.ID = "deny-first"
	deny.Priority = 1
	deny.SecurityProfileID = ""
	deny.Action = domain.DecisionDrop
	c.Policies = append([]domain.SecurityPolicy{deny}, c.Policies...)
	errs := UnreachablePolicyErrorsForConfig(c)
	if !errorsContain(errs, "policy web is unreachable") {
		t.Fatalf("gate incorrectly made shadowed allow reachable: %v", errs)
	}
	if !strings.Contains(errs[0], "deny-first") {
		t.Fatalf("missing authoritative deny source: %v", errs)
	}
}
