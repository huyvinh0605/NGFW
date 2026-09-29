package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func m4Config() domain.Config {
	c := Defaults()
	c.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	c.Interfaces = []domain.Interface{
		{ID: "lan0", SystemName: "eth0", ZoneID: "lan", Mode: domain.InterfaceL3},
		{ID: "wan0", SystemName: "eth1", ZoneID: "wan", Mode: domain.InterfaceL3},
	}
	c.RequestGate = &domain.RequestGateConfig{Enabled: true}
	c.Profiles = []domain.SecurityProfile{{ID: "gate", TLSMode: domain.TLSDecrypt, RequestGate: &domain.RequestGateProfile{Enabled: true, FailMode: domain.GateFailClose, OversizeAction: "BLOCK", UnsupportedEncodingAction: "BLOCK", BlockQUIC: true}}}
	c.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, SecurityProfileID: "gate", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	c.TLSExclusions = []domain.TLSExclusion{{ID: "bank", Enabled: true, Domains: []string{"*.Example.COM."}, DestinationCIDRs: []string{"203.0.113.0/24"}, Ports: []int{443}, Reason: "banking site pinning"}}
	return c
}

func errorsContain(errs []string, part string) bool {
	for _, err := range errs {
		if strings.Contains(err, part) {
			return true
		}
	}
	return false
}

func TestM4ConfigDefaultsAndValidation(t *testing.T) {
	c := m4Config()
	if errs := (Validator{}).Validate(c); len(errs) != 0 {
		t.Fatalf("valid M4 config rejected: %v", errs)
	}
	g := domain.EffectiveRequestGateConfig(c)
	if g.WorkerCount != 2 || g.MaxRawBodyBytes != 64<<10 || g.RequestTimeoutMillis != 2000 {
		t.Fatalf("incorrect defaults: %+v", g)
	}
	if c.RequestGate.WorkerCount != 0 {
		t.Fatal("defaults mutated candidate")
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded domain.Config
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if errs := (Validator{}).Validate(decoded); len(errs) != 0 {
		t.Fatalf("JSON round-trip invalid: %v", errs)
	}
}

func TestM4OffPreservesLegacyValidation(t *testing.T) {
	c := Defaults()
	baseline := (Validator{}).Validate(c)
	c.RequestGate = &domain.RequestGateConfig{Enabled: false, WorkerCount: -1}
	c.TLSExclusions = []domain.TLSExclusion{{ID: "ignored", Enabled: true, Domains: []string{"not a domain"}}}
	c.Profiles = []domain.SecurityProfile{{ID: "future", TLSMode: domain.TLSMetadata, RequestGate: &domain.RequestGateProfile{Enabled: true, FailMode: "BAD"}}}
	if errs := (Validator{}).Validate(c); len(errs) != len(baseline) {
		t.Fatalf("disabled M4 fields changed legacy validation: %v vs %v", errs, baseline)
	}
}

func TestM4LimitBounds(t *testing.T) {
	tests := []struct {
		name string
		set  func(*domain.RequestGateConfig)
		want string
	}{
		{"workers", func(g *domain.RequestGateConfig) { g.WorkerCount = 5 }, "worker_count"},
		{"negative queue", func(g *domain.RequestGateConfig) { g.QueueItems = -1 }, "queue_items"},
		{"queue bytes", func(g *domain.RequestGateConfig) { g.QueueBytes = 64 << 20 }, "queue_bytes"},
		{"per client", func(g *domain.RequestGateConfig) { g.MaxPerClientRequests = 129 }, "max_per_client_requests"},
		{"raw body", func(g *domain.RequestGateConfig) { g.MaxRawBodyBytes = 2 << 20 }, "max_raw_body_bytes"},
		{"decompressed less than raw", func(g *domain.RequestGateConfig) { g.MaxDecompressedBodyBytes = 1024 }, "max_decompressed_body_bytes"},
		{"timeout", func(g *domain.RequestGateConfig) { g.RequestTimeoutMillis = 30001 }, "request_timeout_ms"},
		{"same listener", func(g *domain.RequestGateConfig) { g.ListenHTTPPort = 18443 }, "listen ports"},
		{"leaf TTL", func(g *domain.RequestGateConfig) { g.LeafCacheTTLSeconds = 86401 }, "leaf_cache_ttl_seconds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := m4Config()
			tc.set(c.RequestGate)
			if errs := ValidateRequestGate(c); !errorsContain(errs, tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, errs)
			}
		})
	}
}

func TestM4GateRequiresAllowSessionAndExplicitFailureActions(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.Config)
		want string
	}{
		{"drop", func(c *domain.Config) { c.Policies[0].Action = domain.DecisionDrop }, "ALLOW SESSION"},
		{"packet", func(c *domain.Config) { c.Policies[0].Scope = "PACKET" }, "ALLOW SESSION"},
		{"UDP only", func(c *domain.Config) { c.Policies[0].Services = []string{"udp:53"} }, "TCP service"},
		{"fail mode", func(c *domain.Config) { c.Profiles[0].RequestGate.FailMode = "UNKNOWN" }, "fail_mode"},
		{"oversize", func(c *domain.Config) { c.Profiles[0].RequestGate.OversizeAction = "" }, "oversize_action"},
		{"encoding", func(c *domain.Config) { c.Profiles[0].RequestGate.UnsupportedEncodingAction = "" }, "unsupported_encoding_action"},
		{"quic without decrypt", func(c *domain.Config) { c.Profiles[0].TLSMode = domain.TLSMetadata }, "block_quic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := m4Config()
			tc.edit(&c)
			if errs := ValidateRequestGate(c); !errorsContain(errs, tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, errs)
			}
		})
	}
}

func TestM4TLSExclusionValidationAndCanonicalDomain(t *testing.T) {
	for raw, want := range map[string]string{"*.Example.COM.": "*.example.com", "API.Example.COM": "api.example.com"} {
		got, err := canonicalTLSDomain(raw)
		if err != nil || got != want {
			t.Fatalf("canonicalTLSDomain(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "*.com", "foo.*.example.com", "bücher.example", "bad..example.com", "-bad.example.com"} {
		if _, err := canonicalTLSDomain(raw); err == nil {
			t.Errorf("accepted invalid TLS domain %q", raw)
		}
	}
	c := m4Config()
	c.TLSExclusions[0].DestinationCIDRs = []string{"not-cidr"}
	c.TLSExclusions[0].Ports = []int{65536}
	c.TLSExclusions[0].Reason = ""
	for _, want := range []string{"invalid CIDR", "invalid port", "requires reason"} {
		if errs := ValidateRequestGate(c); !errorsContain(errs, want) {
			t.Errorf("expected %q, got %v", want, errs)
		}
	}
}

func TestM4ConfigCloneDoesNotAliasNestedGateOrExclusions(t *testing.T) {
	c := m4Config()
	cloned := cloneConfig(c)
	cloned.RequestGate.WorkerCount = 4
	cloned.Profiles[0].RequestGate.FailMode = domain.GateFailOpen
	cloned.TLSExclusions[0].Domains[0] = "other.example.com"
	cloned.TLSExclusions[0].DestinationCIDRs[0] = "192.0.2.0/24"
	cloned.TLSExclusions[0].Ports[0] = 8443
	if c.RequestGate.WorkerCount != 0 || c.Profiles[0].RequestGate.FailMode != domain.GateFailClose || c.TLSExclusions[0].Domains[0] != "*.Example.COM." || c.TLSExclusions[0].DestinationCIDRs[0] != "203.0.113.0/24" || c.TLSExclusions[0].Ports[0] != 443 {
		t.Fatal("clone changed original M4 configuration")
	}
}

func TestM3IPSFailModeUnaffectedByM4Gate(t *testing.T) {
	c := m3Config()
	c.RequestGate = &domain.RequestGateConfig{Enabled: true}
	c.Profiles[0].TLSMode = domain.TLSDecrypt
	c.Profiles[0].RequestGate = &domain.RequestGateProfile{Enabled: true, FailMode: domain.GateFailClose, OversizeAction: "BLOCK", UnsupportedEncodingAction: "BLOCK"}
	if errs := ValidateInspection(c); len(errs) != 0 {
		t.Fatalf("M4 TLS decrypt unexpectedly changed M3 IPS validation: %v", errs)
	}
	c.Profiles[0].Inspection.FailMode = "CLOSE"
	if errs := ValidateInspection(c); !errorsContain(errs, "fail_mode must be OPEN") {
		t.Fatalf("M4 gate incorrectly enabled M3 fail-close: %v", errs)
	}
}
