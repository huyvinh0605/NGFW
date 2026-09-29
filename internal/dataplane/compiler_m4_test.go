package dataplane

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

func TestM4ProxySchemaIsOwnedAndInertUntilCapabilityProbe(t *testing.T) {
	schema := ProxySchemaScript()
	if !strings.Contains(schema, "table inet ngfw_proxy") || !strings.Contains(schema, "schema=1") || !strings.Contains(schema, "chain select") {
		t.Fatalf("missing owned proxy schema: %q", schema)
	}
	for _, forbidden := range []string{"hook ", "redirect", "tproxy", "flush ruleset", "table inet ngfw {"} {
		if strings.Contains(strings.ToLower(schema), forbidden) {
			t.Fatalf("unprobed traffic mutation %q in inert schema", forbidden)
		}
	}
}

func m4SelectorConfig() domain.Config {
	c := configpkg.Defaults()
	c.RequestGate = &domain.RequestGateConfig{Enabled: true}
	c.Profiles = []domain.SecurityProfile{{ID: "web-gate", TLSMode: domain.TLSDecrypt, RequestGate: &domain.RequestGateProfile{Enabled: true, FailMode: domain.GateFailClose, OversizeAction: "BLOCK", UnsupportedEncodingAction: "BLOCK"}}}
	c.Policies = []domain.SecurityPolicy{
		{ID: "plain-allow", Priority: 10, SourceZones: []string{"mgmt"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
		{ID: "deny-host", Priority: 20, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, SourceAddresses: []string{"192.168.10.99/32"}, Services: []string{"tcp:443"}, Action: domain.DecisionDrop, Scope: "SESSION", Enabled: true},
		{ID: "gate-web", Priority: 30, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, SourceAddresses: []string{"192.168.10.0/24"}, Services: []string{"tcp:80", "tcp:443"}, SecurityProfileID: "web-gate", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
	}
	return c
}

func TestM4ProxySelectionPreservesFirstMatchAndAnnotatesOnlyGateAllow(t *testing.T) {
	plan, err := CompileM4ProxySelection(m4SelectorConfig(), 23)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Enabled || plan.SchemaVersion != ProxySelectionSchema || plan.Generation != 23 || plan.ListenHTTPPort != 18080 || plan.ListenHTTPSPort != 18443 {
		t.Fatalf("incorrect plan header: %+v", plan)
	}
	if len(plan.Rules) != 3 {
		t.Fatalf("all first-match rules must survive compilation, got %d", len(plan.Rules))
	}
	wantIDs := []string{"plain-allow", "deny-host", "gate-web"}
	wantGate := []bool{false, false, true}
	for index, rule := range plan.Rules {
		if rule.Match.ID != wantIDs[index] || rule.Match.Priority != (index+1)*10 || rule.Gate != wantGate[index] {
			t.Fatalf("rule %d changed first-match order or gate: %+v", index, rule)
		}
	}
	if plan.Rules[2].ProfileID != "web-gate" || len(plan.Rules[2].Match.SourceAddresses) != 1 || len(plan.Rules[2].Match.Services) != 2 {
		t.Fatalf("compiled L3/L4 match or profile was lost: %+v", plan.Rules[2])
	}
	if !reflect.DeepEqual(plan.Rules[2].GatePorts, []connectivity.PortRange{{First: 80, Last: 80}, {First: 443, Last: 443}}) {
		t.Fatalf("nft plan has incorrect gate ports: %+v", plan.Rules[2].GatePorts)
	}
	if plan.Rules[1].Match.Action != domain.DecisionDrop || plan.Rules[1].Gate {
		t.Fatal("earlier deny was incorrectly made an intercept rule")
	}
}

func TestM4ProxySelectorIsEmptyWhenDisabledOrNoGatePolicy(t *testing.T) {
	c := m4SelectorConfig()
	c.RequestGate.Enabled = false
	before := c.RequestGate.WorkerCount
	plan, err := CompileM4ProxySelection(c, 4)
	if err != nil || plan.Enabled || len(plan.Rules) != 0 || plan.ListenHTTPPort != 0 || plan.ListenHTTPSPort != 0 {
		t.Fatalf("M4 OFF produced a selector: %+v, %v", plan, err)
	}
	if c.RequestGate.WorkerCount != before {
		t.Fatal("selector compilation mutated candidate")
	}
	c.RequestGate.Enabled = true
	c.Policies[2].SecurityProfileID = ""
	plan, err = CompileM4ProxySelection(c, 5)
	if err != nil || plan.Enabled || len(plan.Rules) != 0 {
		t.Fatalf("gate without referenced profile produced selector: %+v, %v", plan, err)
	}
}

func TestM4ProxySelectionRejectsPolicyShadowAndGateOnDeny(t *testing.T) {
	c := m4SelectorConfig()
	c.Policies[1].SourceAddresses = nil // earlier deny now covers gate-web
	c.Policies[1].Services = nil
	if _, err := CompileM4ProxySelection(c, 8); err == nil {
		t.Fatal("a later gated ALLOW was accepted behind a covering deny")
	}
	c = m4SelectorConfig()
	c.Policies[2].Action = domain.DecisionDrop
	if _, err := CompileM4ProxySelection(c, 9); err == nil {
		t.Fatal("request-gate profile on DROP was accepted")
	}
	c = m4SelectorConfig()
	c.Policies[2].Services = []string{"udp:53"}
	if _, err := CompileM4ProxySelection(c, 10); err == nil {
		t.Fatal("UDP-only gate policy was accepted")
	}
}

func TestM4ProxySelectionDetachedFromCandidateAndClone(t *testing.T) {
	c := m4SelectorConfig()
	plan, err := CompileM4ProxySelection(c, 10)
	if err != nil {
		t.Fatal(err)
	}
	c.Policies[2].SourceAddresses[0] = "203.0.113.0/24"
	c.Policies[2].Services[0] = "udp:53"
	if plan.Rules[2].Match.SourceAddresses[0].String() != "192.168.10.0/24" || plan.Rules[2].Match.Services[0].Protocol != 6 {
		t.Fatal("compiled selector aliases candidate")
	}
	clone := plan.Clone()
	clone.Rules[2].Match.SourceZones["dmz"] = struct{}{}
	clone.Rules[2].Match.Services[0].Ports[0].First = 1
	clone.Rules[2].GatePorts[0].First = 1
	clone.Rules[2].Match.SourceAddresses[0] = clone.Rules[1].Match.SourceAddresses[0]
	if reflect.DeepEqual(clone.Rules[2].Match, plan.Rules[2].Match) || len(plan.Rules[2].Match.SourceZones) != 1 || plan.Rules[2].Match.Services[0].Ports[0].First == 1 || plan.Rules[2].GatePorts[0].First == 1 || plan.Rules[2].Match.SourceAddresses[0].String() != "192.168.10.0/24" {
		t.Fatal("selector clone aliases compiled rule data")
	}
}

func TestM4ProxySelectionValidationRejectsUnsafePlans(t *testing.T) {
	base, err := CompileM4ProxySelection(m4SelectorConfig(), 12)
	if err != nil {
		t.Fatal(err)
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("compiler returned invalid plan: %v", err)
	}
	tests := []struct {
		name string
		edit func(*ProxySelectionPlan)
	}{
		{"schema", func(p *ProxySelectionPlan) { p.SchemaVersion++ }},
		{"same listener", func(p *ProxySelectionPlan) { p.ListenHTTPSPort = p.ListenHTTPPort }},
		{"unordered", func(p *ProxySelectionPlan) { p.Rules[2].Match.Priority = 5 }},
		{"duplicate ID", func(p *ProxySelectionPlan) { p.Rules[2].Match.ID = p.Rules[1].Match.ID }},
		{"gate on deny", func(p *ProxySelectionPlan) { p.Rules[1].Gate = true; p.Rules[1].ProfileID = "web-gate" }},
		{"gate missing profile", func(p *ProxySelectionPlan) { p.Rules[2].ProfileID = "" }},
		{"gate missing ports", func(p *ProxySelectionPlan) { p.Rules[2].GatePorts = nil }},
		{"gate broadened ports", func(p *ProxySelectionPlan) { p.Rules[2].GatePorts[0].First = 1 }},
		{"ungated with ports", func(p *ProxySelectionPlan) { p.Rules[0].GatePorts = []connectivity.PortRange{{First: 443, Last: 443}} }},
		{"disabled but nonempty", func(p *ProxySelectionPlan) { p.Enabled = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := base.Clone()
			tc.edit(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatalf("unsafe plan %q accepted", tc.name)
			}
		})
	}
}

func TestM4ProxySelectionJSONRoundTripPreservesCompiledMatch(t *testing.T) {
	plan, err := CompileM4ProxySelection(m4SelectorConfig(), 14)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var restored ProxySelectionPlan
	if err := json.Unmarshal(payload, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("restored plan invalid: %v", err)
	}
	if !reflect.DeepEqual(plan, restored) {
		t.Fatalf("plan changed across JSON snapshot:\noriginal=%+v\nrestored=%+v", plan, restored)
	}
}
