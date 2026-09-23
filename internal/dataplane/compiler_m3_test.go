package dataplane

import (
	"fmt"
	"strings"
	"testing"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

func m3DataplaneConfig() domain.Config {
	c := configpkg.Defaults()
	c.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	c.Interfaces = []domain.Interface{{ID: "lan0", SystemName: "eth1", ZoneID: "lan", Mode: domain.InterfaceL3}, {ID: "wan0", SystemName: "eth0", ZoneID: "wan", Mode: domain.InterfaceL3}}
	c.Inspection = &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()}
	c.Profiles = []domain.SecurityProfile{{ID: "ips", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIPS, FailMode: "OPEN", RulesetID: configpkg.BuiltinM3RulesetID}}}
	c.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, Applications: []string{"HTTP", "TLS"}, ApplicationMatchMode: configpkg.ApplicationMatchRestrictL3Allow, SecurityProfileID: "ips", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	return c
}

func TestCompileM3BundleKeepsDynamicSetsOutOfPolicyTransaction(t *testing.T) {
	c := m3DataplaneConfig()
	_, plan, bundle, err := CompileM3(c, 2, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 1 {
		t.Fatalf("unexpected plan %#v", plan)
	}
	if strings.Contains(bundle.PolicyTransaction, "flush table inet ngfw_inspection") || strings.Contains(bundle.PolicyTransaction, "flush set inet ngfw_inspection app_denied_v4") {
		t.Fatal("policy transaction flushes dynamic inspection state")
	}
	for _, want := range []string{"flush chain inet ngfw_inspection inspect", "queue num 100 bypass", "meta nfproto . meta l4proto @ips_ready", "tcp dport 80", "tcp dport 443"} {
		if !strings.Contains(bundle.PolicyTransaction, want) {
			t.Fatalf("missing %q in:\n%s", want, bundle.PolicyTransaction)
		}
	}
}

func TestInspectionSchemaUsesQualifiedExpressionTypes(t *testing.T) {
	script := InspectionSchemaScript()
	if strings.Contains(script, "type integer") {
		t.Fatal("unqualified integer type returned")
	}
	for _, want := range []string{"typeof ct zone . ct id", "flags timeout", "priority -15", "priority 10"} {
		if !strings.Contains(script, want) {
			t.Fatalf("schema missing %q", want)
		}
	}
}

func TestIDSPlanUsesNFLOGNotNFQUEUE(t *testing.T) {
	c := m3DataplaneConfig()
	c.Profiles[0].Inspection.Mode = domain.InspectionModeIDS
	c.Policies[0].Applications = nil
	c.Policies[0].ApplicationMatchMode = ""
	_, _, bundle, err := CompileM3(c, 2, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bundle.PolicyTransaction, "log group 100") || strings.Contains(bundle.PolicyTransaction, "queue num 100") {
		t.Fatalf("IDS render incorrect:\n%s", bundle.PolicyTransaction)
	}
}

func TestInspectionCompilerExcludesManagementUnlessOptedIn(t *testing.T) {
	c := m3DataplaneConfig()
	c.Interfaces = append(c.Interfaces, domain.Interface{ID: "mgmt0", SystemName: "eth9", ZoneID: "mgmt", Mode: domain.InterfaceManagement, AdminState: true})
	_, _, bundle, err := CompileM3(c, 2, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bundle.PolicyTransaction, `iifname != "eth9" oifname != "eth9"`) {
		t.Fatalf("management exclusion missing:\n%s", bundle.PolicyTransaction)
	}
	c.Inspection.IncludeManagement = true
	_, _, bundle, err = CompileM3(c, 3, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bundle.PolicyTransaction, `iifname != "eth9"`) {
		t.Fatalf("management exclusion remained after opt-in:\n%s", bundle.PolicyTransaction)
	}
}

func TestInspectionCompilerBoundsExpandedServiceDirections(t *testing.T) {
	c := m3DataplaneConfig()
	c.Policies = make([]domain.SecurityPolicy, 0, 2501)
	for index := 0; index < 2501; index++ {
		c.Policies = append(c.Policies, domain.SecurityPolicy{ID: fmt.Sprintf("p-%d", index), Priority: index + 1, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80"}, SecurityProfileID: "ips", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true})
	}
	program := connectivity.Program{Generation: 1, Selections: map[string]connectivity.InspectionSelection{}}
	for _, policy := range c.Policies {
		program.Selections[policy.ID] = connectivity.InspectionSelection{PolicyID: policy.ID, Mode: domain.InspectionModeIPS, Generation: 1}
	}
	if _, err := CompileInspectionPlan(c, program); err == nil || !strings.Contains(err.Error(), "10000") {
		t.Fatalf("expanded selector cap was not enforced: %v", err)
	}
}
