package config

import (
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func m3Config() domain.Config {
	c := Defaults()
	c.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	c.Interfaces = []domain.Interface{{ID: "lan0", SystemName: "eth0", ZoneID: "lan", Mode: domain.InterfaceL3}, {ID: "wan0", SystemName: "eth1", ZoneID: "wan", Mode: domain.InterfaceL3}}
	c.Inspection = &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()}
	c.Profiles = []domain.SecurityProfile{{ID: "m3", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIPS, FailMode: "OPEN", RulesetID: BuiltinM3RulesetID}}}
	c.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80"}, Applications: []string{"HTTP"}, ApplicationMatchMode: ApplicationMatchRestrictL3Allow, SecurityProfileID: "m3", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	return c
}

func TestValidateInspectionAcceptsM3Profile(t *testing.T) {
	if errs := ValidateInspection(m3Config()); len(errs) != 0 {
		t.Fatalf("valid M3 config rejected: %v", errs)
	}
}

func TestValidateInspectionRejectsFailClosedAndUnsupportedApp(t *testing.T) {
	c := m3Config()
	c.Profiles[0].Inspection.FailMode = "CLOSED"
	c.Policies[0].Applications = []string{"SQL"}
	if errs := ValidateInspection(c); len(errs) < 2 {
		t.Fatalf("expected fail mode and application errors, got %v", errs)
	}
}

func TestLegacyM2ProfileDoesNotActivateM3Validation(t *testing.T) {
	c := Defaults()
	c.Profiles = []domain.SecurityProfile{{ID: "basic", DPIEnabled: true, TLSMode: domain.TLSMetadata}}
	c.Policies = []domain.SecurityPolicy{{ID: "allow", Priority: 10, SecurityProfileID: "basic", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	if domain.UsesM3(c) {
		t.Fatal("legacy profile unexpectedly activates M3")
	}
	if errs := ValidateInspection(c); len(errs) != 0 {
		t.Fatalf("legacy M2 config rejected: %v", errs)
	}
}

func TestDisabledInspectionProfileDoesNotActivateM3Runtime(t *testing.T) {
	c := Defaults()
	c.Inspection = &domain.InspectionConfig{Enabled: false}
	c.Profiles = []domain.SecurityProfile{{ID: "future-ids", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIDS, FailMode: InspectionFailOpen, RulesetID: BuiltinM3RulesetID}}}
	if domain.UsesM3(c) {
		t.Fatal("disabled inspection with an unreferenced profile would spawn the M3 runtime")
	}
	if errs := ValidateInspection(c); len(errs) != 0 {
		t.Fatalf("valid inactive profile should remain editable: %v", errs)
	}
}

func TestEffectiveInspectionConfigDoesNotMutateInput(t *testing.T) {
	c := domain.Config{Inspection: &domain.InspectionConfig{Enabled: true}}
	effective := domain.EffectiveInspectionConfig(c)
	if effective.Limits.EVELineBytes == 0 || c.Inspection.Limits.EVELineBytes != 0 {
		t.Fatal("effective defaults mutated input")
	}
}

func TestInspectionLimitHardCapsMatchM3ResourceContract(t *testing.T) {
	tests := []struct {
		name string
		set  func(*domain.InspectionLimits)
	}{
		{"normalized event", func(value *domain.InspectionLimits) { value.NormalizedEventBytes = 16<<10 + 1 }},
		{"security bytes", func(value *domain.InspectionLimits) { value.SecurityEventBytes = 32<<20 + 1 }},
		{"pending", func(value *domain.InspectionLimits) { value.CorrelationPending = 4097 }},
		{"correlation wait", func(value *domain.InspectionLimits) { value.CorrelationWaitMillis = 5001 }},
		{"application minimum", func(value *domain.InspectionLimits) { value.AppDetectionTimeoutMillis = 999 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value := m3Config()
			tc.set(&value.Inspection.Limits)
			if errs := ValidateInspection(value); len(errs) == 0 {
				t.Fatal("out-of-contract limit was accepted")
			}
		})
	}
}
