package connectivity

import (
	"net/netip"
	"testing"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func validM3ProgramConfig() domain.Config {
	c := configpkg.Defaults()
	c.Inspection = &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()}
	c.Profiles = []domain.SecurityProfile{{ID: "ips", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIPS, FailMode: "OPEN", RulesetID: configpkg.BuiltinM3RulesetID}}}
	c.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, Applications: []string{"tls", "HTTP"}, ApplicationMatchMode: configpkg.ApplicationMatchRestrictL3Allow, SecurityProfileID: "ips", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	return c
}

func TestCompileM3SelectsInspectionAfterL3Match(t *testing.T) {
	p, err := CompileM3(validM3ProgramConfig(), 7)
	if err != nil {
		t.Fatal(err)
	}
	selection := SelectInspection(p, View{SourceIP: netip.MustParseAddr("192.168.10.10"), DestinationIP: netip.MustParseAddr("203.0.113.10"), DestinationPort: 443, Protocol: 6, SourceZone: "lan", DestinationZone: "wan"})
	if selection.Mode != domain.InspectionModeIPS || selection.ProfileID != "ips" || len(selection.AllowedApps) != 2 || selection.Generation != 7 {
		t.Fatalf("bad selection: %#v", selection)
	}
	copy := p.Clone()
	selected := copy.Selections["web"]
	selected.AllowedApps[0] = "CHANGED"
	if p.Selections["web"].AllowedApps[0] == "CHANGED" {
		t.Fatal("program clone shares selection slice")
	}
}

func TestCompileForCapabilitiesRejectsMissingInspection(t *testing.T) {
	if _, err := CompileForCapabilities(validM3ProgramConfig(), 1, Capabilities{}); err == nil {
		t.Fatal("M3 config accepted without capability")
	}
}

func TestApplicationCannotOpenL3Deny(t *testing.T) {
	c := validM3ProgramConfig()
	c.Policies[0].Action = domain.DecisionDrop
	if _, err := CompileM3(c, 1); err == nil {
		t.Fatal("application restriction on DROP accepted")
	}
}

func TestManagementTrafficRequiresExplicitInspectionOptIn(t *testing.T) {
	c := validM3ProgramConfig()
	c.Interfaces = []domain.Interface{{ID: "mgmt0", SystemName: "eth9", ZoneID: "mgmt", Mode: domain.InterfaceManagement, AdminState: true}}
	c.Policies[0].SourceZones = nil
	program, err := CompileM3(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	view := View{SourceIP: netip.MustParseAddr("192.168.100.10"), DestinationIP: netip.MustParseAddr("203.0.113.10"), DestinationPort: 443, Protocol: 6, SourceZone: "mgmt", DestinationZone: "wan"}
	if selection := SelectInspection(program, view); selection.Mode != domain.InspectionModeOff {
		t.Fatalf("management traffic inspected without opt-in: %#v", selection)
	}
	c.Inspection.IncludeManagement = true
	program, err = CompileM3(c, 3)
	if err != nil {
		t.Fatal(err)
	}
	if selection := SelectInspection(program, view); selection.Mode != domain.InspectionModeIPS {
		t.Fatalf("management opt-in was ignored: %#v", selection)
	}
	clone := program.Clone()
	delete(clone.ManagementZones, "mgmt")
	if _, ok := program.ManagementZones["mgmt"]; !ok {
		t.Fatal("program clone shares management zone map")
	}
}
