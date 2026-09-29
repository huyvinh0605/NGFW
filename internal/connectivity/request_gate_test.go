package connectivity

import (
	"net/netip"
	"reflect"
	"testing"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func m4ProgramConfig() domain.Config {
	c := configpkg.Defaults()
	c.RequestGate = &domain.RequestGateConfig{Enabled: true}
	c.Profiles = []domain.SecurityProfile{{ID: "gate", TLSMode: domain.TLSDecrypt, RequestGate: &domain.RequestGateProfile{Enabled: true, FailMode: domain.GateFailClose, OversizeAction: "BLOCK", UnsupportedEncodingAction: "BLOCK"}}}
	c.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, SecurityProfileID: "gate", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	c.TLSExclusions = []domain.TLSExclusion{{ID: "bank", Enabled: true, Domains: []string{"*.Example.COM."}, DestinationCIDRs: []string{"10.20.0.0/24"}, Ports: []int{443}, Reason: "pinning"}}
	return c
}

func m4View(port uint16) View {
	return View{SourceIP: netip.MustParseAddr("192.168.10.10"), DestinationIP: netip.MustParseAddr("10.20.0.10"), SourcePort: 50000, DestinationPort: port, Protocol: 6, SourceZone: "lan", DestinationZone: "wan"}
}

func TestRequestGateTCPPortsIsSharedWithRuntimeSelection(t *testing.T) {
	c := m4ProgramConfig()
	c.Policies[0].Services = nil
	program, err := CompileM4(c, 31)
	if err != nil {
		t.Fatal(err)
	}
	wildcard, ok := program.CompiledRequestGateForPolicy("web")
	if !ok || !reflect.DeepEqual(wildcard.TCPPorts(), []PortRange{{First: 80, Last: 80}, {First: 443, Last: 443}}) {
		t.Fatalf("wildcard must gate only HTTP and HTTPS: %+v", wildcard.TCPPorts())
	}
	for _, port := range []uint16{79, 81, 442, 444, 8443} {
		if selected := SelectRequestGate(program, m4View(port)); selected.Enabled {
			t.Fatalf("wildcard unexpectedly gated TCP/%d", port)
		}
	}
	ports := wildcard.TCPPorts()
	ports[0].First = 1
	if SelectRequestGate(program, m4View(1)).Enabled {
		t.Fatal("returned gate ports alias compiled runtime state")
	}
	clone := program.Clone()
	clonedGate := clone.requestGates["web"]
	clonedGate.tcpPorts[0].First = 1
	clone.requestGates["web"] = clonedGate
	if SelectRequestGate(program, m4View(1)).Enabled {
		t.Fatal("cloned program aliases original gate ports")
	}

	c.Policies[0].Services = []string{"udp:53", "tcp:443-444", "tcp:80", "tcp:444-445", "tcp:8443"}
	program, err = CompileM4(c, 32)
	if err != nil {
		t.Fatal(err)
	}
	explicit, ok := program.CompiledRequestGateForPolicy("web")
	want := []PortRange{{First: 80, Last: 80}, {First: 443, Last: 445}, {First: 8443, Last: 8443}}
	if !ok || !reflect.DeepEqual(explicit.TCPPorts(), want) {
		t.Fatalf("explicit TCP services lost OR/range semantics: got %+v want %+v", explicit.TCPPorts(), want)
	}
	for _, port := range []uint16{80, 443, 444, 445, 8443} {
		if !SelectRequestGate(program, m4View(port)).Enabled {
			t.Fatalf("explicit TCP/%d was not gated", port)
		}
	}
	udp := m4View(53)
	udp.Protocol = 17
	if SelectRequestGate(program, udp).Enabled {
		t.Fatal("UDP submatch was gated")
	}
}

func TestCompileM4SelectsOnlyFirstMatchAllowAndBindsGeneration(t *testing.T) {
	c := m4ProgramConfig()
	p, err := CompileM4(c, 17)
	if err != nil {
		t.Fatal(err)
	}
	plan := SelectRequestGate(p, m4View(443))
	if !plan.Enabled || plan.PolicyID != "web" || plan.ProfileID != "gate" || plan.Generation != 17 || plan.TLSMode != domain.TLSDecrypt || plan.FailMode != domain.GateFailClose || plan.RulesetID != domain.DefaultRequestGateConfig().RulesetID {
		t.Fatalf("wrong gate plan: %+v", plan)
	}
	denied := c.Policies[0]
	denied.ID, denied.Priority, denied.SecurityProfileID, denied.Action = "deny", 1, "", domain.DecisionDrop
	c.Policies = append([]domain.SecurityPolicy{denied}, c.Policies...)
	if _, err := CompileM4(c, 18); err == nil {
		t.Fatal("gate accepted a policy shadowed by first-match deny")
	}
	// At runtime, even a program with a cached later gate plan must obey the
	// authoritative first-match decision.
	p.Rules = append([]Rule{{ID: "deny", Priority: 1, Action: domain.DecisionDrop, Enabled: true}}, p.Rules...)
	if selected := SelectRequestGate(p, m4View(443)); selected.Enabled || selected.PolicyID != "deny" {
		t.Fatalf("deny opened by later gate: %+v", selected)
	}
}

func TestM4NoImplicitGateFromDefaultAllowOrUnsupportedTransport(t *testing.T) {
	c := m4ProgramConfig()
	c.DefaultDeny = false
	p, err := CompileM4(c, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range []View{
		{SourceIP: netip.MustParseAddr("192.0.2.2"), DestinationIP: netip.MustParseAddr("203.0.113.10"), DestinationPort: 443, Protocol: 6, SourceZone: "dmz", DestinationZone: "wan"},
		{SourceIP: netip.MustParseAddr("192.168.10.10"), DestinationIP: netip.MustParseAddr("10.20.0.10"), DestinationPort: 443, Protocol: 17, SourceZone: "lan", DestinationZone: "wan"},
	} {
		if plan := SelectRequestGate(p, view); plan.Enabled {
			t.Fatalf("implicit gate on default/UDP flow: %+v", plan)
		}
	}
	if plan := SelectRequestGate(p, m4View(8443)); plan.Enabled {
		t.Fatalf("port not selected by policy acquired gate: %+v", plan)
	}
	c.Policies[0].Services = nil // wildcard policy: standard web ports only
	p, err = CompileM4(c, 3)
	if err != nil {
		t.Fatal(err)
	}
	if plan := SelectRequestGate(p, m4View(8443)); plan.Enabled {
		t.Fatal("wildcard policy sent every TCP port through HTTP/TLS gate")
	}
	c.Policies[0].Services = []string{"tcp:8443"}
	p, err = CompileM4(c, 4)
	if err != nil {
		t.Fatal(err)
	}
	if plan := SelectRequestGate(p, m4View(8443)); !plan.Enabled {
		t.Fatal("explicit alternate TLS port was not selected")
	}
}

func TestM4MixedTCPUDPPolicyGatesOnlyTCP(t *testing.T) {
	c := m4ProgramConfig()
	c.Policies[0].Services = append(c.Policies[0].Services, "udp:53")
	p, err := CompileM4(c, 5)
	if err != nil {
		t.Fatal(err)
	}
	udp := m4View(53)
	udp.Protocol = 17
	if decision := p.Evaluate(udp); decision.Action != domain.DecisionAllow || decision.PolicyID != "web" {
		t.Fatalf("fixture UDP did not match base policy: %+v", decision)
	}
	if plan := SelectRequestGate(p, udp); plan.Enabled {
		t.Fatalf("UDP submatch was sent to HTTP/TLS gate: %+v", plan)
	}
	if plan := SelectRequestGate(p, m4View(443)); !plan.Enabled {
		t.Fatal("TCP submatch lost gate")
	}
}

func TestM4ExclusionUsesPostDNATDestinationAndFirstMatch(t *testing.T) {
	c := m4ProgramConfig()
	c.TLSExclusions = append(c.TLSExclusions, domain.TLSExclusion{ID: "cidr-only", Enabled: true, DestinationCIDRs: []string{"10.20.0.0/16"}, Ports: []int{443}, Reason: "private network"})
	p, err := CompileM4(c, 7)
	if err != nil {
		t.Fatal(err)
	}
	plan := SelectRequestGate(p, m4View(443))
	postDNAT := netip.MustParseAddrPort("10.20.0.10:443")
	public := netip.MustParseAddrPort("198.51.100.20:443")
	if exclusion, ok := plan.MatchTLSExclusion("API.EXAMPLE.COM.", postDNAT); !ok || exclusion.ID != "bank" {
		t.Fatalf("expected first matched domain+post-DNAT CIDR: %+v %v", exclusion, ok)
	}
	if exclusion, ok := plan.MatchTLSExclusion("example.com", postDNAT); !ok || exclusion.ID != "cidr-only" {
		t.Fatalf("wildcard matched apex or later CIDR rule missed: %+v %v", exclusion, ok)
	}
	if _, ok := plan.MatchTLSExclusion("api.example.com", public); ok {
		t.Fatal("pre-DNAT public IP incorrectly matched private destination exclusion")
	}
	if exclusion, ok := plan.MatchTLSExclusion("[hidden ECH]", postDNAT); !ok || exclusion.ID != "cidr-only" {
		t.Fatalf("invalid SNI should match only CIDR-only exclusion: %+v %v", exclusion, ok)
	}
	if _, ok := plan.MatchTLSExclusion("api.example.com", netip.MustParseAddrPort("10.20.0.10:8443")); ok {
		t.Fatal("exclusion ignored destination port")
	}
}

func TestM4PlanAndProgramCloneAreIsolated(t *testing.T) {
	c := m4ProgramConfig()
	p, err := CompileM4(c, 9)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSExclusions[0].Domains[0] = "changed.example.com"
	c.Profiles[0].RequestGate.FailMode = domain.GateFailOpen
	first := SelectRequestGate(p, m4View(443))
	if first.FailMode != domain.GateFailClose || first.TLSExclusionRules()[0].Domains[0] != "*.example.com" {
		t.Fatal("compiled gate aliases candidate configuration")
	}
	detached := first.TLSExclusionRules()
	detached[0].Domains[0] = "corrupt.example.com"
	second := SelectRequestGate(p, m4View(443))
	if second.TLSExclusionRules()[0].Domains[0] != "*.example.com" {
		t.Fatal("returned gate plan mutates compiled program")
	}
	cloned := p.Clone()
	cloned.requestGates["web"].exclusions.rules[0].Domains[0] = "clone.example.com"
	if SelectRequestGate(p, m4View(443)).TLSExclusionRules()[0].Domains[0] != "*.example.com" {
		t.Fatal("Program.Clone shares gate selectors")
	}
}

func TestM4GatePoliciesShareOneBoundedExclusionSnapshot(t *testing.T) {
	c := m4ProgramConfig()
	second := c.Policies[0]
	second.ID = "web-dmz"
	second.Priority = 20
	second.DestinationZones = []string{"dmz"}
	c.Policies = append(c.Policies, second)
	p, err := CompileM4(c, 10)
	if err != nil {
		t.Fatal(err)
	}
	if p.requestGates["web"].exclusions != p.requestGates["web-dmz"].exclusions {
		t.Fatal("compiled every policy with a separate exclusion snapshot")
	}
	for i := 0; i < 100; i++ {
		if plan := SelectRequestGate(p, m4View(443)); !plan.Enabled || plan.exclusions != p.requestGates["web"].exclusions {
			t.Fatal("per-flow gate selection copied the entire exclusion set")
		}
	}
	cloned := p.Clone()
	if cloned.requestGates["web"].exclusions == p.requestGates["web"].exclusions || cloned.requestGates["web"].exclusions != cloned.requestGates["web-dmz"].exclusions {
		t.Fatal("Program.Clone did not retain isolated shared snapshot")
	}
}

func TestM4CapabilityAndGloballyDisabledGate(t *testing.T) {
	c := m4ProgramConfig()
	if _, err := CompileForCapabilities(c, 1, Capabilities{Inspection: true}); err == nil {
		t.Fatal("active M4 configuration accepted without gate capability")
	}
	if _, err := CompileForCapabilities(c, 1, Capabilities{RequestGate: true}); err != nil {
		t.Fatalf("M4-only config required M3 capability: %v", err)
	}
	c.RequestGate.Enabled = false
	p, err := CompileForCapabilities(c, 2, Capabilities{})
	if err != nil {
		t.Fatalf("disabled gate should preserve L3 policy: %v", err)
	}
	if decision := p.Evaluate(m4View(443)); decision.Action != domain.DecisionAllow || decision.PolicyID != "web" {
		t.Fatalf("disabled gate changed connectivity decision: %+v", decision)
	}
	if plan := SelectRequestGate(p, m4View(443)); plan.Enabled {
		t.Fatalf("disabled M4 gate produced active plan: %+v", plan)
	}
}

func TestM4PreservesM3InspectionSelection(t *testing.T) {
	c := m4ProgramConfig()
	c.Inspection = &domain.InspectionConfig{Enabled: true}
	c.Profiles[0].IDSIPSEnabled = true
	c.Profiles[0].Inspection = &domain.InspectionProfile{Mode: domain.InspectionModeIPS, FailMode: "OPEN", RulesetID: configpkg.BuiltinM3RulesetID}
	c.Policies[0].Applications = []string{"HTTP", "TLS"}
	c.Policies[0].ApplicationMatchMode = configpkg.ApplicationMatchRestrictL3Allow
	if _, err := CompileForCapabilities(c, 1, Capabilities{RequestGate: true}); err == nil {
		t.Fatal("M4 capability hid missing M3 inspection capability")
	}
	p, err := CompileForCapabilities(c, 2, Capabilities{Inspection: true, RequestGate: true})
	if err != nil {
		t.Fatal(err)
	}
	if gate := SelectRequestGate(p, m4View(443)); !gate.Enabled {
		t.Fatal("M4 gate selection lost")
	}
	if inspection := SelectInspection(p, m4View(443)); inspection.Mode != domain.InspectionModeIPS {
		t.Fatalf("M3 inspection selection drifted: %+v", inspection)
	}
}
