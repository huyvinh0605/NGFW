package connectivity

import (
	"net/netip"
	"testing"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func TestProgramORSemanticsAndPriority(t *testing.T) {
	c := domain.Config{DefaultDeny: true, Policies: []domain.SecurityPolicy{
		{ID: "deny-first", Priority: 1, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Action: domain.DecisionDrop, Enabled: true},
		{ID: "allow-web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, SourceAddresses: []string{"192.168.10.0/24", "192.168.20.0/24"}, Services: []string{"tcp:80-90", "tcp:443"}, Action: domain.DecisionAllow, Enabled: true},
	}}
	p, err := Compile(c, 4)
	if err != nil {
		t.Fatal(err)
	}
	v := View{SourceIP: netip.MustParseAddr("192.168.20.8"), DestinationIP: netip.MustParseAddr("203.0.113.10"), DestinationPort: 443, Protocol: 6, SourceZone: "LAN", DestinationZone: "WAN"}
	decision := p.Evaluate(v)
	if decision.Action != domain.DecisionDrop || decision.PolicyID != "deny-first" {
		t.Fatalf("priority mismatch: %+v", decision)
	}
	c.Policies[0].Enabled = false
	p, err = Compile(c, 5)
	if err != nil {
		t.Fatal(err)
	}
	decision = p.Evaluate(v)
	if decision.Action != domain.DecisionAllow || decision.PolicyID != "allow-web" {
		t.Fatalf("OR/range mismatch: %+v", decision)
	}
	v.DestinationPort = 22
	decision = p.Evaluate(v)
	if decision.Action != domain.DecisionDrop || decision.Reason != "default deny" {
		t.Fatalf("default deny mismatch: %+v", decision)
	}
}

func TestDuplicatePriorityRejected(t *testing.T) {
	_, err := Compile(domain.Config{Policies: []domain.SecurityPolicy{{ID: "a", Priority: 1, Action: domain.DecisionAllow, Enabled: true}, {ID: "b", Priority: 1, Action: domain.DecisionDrop, Enabled: true}}}, 1)
	if err == nil {
		t.Fatal("expected duplicate priority error")
	}
}

func TestCompileM2RejectsInspectionAndNonSessionPredicates(t *testing.T) {
	cases := []domain.SecurityPolicy{
		{ID: "app", Priority: 1, Applications: []string{"http"}, Action: domain.DecisionAllow, Enabled: true},
		{ID: "profile", Priority: 1, SecurityProfileID: "web", Action: domain.DecisionAllow, Enabled: true},
		{ID: "risk", Priority: 1, MinimumRisk: testIntPtr(10), Action: domain.DecisionAllow, Enabled: true},
		{ID: "request", Priority: 1, Scope: "REQUEST", Action: domain.DecisionAllow, Enabled: true},
	}
	for _, policy := range cases {
		t.Run(policy.ID, func(t *testing.T) {
			if _, err := CompileM2(domain.Config{Policies: []domain.SecurityPolicy{policy}}, 1); err == nil {
				t.Fatal("unsupported M2 predicate was accepted")
			}
		})
	}
}

func TestM2ExampleCompilesAndLegacyInspectionExampleIsRejected(t *testing.T) {
	m2, err := configpkg.LoadFile("../../configs/examples/m2-lab.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileM2(m2, 1); err != nil {
		t.Fatalf("M2 example rejected: %v", err)
	}
	legacy, err := configpkg.LoadFile("../../configs/examples/lab.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileM2(legacy, 1); err == nil {
		t.Fatal("inspection-enabled lab example was accepted by M2 compiler")
	}
}

func testIntPtr(value int) *int { return &value }

func TestInferZonesUsesLongestConfiguredRoute(t *testing.T) {
	c := domain.Config{Interfaces: []domain.Interface{
		{ID: "lan-if", ZoneID: "lan", IPv4Addresses: []string{"192.168.10.1/24"}},
		{ID: "wan-if", ZoneID: "wan"},
	}, Routes: []domain.Route{{ID: "default", DestinationCIDR: "0.0.0.0/0", InterfaceID: "wan-if", Enabled: true}}}
	p, err := Compile(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	source, destination := p.InferZones(domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), DstIP: netip.MustParseAddr("203.0.113.10"), Protocol: 6})
	if source != "lan" || destination != "wan" {
		t.Fatalf("zones=%q,%q", source, destination)
	}
}

func TestInferZonesNeverMapsLoopbackOrGatewayAddressThroughDefaultRoute(t *testing.T) {
	c := domain.Config{Interfaces: []domain.Interface{
		{ID: "lan-if", ZoneID: "lan", IPv4Addresses: []string{"192.168.10.1/24"}},
		{ID: "wan-if", ZoneID: "wan", IPv4Addresses: []string{"192.0.2.2/24"}},
	}, Routes: []domain.Route{{ID: "default", DestinationCIDR: "0.0.0.0/0", InterfaceID: "wan-if", Enabled: true}}}
	p, err := Compile(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	loopback := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("127.0.0.1"), DstIP: netip.MustParseAddr("127.0.0.1"), Protocol: 6}
	if source, destination := p.InferZones(loopback); source != ZoneLocal || destination != ZoneLocal {
		t.Fatalf("loopback zones=%q,%q", source, destination)
	}
	if got := p.InferAddressZone(netip.MustParseAddr("192.0.2.2")); got != ZoneLocal {
		t.Fatalf("gateway address zone=%q", got)
	}
	if got := p.InferAddressZone(netip.MustParseAddr("203.0.113.10")); got != "wan" {
		t.Fatalf("routed internet address zone=%q", got)
	}
}
