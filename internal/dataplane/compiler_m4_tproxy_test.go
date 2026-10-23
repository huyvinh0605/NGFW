package dataplane

import (
	"os"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func m4RenderConfig() domain.Config {
	config := m4SelectorConfig()
	config.Interfaces = []domain.Interface{
		{ID: "wan0", ZoneID: "wan", SystemName: "ens33", Mode: domain.InterfaceL3},
		{ID: "lan0", ZoneID: "lan", SystemName: "ens37", Mode: domain.InterfaceL3},
		{ID: "mgmt0", ZoneID: "mgmt", SystemName: "ens39", Mode: domain.InterfaceManagement},
	}
	return config
}

func TestRenderM4TPROXYPreservesFirstMatchAndFailsClosedWithoutListener(t *testing.T) {
	config := m4RenderConfig()
	plan, err := CompileM4ProxySelection(config, 23)
	if err != nil {
		t.Fatal(err)
	}
	script, err := RenderM4TPROXYSelection(config, plan)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Index(script, `m4-first-match:plain-allow`)
	deny := strings.Index(script, `m4-first-match:deny-host`)
	gate := strings.Index(script, `m4:gate-web`)
	if first < 0 || deny < first || gate < deny {
		t.Fatalf("M4 rules lost first-match order: %s", script)
	}
	for _, expected := range []string{
		`fib daddr type local return`,
		`fib daddr oifname "ens33"`,
		`tcp dport 80 tproxy ip to :18080`,
		`tcp dport 443 tproxy ip to :18443`,
		`meta mark set meta mark | 0x40000000 accept`,
		`drop comment "m4-no-listener:gate-web"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("missing selector contract %q: %s", expected, script)
		}
	}
	if strings.Contains(script, "flush ruleset") || strings.Contains(script, "table inet ngfw {") {
		t.Fatal("M4 renderer touched a foreign or M1 table")
	}
	if !strings.HasPrefix(script, "delete table inet ngfw_proxy\ntable inet ngfw_proxy {") {
		t.Fatal("M4 ON must replace its owned table so an inert chain gains a hook")
	}
	if path := os.Getenv("NGFW_M4_SELECTOR_OUTPUT"); path != "" {
		if err := os.WriteFile(path, []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRenderM4TPROXYOffRemovesPreroutingHook(t *testing.T) {
	config := m4RenderConfig()
	config.Profiles[0].RequestGate.Enabled = false
	plan, err := CompileM4ProxySelection(config, 24)
	if err != nil {
		t.Fatal(err)
	}
	script, err := RenderM4TPROXYSelection(config, plan)
	if err != nil {
		t.Fatal(err)
	}
	if script != "delete table inet ngfw_proxy\n"+ProxySchemaScript() || strings.Contains(script, "hook ") {
		t.Fatalf("M4 OFF did not restore the inert table: %s", script)
	}
}

func TestRenderM4TPROXYRejectsStalePlanAndMapsCustomTLSPort(t *testing.T) {
	config := m4RenderConfig()
	plan, err := CompileM4ProxySelection(config, 23)
	if err != nil {
		t.Fatal(err)
	}
	config.Policies[2].SourceAddresses[0] = "192.168.20.0/24"
	if _, err := RenderM4TPROXYSelection(config, plan); err == nil {
		t.Fatal("stale selector plan was rendered")
	}
	config = m4RenderConfig()
	config.Policies[2].Services = []string{"tcp:8080"}
	plan, err = CompileM4ProxySelection(config, 23)
	if err != nil {
		t.Fatal(err)
	}
	if rendered, err := RenderM4TPROXYSelection(config, plan); err != nil || !strings.Contains(rendered, "tcp dport 8080 tproxy ip to :18443") {
		t.Fatalf("explicit TLS port not mapped: %s %v", rendered, err)
	}
}

func TestRenderM4TPROXYKeepsDNATDestinationZoneGuard(t *testing.T) {
	config := m4RenderConfig()
	config.Interfaces = append(config.Interfaces, domain.Interface{ID: "dmz0", ZoneID: "dmz", SystemName: "ens38", Mode: domain.InterfaceL3, IPv4Addresses: []string{"10.20.0.1/24"}})
	config.NATRules = []domain.NATRule{{ID: "public-web", Type: "DNAT", SourceZone: "wan", DestinationZone: "dmz", DestinationNetwork: "198.51.100.20/32", TranslatedAddress: "10.20.0.10", Protocol: "tcp", OriginalPort: 443, TranslatedPort: 443, Enabled: true}}
	plan, err := CompileM4ProxySelection(config, 24)
	if err != nil {
		t.Fatal(err)
	}
	script, err := RenderM4TPROXYSelection(config, plan)
	if err != nil {
		t.Fatal(err)
	}
	guard := `ct status dnat iifname "ens33" ip daddr 10.20.0.10 tcp dport 443 fib daddr oifname != "ens38" drop comment "m4-dnat-zone:public-web"`
	if !strings.Contains(script, guard) || strings.Index(script, guard) > strings.Index(script, "tproxy ip to") {
		t.Fatalf("post-DNAT guard does not precede interception: %s", script)
	}
	if path := os.Getenv("NGFW_M4_NAT_SELECTOR_OUTPUT"); path != "" {
		if err := os.WriteFile(path, []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestM4CustomPortRangesAndQUICKeepsPolicyScope(t *testing.T) {
	config := m4RenderConfig()
	config.Policies[2].Services = []string{"tcp:79-81", "udp:443"}
	config.Profiles[0].RequestGate.BlockQUIC = true
	plan, err := CompileM4ProxySelection(config, 25)
	if err != nil {
		t.Fatal(err)
	}
	script, err := RenderM4TPROXYSelection(config, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp dport 79 tproxy ip to :18443", "tcp dport 80 tproxy ip to :18080", "tcp dport 81 tproxy ip to :18443", "udp dport 443 drop comment \"m4-quic:gate-web\""} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Index(script, "m4-quic:") < strings.Index(script, "m4-first-match:deny-host") {
		t.Fatal("QUIC drop overtook earlier policy")
	}
	config.Policies[2].Services = []string{"tcp:18080"}
	plan, _ = CompileM4ProxySelection(config, 26)
	if _, err := RenderM4TPROXYSelection(config, plan); err == nil {
		t.Fatal("ambiguous direct listener port accepted")
	}
}
