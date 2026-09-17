package dataplane

import (
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func baseM1Config() domain.Config {
	value := config.Defaults()
	value.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}, {ID: "dmz"}}
	value.Interfaces = []domain.Interface{
		{ID: "wan0", SystemName: "eth0", ZoneID: "wan", Mode: domain.InterfaceL3, IPv4Addresses: []string{"192.0.2.2/24"}, MTU: 1500, AdminState: true},
		{ID: "lan0", SystemName: "eth1", ZoneID: "lan", Mode: domain.InterfaceL3, IPv4Addresses: []string{"192.168.10.1/24"}, MTU: 1500, AdminState: true},
		{ID: "dmz0", SystemName: "eth2", ZoneID: "dmz", Mode: domain.InterfaceL3, IPv4Addresses: []string{"10.20.0.1/24"}, MTU: 1500, AdminState: true},
	}
	return value
}

func TestCompilePolicyUsesORSemantics(t *testing.T) {
	value := baseM1Config()
	value.Policies = []domain.SecurityPolicy{{
		ID:                   "allow-web",
		Priority:             10,
		Action:               domain.DecisionAllow,
		Enabled:              true,
		SourceZones:          []string{"lan"},
		DestinationZones:     []string{"wan"},
		SourceAddresses:      []string{"192.168.10.0/25", "192.168.10.128/25"},
		DestinationAddresses: []string{"198.51.100.10", "203.0.113.0/24"},
		Services:             []string{"tcp:80", "udp:53"},
	}}
	ruleset, err := CompileRuleset(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ruleset, `comment "policy:allow-web"`) != 2 {
		t.Fatalf("expected one rule per service:\n%s", ruleset)
	}
	for _, expected := range []string{
		`ip saddr { 192.168.10.0/25, 192.168.10.128/25 }`,
		`ip daddr { 198.51.100.10, 203.0.113.0/24 }`,
		`tcp dport 80`,
		`udp dport 53`,
	} {
		if !strings.Contains(ruleset, expected) {
			t.Fatalf("missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Contains(ruleset, "tcp dport 80 udp dport 53") {
		t.Fatalf("services were ANDed in one rule:\n%s", ruleset)
	}
}

func TestCompileNATHonorsMatchersAndPriority(t *testing.T) {
	value := baseM1Config()
	value.NATRules = []domain.NATRule{
		{ID: "masq", Type: "MASQUERADE", SourceZone: "lan", DestinationZone: "wan", SourceNetwork: "192.168.10.0/24", DestinationNetwork: "0.0.0.0/0", Protocol: "udp", OriginalPort: 53, Enabled: true, Priority: 100},
		{ID: "publish", Type: "DNAT", SourceZone: "wan", DestinationZone: "dmz", SourceNetwork: "198.51.100.0/24", DestinationNetwork: "192.0.2.2/32", Protocol: "tcp", OriginalPort: 8443, TranslatedAddress: "10.20.0.10", TranslatedPort: 443, Enabled: true, Priority: 10},
		{ID: "fixed", Type: "SNAT", SourceZone: "lan", DestinationZone: "wan", SourceNetwork: "192.168.10.128/25", DestinationNetwork: "203.0.113.0/24", Protocol: "tcp", OriginalPort: 443, TranslatedAddress: "192.0.2.3", TranslatedPort: 1443, Enabled: true, Priority: 50},
	}
	ruleset, err := CompileRuleset(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`iifname "eth0" ip saddr 198.51.100.0/24 ip daddr 192.0.2.2/32 tcp dport 8443 dnat to 10.20.0.10:443`,
		`ct status dnat iifname "eth0" ip saddr 198.51.100.0/24 ip daddr 10.20.0.10 tcp dport 443 oifname != "eth2" drop`,
		`iifname "eth1" oifname "eth0" ip saddr 192.168.10.128/25 ip daddr 203.0.113.0/24 tcp dport 443 snat to 192.0.2.3:1443`,
		`iifname "eth1" oifname "eth0" ip saddr 192.168.10.0/24 ip daddr 0.0.0.0/0 udp dport 53 masquerade`,
	} {
		if !strings.Contains(ruleset, expected) {
			t.Fatalf("missing NAT expression %q:\n%s", expected, ruleset)
		}
	}
	if strings.Index(ruleset, "nat:fixed:priority=50") > strings.Index(ruleset, "nat:masq:priority=100") {
		t.Fatalf("postrouting NAT priority order is wrong:\n%s", ruleset)
	}
}

func TestCompileRejectsUnsafeOrUnsupportedM1Policy(t *testing.T) {
	value := baseM1Config()
	value.Policies = []domain.SecurityPolicy{{ID: "bad", Action: domain.DecisionAllow, Enabled: true, SourceAddresses: []string{"1.2.3.4; flush ruleset"}}}
	if _, err := CompileRuleset(value); err == nil {
		t.Fatal("unsafe address accepted")
	}
	value.Policies = []domain.SecurityPolicy{{ID: "m2", Action: domain.DecisionRateLimit, Enabled: true}}
	if _, err := CompileRuleset(value); err == nil {
		t.Fatal("M2 action compiled into M1 ruleset")
	}
}

func TestCompileHonorsDefaultPolicy(t *testing.T) {
	value := baseM1Config()
	value.DefaultDeny = false
	ruleset, err := CompileRuleset(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "chain forward { type filter hook forward priority 0; policy accept;") {
		t.Fatalf("default allow not rendered:\n%s", ruleset)
	}
}
