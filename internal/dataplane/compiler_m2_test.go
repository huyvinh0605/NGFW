package dataplane

import (
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestM2CompilerGuardPrecedesCacheAndNoUnconditionalEstablishedAccept(t *testing.T) {
	config := baseM1Config()
	config.DefaultDeny = true
	config.Policies = []domain.SecurityPolicy{{ID: "allow", Priority: 1, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Enabled: true}}
	ruleset, err := CompileM2Ruleset(config, M2CompileOptions{Epoch: 4, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "priority -20") {
		t.Fatal("runtime guard missing")
	}
	if strings.Contains(ruleset, "ct state established,related accept") {
		t.Fatal("unconditional established accept remains")
	}
	if !strings.Contains(ruleset, "ct mark & 0xffffff00 ==") {
		t.Fatal("cache mark guard missing")
	}
	if !strings.Contains(ruleset, "ct mark set (ct mark & 0x000000ff)") {
		t.Fatal("allow policy does not record cache mark")
	}
	if !strings.Contains(ruleset, "set revoked_ctids { typeof ct id; }") {
		t.Fatal("revoked conntrack set does not use the ct id datatype")
	}
	if strings.Contains(ruleset, "set revoked_ctids { type integer; }") {
		t.Fatal("invalid generic integer conntrack set remains")
	}
	if !strings.Contains(ruleset, "ct state established,related iifname \"eth0\" oifname \"eth1\" tcp sport 443") {
		t.Fatal("constrained reverse established rule is missing")
	}
	if !strings.Contains(ruleset, `comment "policy:allow:reverse"`) {
		t.Fatal("reverse policy provenance comment is missing")
	}
	if strings.Index(ruleset, "priority -20") > strings.Index(ruleset, "priority 0") {
		t.Fatal("guard is after policy")
	}
}

func TestM2CompilerSafeNoCacheMode(t *testing.T) {
	ruleset, err := CompileM2Ruleset(baseM1Config(), M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ruleset, "ct mark & 0xffffff00 ==") {
		t.Fatal("no-cache mode generated cache accept")
	}
	if !strings.Contains(ruleset, "source_blocks") {
		t.Fatal("runtime source guard missing")
	}
}

func TestM2CompilerDefaultAllowUsesExplicitFallback(t *testing.T) {
	config := baseM1Config()
	config.DefaultDeny = false
	ruleset, err := CompileM2Ruleset(config, M2CompileOptions{Epoch: 2, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "chain forward { type filter hook forward priority 0; policy drop;") {
		t.Fatal("M2 default-allow chain is not fail-closed")
	}
	if !strings.Contains(ruleset, `comment "default:allow"`) {
		t.Fatal("explicit default allow rule is missing")
	}
	if strings.Contains(ruleset, "chain forward { type filter hook forward priority 0; policy accept;") {
		t.Fatal("base chain policy accept bypass remains")
	}
}
