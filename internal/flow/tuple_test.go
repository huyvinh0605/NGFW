package flow

import (
	"net/netip"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestPairAndAliases(t *testing.T) {
	o := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}
	r := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("203.0.113.10"), SrcPort: 443, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 61000, Protocol: 6}
	s := Scope{NetworkNamespace: "init", ConntrackZone: 2}
	aliases := Aliases(s, o, &r, nil)
	if len(aliases) != 4 {
		t.Fatalf("aliases=%d", len(aliases))
	}
	if Pair(aliases[0], aliases[1]) != Pair(aliases[1], aliases[0]) {
		t.Fatal("pair is not deterministic")
	}
	if aliases[0].Reverse().Tuple != aliases[1].Tuple {
		t.Fatal("reverse mismatch")
	}
}

func TestParseLegacyRejectsMixedFamily(t *testing.T) {
	_, err := ParseLegacy(domain.FlowKey{SrcIP: "192.0.2.1", DstIP: "2001:db8::1", Protocol: "tcp"})
	if err == nil {
		t.Fatal("expected family error")
	}
}
