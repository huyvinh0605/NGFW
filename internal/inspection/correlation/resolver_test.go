package correlation

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/session"
)

type fakeLookup struct {
	byKey     map[flow.Key][]domain.RuntimeSession
	truncated bool
}

func (f fakeLookup) ResolveCandidates(key flow.Key, _ time.Time, limit int) ([]domain.RuntimeSession, bool) {
	items := f.byKey[key]
	if len(items) > limit {
		return items[:limit], true
	}
	return items, f.truncated
}

func TestResolverUsesTupleAndBindsFlowID(t *testing.T) {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}
	scope := flow.Scope{NetworkNamespace: "init"}
	key := flow.Key{Scope: scope, Tuple: tuple}
	session := domain.RuntimeSession{SessionID: "s1", Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", ID: 1, KernelStart: 10, Original: tuple}, OriginalTuple: tuple, State: domain.SessionEstablished}
	resolver := NewResolver(fakeLookup{byKey: map[flow.Key][]domain.RuntimeSession{key: {session}}}, scope, 10)
	now := time.Now().UTC()
	obs := inspection.Observation{Source: inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1"}, HasFlowID: true, FlowID: 99, Tuple: &tuple, ObservedAt: &now}
	result := resolver.Resolve(obs)
	if result.State != domain.CorrelationCorrelated || result.Session == nil || result.Session.SessionID != "s1" {
		t.Fatalf("unexpected resolution: %#v", result)
	}
}

func TestResolverNewSensorEpochDropsOldFlowBinding(t *testing.T) {
	tupleOne := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}
	tupleTwo := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.11"), SrcPort: 50001, DstIP: netip.MustParseAddr("203.0.113.11"), DstPort: 443, Protocol: 6}
	scope := flow.Scope{NetworkNamespace: "init"}
	now := time.Now().UTC()
	lookup := fakeLookup{byKey: map[flow.Key][]domain.RuntimeSession{
		{Scope: scope, Tuple: tupleOne}: {{SessionID: "old", Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", ID: 1, KernelStart: 10, Original: tupleOne}, OriginalTuple: tupleOne, CreatedAt: now.Add(-time.Second)}},
		{Scope: scope, Tuple: tupleTwo}: {{SessionID: "new", Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", ID: 2, KernelStart: 11, Original: tupleTwo}, OriginalTuple: tupleTwo, CreatedAt: now.Add(-time.Second)}},
	}}
	resolver := NewResolver(lookup, scope, 10)
	old := inspection.Observation{Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "epoch-old"}, HasFlowID: true, FlowID: 7, Tuple: &tupleOne, ObservedAt: &now}
	if result := resolver.Resolve(old); result.Session == nil || result.Session.SessionID != "old" {
		t.Fatalf("old binding failed: %#v", result)
	}
	newObservation := inspection.Observation{Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "epoch-new"}, HasFlowID: true, FlowID: 7, Tuple: &tupleTwo, ObservedAt: &now}
	if result := resolver.Resolve(newObservation); result.Session == nil || result.Session.SessionID != "new" {
		t.Fatalf("new epoch reused old binding: %#v", result)
	}
	if len(resolver.bindings) != 1 {
		t.Fatalf("old epoch bindings retained: %#v", resolver.bindings)
	}
}

func TestResolverDoesNotGuessAmbiguous(t *testing.T) {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("198.51.100.1"), Protocol: 17}
	key := flow.Key{Tuple: tuple}
	sessions := []domain.RuntimeSession{{SessionID: "a", Identity: domain.ConntrackIdentity{ID: 1, KernelStart: 1, Original: tuple}, OriginalTuple: tuple}, {SessionID: "b", Identity: domain.ConntrackIdentity{ID: 2, KernelStart: 2, Original: tuple}, OriginalTuple: tuple}}
	now := time.Now()
	result := NewResolver(fakeLookup{byKey: map[flow.Key][]domain.RuntimeSession{key: sessions}}, flow.Scope{}, 10).Resolve(inspection.Observation{Tuple: &tuple, ObservedAt: &now})
	if result.State != domain.CorrelationAmbiguous {
		t.Fatalf("ambiguous tuple was guessed: %#v", result)
	}
}

func TestResolverDoesNotEnforceAgainstSessionMissingKernelStart(t *testing.T) {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 1234, DstIP: netip.MustParseAddr("198.51.100.1"), DstPort: 443, Protocol: 6}
	key := flow.Key{Tuple: tuple}
	partial := domain.RuntimeSession{SessionID: "partial", Identity: domain.ConntrackIdentity{ID: 7, Original: tuple}, OriginalTuple: tuple}
	now := time.Now().UTC()
	result := NewResolver(fakeLookup{byKey: map[flow.Key][]domain.RuntimeSession{key: {partial}}}, flow.Scope{}, 10).Resolve(inspection.Observation{Tuple: &tuple, ObservedAt: &now})
	if result.State != domain.CorrelationUncorrelated || result.Session != nil {
		t.Fatalf("partial identity was selected for correlation: %#v", result)
	}
}

func TestPendingBoundedAndExpires(t *testing.T) {
	p := NewPendingCorrelations(1, time.Second)
	now := time.Now()
	if !p.Add(inspection.Observation{ID: "a"}, now) || p.Add(inspection.Observation{ID: "b"}, now) {
		t.Fatal("pending capacity not enforced")
	}
	_, expired := p.RetryDue(now.Add(2*time.Second), 10)
	if len(expired) != 1 || p.Len() != 0 {
		t.Fatalf("pending did not expire: %#v", expired)
	}
}

func TestResolverMapsSNATDNATAndDoubleNATAliases(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	tests := []struct {
		name     string
		original domain.Tuple
		reply    domain.Tuple
		observed domain.Tuple
	}{
		{
			name:     "snat",
			original: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6},
			reply:    domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("203.0.113.10"), SrcPort: 443, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 61000, Protocol: 6},
			observed: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.2"), SrcPort: 61000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6},
		},
		{
			name:     "dnat",
			original: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("198.51.100.20"), SrcPort: 51000, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 8443, Protocol: 6},
			reply:    domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("10.20.0.10"), SrcPort: 443, DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 51000, Protocol: 6},
			observed: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("198.51.100.20"), SrcPort: 51000, DstIP: netip.MustParseAddr("10.20.0.10"), DstPort: 443, Protocol: 6},
		},
		{
			name:     "double-nat-policy-view",
			original: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 8443, Protocol: 6},
			reply:    domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("10.20.0.10"), SrcPort: 443, DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 61000, Protocol: 6},
			observed: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("10.20.0.10"), DstPort: 443, Protocol: 6},
		},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := session.NewRuntimeStore(session.RuntimeLimits{MaxSessions: 8})
			record := conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: uint32(index + 1), KernelStart: uint64(index + 1), Original: tc.original}, OriginalTuple: tc.original, ReplyTuple: &tc.reply, KernelStart: now, Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true, Timestamp: true}}
			created, _, err := store.Apply(record, now)
			if err != nil {
				t.Fatal(err)
			}
			resolver := NewResolver(store, flow.Scope{NetworkNamespace: "init", ConntrackZone: 1}, 32)
			observation := inspection.Observation{Source: inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1"}, HasFlowID: true, FlowID: uint64(index + 1), Tuple: &tc.observed, ObservedAt: &now}
			result := resolver.Resolve(observation)
			if result.State != domain.CorrelationCorrelated || result.Session == nil || result.Session.SessionID != created.SessionID {
				t.Fatalf("alias correlation failed: %#v", result)
			}
		})
	}
}
