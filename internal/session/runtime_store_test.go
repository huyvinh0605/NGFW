package session

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
)

func testRecord() conntrack.Record {
	o := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}
	r := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("203.0.113.10"), SrcPort: 443, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 61000, Protocol: 6}
	return conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 2, Family: domain.FamilyIPv4, ID: 11, KernelStart: 10, Original: o}, OriginalTuple: o, ReplyTuple: &r, PacketsOriginal: 1, BytesOriginal: 100, PacketsReply: 1, BytesReply: 120, Timeout: time.Minute, KernelStart: time.Unix(10, 0).UTC(), SeenReply: true, Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, Counters: true, Timeout: true, ID: true}}
}

func TestRuntimeStoreNATAliasAndLifecycle(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 10})
	now := time.Unix(100, 0).UTC()
	v, created, err := s.Apply(testRecord(), now)
	if err != nil || !created {
		t.Fatalf("apply: %v created=%v", err, created)
	}
	if v.State != domain.SessionEstablished || !v.NAT.SNAT || v.NAT.TranslatedTuple == nil {
		t.Fatalf("bad NAT/state: %+v", v)
	}
	alias := flow.Key{Scope: flow.Scope{NetworkNamespace: "init", ConntrackZone: 2}, Tuple: *v.TranslatedTuple}
	resolved, err := s.Resolve(alias)
	if err != nil || resolved.SessionID != v.SessionID {
		t.Fatalf("alias resolve: %v %+v", err, resolved)
	}
	updated, created, err := s.Apply(testRecord(), now.Add(time.Second))
	if err != nil || created || updated.SessionID != v.SessionID {
		t.Fatalf("duplicate session: %v created=%v", err, created)
	}
	if _, closed := s.Close(v.Identity, "destroy", now.Add(2*time.Second)); !closed {
		t.Fatal("destroy did not close")
	}
	if _, ok := s.Get(v.SessionID); ok {
		t.Fatal("closed session remained active")
	}
}

func TestRuntimeStoreCombinedNATAlias(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 4})
	original := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 8443, Protocol: 6}
	reply := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("10.20.0.10"), SrcPort: 443, DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 61000, Protocol: 6}
	record := conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: 12, KernelStart: 12, Original: original}, OriginalTuple: original, ReplyTuple: &reply, KernelStart: time.Unix(12, 0).UTC()}
	v, _, err := s.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !v.NAT.SNAT || !v.NAT.DNAT {
		t.Fatalf("combined NAT flags=%+v", v.NAT)
	}
	policyView := original
	policyView.DstIP, policyView.DstPort = v.TranslatedTuple.DstIP, v.TranslatedTuple.DstPort
	resolved, err := s.Resolve(flow.Key{Scope: flow.Scope{NetworkNamespace: "init", ConntrackZone: 1}, Tuple: policyView})
	if err != nil || resolved.SessionID != v.SessionID {
		t.Fatalf("combined policy alias resolve err=%v session=%+v", err, resolved)
	}
}

func TestRuntimeStoreGenerationAndPagination(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	now := time.Now().UTC()
	v, _, err := s.Apply(testRecord(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDecision(v.SessionID, 7, domain.DecisionAllow, "allow-web", "policy allow-web matched"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(v.SessionID)
	if got.CacheState != domain.CacheCached || got.PolicyGeneration != 7 {
		t.Fatalf("decision not cached: %+v", got)
	}
	if _, err := s.Invalidate(v.SessionID, 8, "policy generation changed", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(v.SessionID)
	if got.CacheState != domain.CacheInvalidated || got.PolicyGeneration != 8 {
		t.Fatalf("cache not invalidated: %+v", got)
	}
	page := s.Query(SessionFilter{}, Page{Number: 1, Size: 1})
	if len(page.Items) != 1 || page.Total != 1 {
		t.Fatalf("page=%+v", page)
	}
}

func TestRuntimeStorePartialDestroyAndCapacity(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 1})
	first, _, err := s.Apply(testRecord(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// DESTROY events can omit the original tuple and kernel timestamp. The
	// scoped conntrack ID must still resolve the same session.
	closed, ok := s.Close(domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 2, Family: domain.FamilyIPv4, ID: 11}, "destroy", time.Now().UTC())
	if !ok || closed.SessionID != first.SessionID {
		t.Fatalf("partial destroy resolved=%v session=%+v", ok, closed)
	}
	second := testRecord()
	second.Identity.ID = 12
	second.Identity.Original = second.OriginalTuple
	second.OriginalTuple.SrcPort++
	if _, _, err := s.Apply(second, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	third := second
	third.Identity.ID = 13
	third.OriginalTuple.SrcPort++
	if _, _, err := s.Apply(third, time.Now().UTC()); err != ErrRuntimeCapacity {
		t.Fatalf("capacity error=%v", err)
	}
}

func TestRuntimeStoreTranslatedAndAnyFilters(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 4})
	v, _, err := s.Apply(testRecord(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	translated := v.TranslatedTuple
	if translated == nil {
		t.Fatal("test record did not produce translated tuple")
	}
	page := s.Query(SessionFilter{TupleView: "translated", SourceIP: translated.SrcIP.String()}, Page{Number: 1, Size: 10})
	if page.Total != 1 {
		t.Fatalf("translated filter total=%d", page.Total)
	}
	page = s.Query(SessionFilter{TupleView: "any", SourceIP: translated.SrcIP.String()}, Page{Number: 1, Size: 10})
	if page.Total != 1 {
		t.Fatalf("any filter total=%d", page.Total)
	}
}

func TestRuntimeStoreConntrackIDReuseDoesNotMergeDifferentTuple(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 4})
	first := testRecord()
	if _, _, err := s.Apply(first, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	reused := testRecord()
	reused.OriginalTuple.SrcPort++
	reused.Identity.Original = reused.OriginalTuple
	second, created, err := s.Apply(reused, time.Now().UTC())
	if err != nil || !created {
		t.Fatalf("tuple reuse err=%v created=%v", err, created)
	}
	if second.SessionID == sessionID(first.Identity) || len(s.List()) != 2 {
		t.Fatalf("tuple reuse merged: %+v sessions=%d", second, len(s.List()))
	}
}

func TestRuntimeStoreDestroyIdentityCollisionDoesNotCloseLiveSession(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 4})
	record := testRecord()
	v, _, err := s.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrong := record.Identity
	wrong.ID++
	if _, closed := s.Close(wrong, "wrong destroy", time.Now().UTC()); closed {
		t.Fatal("destroy with a colliding conntrack ID closed the live session")
	}
	if _, ok := s.Get(v.SessionID); !ok {
		t.Fatal("live session was removed")
	}
}

func TestRuntimeStoreCleanupRemovesExpiredIndexes(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2, ClosedTTL: time.Second})
	createdAt := time.Unix(100, 0).UTC()
	v, _, err := s.Apply(testRecord(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if removed := s.Cleanup(createdAt.Add(2*time.Minute), 10); removed != 1 {
		t.Fatalf("removed=%d", removed)
	}
	if _, ok := s.Get(v.SessionID); ok {
		t.Fatal("expired session remained active")
	}
	alias := flow.Key{Scope: flow.Scope{NetworkNamespace: "init", ConntrackZone: 2}, Tuple: *v.TranslatedTuple}
	if _, err := s.Resolve(alias); err != ErrSessionMissing {
		t.Fatalf("stale alias resolved: %v", err)
	}
}

func TestRuntimeStoreIgnoresDelayedEventAfterDestroy(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	record := testRecord()
	v, _, err := s.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Close(v.Identity, "destroy", time.Now().UTC()); !ok {
		t.Fatal("close failed")
	}
	if _, created, err := s.Apply(record, time.Now().UTC()); err != ErrStaleEvent || created {
		t.Fatalf("delayed event err=%v created=%v", err, created)
	}
}

func TestRuntimeStoreReconcileMissingRemovesStaleIndexes(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 4, ClosedTTL: time.Minute})
	first := testRecord()
	second := testRecord()
	second.Identity.ID = 22
	second.Identity.KernelStart = 22
	second.Identity.Original = second.OriginalTuple
	second.OriginalTuple.SrcPort++
	started := time.Unix(200, 0).UTC()
	firstValue, _, err := s.Apply(first, started)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, _, err := s.Apply(second, started)
	if err != nil {
		t.Fatal(err)
	}
	removed := s.ReconcileMissing([]domain.ConntrackIdentity{first.Identity}, started.Add(time.Second), started.Add(2*time.Second), "resync stale")
	if len(removed) != 1 || removed[0].SessionID != secondValue.SessionID {
		t.Fatalf("removed=%+v", removed)
	}
	if _, ok := s.Get(firstValue.SessionID); !ok {
		t.Fatal("session present in dump was removed")
	}
	if _, ok := s.Get(secondValue.SessionID); ok {
		t.Fatal("stale session remained active")
	}
	if _, err := s.Resolve(flow.Key{Scope: flow.Scope{NetworkNamespace: "init", ConntrackZone: 2}, Tuple: secondValue.OriginalTuple}); err != ErrSessionMissing {
		t.Fatalf("stale original alias resolved: %v", err)
	}
}

func TestRuntimeStorePartialUpdateKeepsKnownTupleAndNAT(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	record := testRecord()
	v, _, err := s.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	partial := conntrack.Record{
		Identity:        record.Identity,
		PacketsOriginal: 9,
		BytesOriginal:   900,
		Presence:        conntrack.Presence{ID: true, Counters: true},
	}
	updated, created, err := s.Apply(partial, time.Now().Add(time.Second))
	if err != nil || created || updated.SessionID != v.SessionID {
		t.Fatalf("partial update err=%v created=%v session=%+v", err, created, updated)
	}
	if updated.ReplyTuple == nil || updated.TranslatedTuple == nil || updated.PacketsOriginal != 9 {
		t.Fatalf("partial update erased known state: %+v", updated)
	}
}

func TestRuntimeStoreRejectsStaleDecisionRevision(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	v, _, err := s.Apply(testRecord(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Invalidate(v.SessionID, 2, "policy changed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDecisionIfCurrent(v.SessionID, v.Revision, 1, domain.DecisionAllow, "old", "stale"); err != ErrStaleDecision {
		t.Fatalf("stale decision error=%v", err)
	}
}
