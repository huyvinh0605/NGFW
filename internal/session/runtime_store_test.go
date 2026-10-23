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
	record := conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: 12, KernelStart: 12, Original: original}, OriginalTuple: original, ReplyTuple: &reply, KernelStart: time.Unix(12, 0).UTC(), Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true, Timestamp: true}}
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

func TestRuntimeStoreVerifiedExpiryRemovesIndexes(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2, ClosedTTL: time.Second})
	createdAt := time.Unix(100, 0).UTC()
	v, _, err := s.Apply(testRecord(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	candidates, count, _ := s.ExpiredCandidates(createdAt.Add(2*time.Minute), 10)
	if count != 1 || len(candidates) != 1 {
		t.Fatalf("expiry candidates=%d count=%d", len(candidates), count)
	}
	if _, ok := s.Get(v.SessionID); !ok {
		t.Fatal("expiry estimate closed a live session without kernel verification")
	}
	if _, closed := s.CloseVerifiedExpired(candidates[0], createdAt.Add(2*time.Minute)); !closed {
		t.Fatal("verified expiry failed to close candidate")
	}
	if _, ok := s.Get(v.SessionID); ok {
		t.Fatal("expired session remained active")
	}
	alias := flow.Key{Scope: flow.Scope{NetworkNamespace: "init", ConntrackZone: 2}, Tuple: *v.TranslatedTuple}
	if _, err := s.Resolve(alias); err != ErrSessionMissing {
		t.Fatalf("stale alias resolved: %v", err)
	}
}

func TestRuntimeStoreObservationDoesNotInventPacketActivityOrEraseMark(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	now := time.Unix(1000, 0).UTC()
	record := testRecord()
	record.Mark = 0x12345000
	record.Presence.Mark = true
	first, created, changed, err := s.ApplyObserved(record, now)
	if err != nil || !created || !changed {
		t.Fatalf("first observation: created=%v changed=%v err=%v", created, changed, err)
	}
	partial := record
	partial.Mark = 0
	partial.Presence.Mark = false
	again, created, changed, err := s.ApplyObserved(partial, now.Add(time.Second))
	if err != nil || created || changed {
		t.Fatalf("unchanged observation: created=%v changed=%v err=%v", created, changed, err)
	}
	if again.KernelMark != record.Mark || !again.LastSeen.Equal(first.LastSeen) || again.Revision != first.Revision {
		t.Fatalf("partial update changed mark/activity/revision: %+v", again)
	}
	if !again.LastObservedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("last observed was not refreshed: %v", again.LastObservedAt)
	}
	partial.Presence.Mark = true // Explicit zero is different from absent.
	zero, _, changed, err := s.ApplyObserved(partial, now.Add(2*time.Second))
	if err != nil || !changed || zero.KernelMark != 0 || zero.KernelEpoch != 0 {
		t.Fatalf("explicit zero mark not merged: %+v changed=%v err=%v", zero, changed, err)
	}
	partial.PacketsOriginal++
	active, _, changed, err := s.ApplyObserved(partial, now.Add(3*time.Second))
	if err != nil || !changed || !active.LastSeen.Equal(now.Add(3*time.Second)) {
		t.Fatalf("counter growth not counted as activity: %+v changed=%v err=%v", active, changed, err)
	}
}

func TestRuntimeStoreMergesCounterDirectionsIndependently(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	now := time.Unix(1500, 0).UTC()
	record := testRecord()
	record.Presence.Counters = false
	record.Presence.CountersOriginal = true
	record.Presence.Timestamp = true
	record.Presence.Mark = true
	created, _, err := s.Apply(record, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.BytesOriginal != record.BytesOriginal || created.BytesReply != 0 ||
		!hasMissing(created.Quality.MissingFields, "counters_reply") ||
		!hasMissing(created.Quality.MissingFields, "counters") {
		t.Fatalf("partial original counters: %+v", created)
	}
	reply := record
	reply.Presence.CountersOriginal = false
	reply.Presence.CountersReply = true
	reply.BytesOriginal = 0 // absent direction must not erase prior observation
	merged, _, changed, err := s.ApplyObserved(reply, now.Add(time.Second))
	if err != nil || !changed {
		t.Fatalf("reply observation: changed=%v err=%v", changed, err)
	}
	if merged.BytesOriginal != record.BytesOriginal || merged.BytesReply != record.BytesReply ||
		hasMissing(merged.Quality.MissingFields, "counters") || merged.Quality.TrackingStatus != domain.TrackingComplete {
		t.Fatalf("directional counters did not complete tracking: %+v", merged)
	}
}

func TestRuntimeStoreExpiryVerificationIsConditionalAndBacksOff(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	now := time.Unix(2000, 0).UTC()
	record := testRecord()
	value, _, err := s.Apply(record, now)
	if err != nil {
		t.Fatal(err)
	}
	due := now.Add(2 * time.Minute)
	candidates, _, _ := s.ExpiredCandidates(due, 10)
	if len(candidates) != 1 {
		t.Fatalf("expiry candidates=%d", len(candidates))
	}
	if !s.DeferExpired(candidates[0], due, "get unavailable") {
		t.Fatal("failed to defer candidate")
	}
	if retry, _, _ := s.ExpiredCandidates(due.Add(time.Second), 10); len(retry) != 0 {
		t.Fatal("unavailable Get was retried without backoff")
	}
	if _, ok := s.Get(value.SessionID); !ok {
		t.Fatal("unavailable Get closed active session")
	}
	record.Timeout = 3 * time.Minute
	if _, _, err := s.Apply(record, due.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, closed := s.CloseVerifiedExpired(candidates[0], due.Add(3*time.Second)); closed {
		t.Fatal("old verification closed a refreshed session")
	}
	if _, ok := s.Get(value.SessionID); !ok {
		t.Fatal("refreshed session was removed")
	}
}

func TestRuntimeStorePresentZeroTimeoutIsDueForVerification(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	now := time.Unix(2500, 0).UTC()
	record := testRecord()
	record.Timeout = 0
	record.Presence.Timeout = true
	value, _, err := s.Apply(record, now)
	if err != nil || value.ExpiresAt == nil || !value.ExpiresAt.Equal(now) {
		t.Fatalf("explicit zero timeout was treated as absent: %+v err=%v", value, err)
	}
	candidates, _, _ := s.ExpiredCandidates(now, 1)
	if len(candidates) != 1 {
		t.Fatal("zero-timeout flow was not selected for verification")
	}
}

func TestRuntimeStoreSameTupleNewIncarnationDoesNotMerge(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 4})
	now := time.Unix(3000, 0).UTC()
	old := testRecord()
	first, _, err := s.Apply(old, now)
	if err != nil {
		t.Fatal(err)
	}
	reused := old
	reused.Identity.ID++
	reused.Identity.KernelStart++
	reused.KernelStart = reused.KernelStart.Add(time.Second)
	second, created, err := s.Apply(reused, now.Add(time.Second))
	if err != nil || !created || first.SessionID == second.SessionID {
		t.Fatalf("new incarnation merged with old: first=%s second=%s created=%v err=%v", first.SessionID, second.SessionID, created, err)
	}
	removed := s.ReconcileMissing([]domain.ConntrackIdentity{reused.Identity}, now, now.Add(2*time.Second), "verified absent")
	if len(removed) != 1 || removed[0].SessionID != first.SessionID {
		t.Fatalf("incorrect resync removal: %+v", removed)
	}
	if _, ok := s.Get(second.SessionID); !ok {
		t.Fatal("new incarnation was closed by old cleanup")
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

func TestRuntimeStoreUnavailableDecisionAndInvalidationDoNotExposeStaleAllow(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 2})
	v, _, err := s.Apply(testRecord(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkEvaluationUnavailable(v.SessionID, 3, "local traffic is outside the forward path"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(v.SessionID)
	if got.CacheState != domain.CacheNotEvaluated || got.Decision != "" || got.DecisionReason == "" {
		t.Fatalf("unavailable evaluation=%+v", got)
	}
	if _, err := s.SetDecision(v.SessionID, 3, domain.DecisionAllow, "allow", "matched"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Invalidate(v.SessionID, 4, "policy changed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(v.SessionID)
	if got.Decision != "" || got.EffectiveDecision != "" || got.MatchedPolicyID != "" || got.CacheState != domain.CacheInvalidated {
		t.Fatalf("invalidation exposed stale verdict: %+v", got)
	}
}
