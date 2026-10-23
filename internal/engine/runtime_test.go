package engine

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

func runtimeRecord(id uint32) conntrack.Record {
	o := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: uint16(40000 + id), DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}
	r := o.Reverse()
	return conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: id, KernelStart: uint64(id), Original: o}, OriginalTuple: o, ReplyTuple: &r, KernelStart: time.Unix(int64(id), 0), SeenReply: true, Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true}}
}

func TestM2RuntimeResyncAndGenerationInvalidation(t *testing.T) {
	source := conntrack.NewFakeSource(100)
	p, err := connectivity.Compile(domain.Config{DefaultDeny: true, Policies: []domain.SecurityPolicy{{ID: "web", Priority: 1, SourceZones: nil, DestinationZones: nil, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Enabled: true}}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, p, 1, session.RuntimeLimits{MaxSessions: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	record := runtimeRecord(1)
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(runtime.Store.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	items := runtime.Store.List()
	if len(items) != 1 {
		t.Fatalf("sessions=%d", len(items))
	}
	decision, err := runtime.Evaluate(items[0].SessionID)
	if err != nil || decision.Action != domain.DecisionAllow {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if err := runtime.AddTemporaryBlock(domain.TemporaryBlock{ID: "b1", Indicator: record.OriginalTuple.SrcIP.String(), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	decision, err = runtime.Evaluate(items[0].SessionID)
	if err != nil || decision.Action != domain.DecisionDrop || !strings.Contains(decision.Reason, "overrides") {
		t.Fatalf("temporary block decision=%+v err=%v", decision, err)
	}
	runtime.RemoveTemporaryBlock(record.OriginalTuple.SrcIP.String())
	p2, err := connectivity.Compile(domain.Config{DefaultDeny: true}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(p2, 2, "policy generation changed"); err != nil {
		t.Fatal(err)
	}
	got, _ := runtime.Store.Get(items[0].SessionID)
	if got.CacheState != domain.CacheInvalidated || got.PolicyGeneration != 2 {
		t.Fatalf("cache not invalidated: %+v", got)
	}
	decision, err = runtime.Evaluate(items[0].SessionID)
	if err != nil || decision.Action != domain.DecisionDrop || decision.Reason != "default deny" {
		t.Fatalf("generation mismatch reused old decision: %+v err=%v", decision, err)
	}
	if err := runtime.Revoke(items[0].SessionID, "manual revoke"); err != nil {
		t.Fatal(err)
	}
	decision, err = runtime.Evaluate(items[0].SessionID)
	if err != nil || decision.Action != domain.DecisionDrop {
		t.Fatalf("revocation decision=%+v err=%v", decision, err)
	}
	runtimeSink{r: runtime}.ReportLoss(conntrack.Loss{Reason: "test lost event", Count: 1})
	deadline = time.Now().Add(time.Second)
	for runtime.Stats().Resyncs < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Stats().Resyncs < 2 {
		t.Fatal("lost event did not trigger bounded resync")
	}
	_ = runtime.Stop()
}

func TestM2RuntimeUpdateAndDestroyLifecycle(t *testing.T) {
	source := conntrack.NewFakeSource(10)
	p, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, p, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	record := runtimeRecord(20)
	record.Presence.Counters = true
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(runtime.Store.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	items := runtime.Store.List()
	if len(items) != 1 {
		t.Fatalf("new sessions=%d", len(items))
	}
	record.PacketsOriginal = 5
	record.BytesOriginal = 500
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventUpdate, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, ok := runtime.Store.Get(items[0].SessionID)
		if ok && current.PacketsOriginal == 5 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	current, _ := runtime.Store.Get(items[0].SessionID)
	if current.PacketsOriginal != 5 || current.BytesOriginal != 500 {
		t.Fatalf("update counters=%+v", current)
	}
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventDestroy, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for len(runtime.Store.List()) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(runtime.Store.List()) != 0 {
		t.Fatal("destroy left active session")
	}
	_ = runtime.Stop()
}

func TestM2RuntimeResyncCleansFlowMissingFromKernelDump(t *testing.T) {
	source := conntrack.NewFakeSource(16)
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 8})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, second := runtimeRecord(31), runtimeRecord(32)
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: first}); err != nil {
		t.Fatal(err)
	}
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: second}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(runtime.Store.List()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(runtime.Store.List()) != 2 {
		t.Fatalf("sessions before resync=%d", len(runtime.Store.List()))
	}
	source.Forget(second.Identity)
	runtimeSink{r: runtime}.ReportLoss(conntrack.Loss{Reason: "lost destroy", Count: 1})
	deadline = time.Now().Add(time.Second)
	for (runtime.Stats().Resyncs < 2 || len(runtime.Store.List()) != 1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Stats().Resyncs < 2 {
		t.Fatal("lost event did not trigger resync")
	}
	if len(runtime.Store.List()) != 1 {
		t.Fatalf("stale session was not cleaned: %d", len(runtime.Store.List()))
	}
	_ = runtime.Stop()
}

func TestM2RuntimeExpiryRequiresKernelAbsence(t *testing.T) {
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record := runtimeRecord(91)
	record.Presence.Timeout = true
	record.Timeout = time.Minute

	present := conntrack.NewFakeSource(4)
	present.SetSnapshot(record)
	runtime := NewRuntime(present, program, 1, session.RuntimeLimits{MaxSessions: 4})
	created, _, err := runtime.Store.Apply(record, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, _ := runtime.Store.ExpiredCandidates(now, 1)
	if len(candidates) != 1 {
		t.Fatal("missing due session")
	}
	runtime.verifyExpiredCandidate(context.Background(), candidates[0])
	current, ok := runtime.Store.Get(created.SessionID)
	if !ok || current.ExpiresAt == nil || !current.ExpiresAt.After(now) {
		t.Fatalf("kernel-present session was closed or not refreshed: %+v", current)
	}

	absent := conntrack.NewFakeSource(4)
	missingRuntime := NewRuntime(absent, program, 1, session.RuntimeLimits{MaxSessions: 4})
	created, _, err = missingRuntime.Store.Apply(record, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, _ = missingRuntime.Store.ExpiredCandidates(now, 1)
	missingRuntime.verifyExpiredCandidate(context.Background(), candidates[0])
	if _, ok := missingRuntime.Store.Get(created.SessionID); ok || missingRuntime.Stats().Closed != 1 {
		t.Fatal("confirmed kernel absence did not close the session")
	}
}

type unavailableGetSource struct{ conntrack.Source }

func (unavailableGetSource) Get(context.Context, conntrack.Identity) (conntrack.Record, error) {
	return conntrack.Record{}, context.DeadlineExceeded
}

func TestM2RuntimeExpiryGetErrorKeepsSession(t *testing.T) {
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record := runtimeRecord(92)
	record.Presence.Timeout = true
	record.Timeout = time.Second
	runtime := NewRuntime(unavailableGetSource{conntrack.NewFakeSource(4)}, program, 1, session.RuntimeLimits{MaxSessions: 4})
	value, _, err := runtime.Store.Apply(record, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, _ := runtime.Store.ExpiredCandidates(now, 1)
	runtime.verifyExpiredCandidate(context.Background(), candidates[0])
	current, ok := runtime.Store.Get(value.SessionID)
	if !ok || current.Quality.TrackingStatus != domain.TrackingStale || runtime.Stats().GetUnavailable != 1 {
		t.Fatalf("Get error became a false close: %+v stats=%+v", current, runtime.Stats())
	}
}

func TestM2RuntimeNoOpResyncPreservesActivityAndRevision(t *testing.T) {
	source := conntrack.NewFakeSource(4)
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	record := runtimeRecord(93)
	source.SetSnapshot(record)
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	first := runtime.Store.List()[0]
	runtime.resync(source, ctx)
	second, ok := runtime.Store.Get(first.SessionID)
	if !ok || second.Revision != first.Revision || !second.LastSeen.Equal(first.LastSeen) || runtime.updated.Load() != 0 {
		t.Fatalf("no-op dump changed session activity/revision: before=%+v after=%+v", first, second)
	}
}

func TestM2RuntimeNoOpResyncDoesNotReevaluateInvalidatedSession(t *testing.T) {
	source := conntrack.NewFakeSource(4)
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	record := runtimeRecord(94)
	source.SetSnapshot(record)
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	before := runtime.Store.List()[0]
	invalidated, err := runtime.Store.Invalidate(before.SessionID, 1, "test", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	runtime.resync(source, ctx)
	after, ok := runtime.Store.Get(before.SessionID)
	if !ok || after.Revision != invalidated.Revision || after.CacheState != domain.CacheInvalidated {
		t.Fatalf("no-op resync retried policy evaluation: invalidated=%+v after=%+v", invalidated, after)
	}
}

type lossDuringDumpSource struct {
	conntrack.Source
	onDump func()
}

func (s lossDuringDumpSource) Dump(ctx context.Context, limits conntrack.DumpLimits, visit func(conntrack.Record) error) (conntrack.DumpResult, error) {
	result, err := s.Source.Dump(ctx, limits, visit)
	s.onDump()
	return result, err
}

func TestM2RuntimeEventLossDuringDumpPreventsNegativeSweep(t *testing.T) {
	source := conntrack.NewFakeSource(4)
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	record := runtimeRecord(94)
	source.SetSnapshot(record)
	runtime.applyRecord(record, time.Now().UTC(), conntrack.EventNew, true)
	source.Forget(record.Identity)
	runtime.mu.Lock()
	runtime.resyncing = true
	runtime.mu.Unlock()
	runtime.resync(lossDuringDumpSource{Source: source, onDump: func() { runtime.lossVersion.Add(1) }}, ctx)
	if len(runtime.Store.List()) != 1 || runtime.Stats().DumpIncomplete == 0 {
		t.Fatal("a dump with event loss incorrectly closed a session")
	}
}

type recordingGuard struct{ released atomic.Int32 }

func (*recordingGuard) AddSourceBlock(context.Context, string, time.Time) error { return nil }
func (*recordingGuard) RemoveSourceBlock(context.Context, string) error         { return nil }
func (*recordingGuard) RevokeSession(context.Context, domain.RuntimeSession) error {
	return nil
}
func (g *recordingGuard) ReleaseSession(context.Context, domain.RuntimeSession) error {
	g.released.Add(1)
	return nil
}

func TestM2RuntimeOldClosePreservesReusedRevokedID(t *testing.T) {
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(conntrack.NewFakeSource(4), program, 1, session.RuntimeLimits{MaxSessions: 4})
	guard := &recordingGuard{}
	runtime.SetGuardEnforcer(guard)
	now := time.Now().UTC()
	old := runtimeRecord(95)
	first, _, err := runtime.Store.Apply(old, now)
	if err != nil {
		t.Fatal(err)
	}
	newer := runtimeRecord(95)
	newer.OriginalTuple.SrcPort++
	newer.Identity.Original = newer.OriginalTuple
	newer.Identity.KernelStart++
	second, _, err := runtime.Store.Apply(newer, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Store.MarkRevoked(first.SessionID, 1, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Store.MarkRevoked(second.SessionID, 1, "test"); err != nil {
		t.Fatal(err)
	}
	closed, ok := runtime.Store.Close(first.Identity, "old destroy", now.Add(2*time.Second))
	if !ok {
		t.Fatal("old session did not close")
	}
	runtime.releaseClosedSession(closed, "old destroy")
	if guard.released.Load() != 0 {
		t.Fatal("closing old incarnation removed guard owned by a newer revoked session")
	}
}

func TestM2RuntimeEvaluatesDNATPolicyOnPostTranslationTuple(t *testing.T) {
	source := conntrack.NewFakeSource(10)
	config := domain.Config{
		DefaultDeny: true,
		Interfaces: []domain.Interface{
			{ID: "wan-if", SystemName: "wan0", ZoneID: "wan", IPv4Addresses: []string{"192.0.2.1/24"}},
			{ID: "dmz-if", SystemName: "dmz0", ZoneID: "dmz", IPv4Addresses: []string{"10.20.0.1/24"}},
		},
		Routes:   []domain.Route{{ID: "default", DestinationCIDR: "0.0.0.0/0", InterfaceID: "wan-if", Enabled: true}},
		Policies: []domain.SecurityPolicy{{ID: "publish-web", Priority: 1, SourceZones: []string{"wan"}, DestinationZones: []string{"dmz"}, DestinationAddresses: []string{"10.20.0.10"}, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Enabled: true}},
	}
	program, err := connectivity.Compile(config, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	original := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.100"), SrcPort: 51000, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 8443, Protocol: 6}
	reply := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("10.20.0.10"), SrcPort: 443, DstIP: original.SrcIP, DstPort: original.SrcPort, Protocol: 6}
	record := conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: 55, KernelStart: 55, Original: original}, OriginalTuple: original, ReplyTuple: &reply, Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true}, KernelStart: time.Unix(55, 0).UTC()}
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(runtime.Store.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	items := runtime.Store.List()
	if len(items) != 1 {
		t.Fatalf("sessions=%d", len(items))
	}
	if items[0].SourceZone != "wan" || items[0].DestinationZone != "dmz" {
		t.Fatalf("zones were not inferred from DNAT view: %+v", items[0])
	}
	decision, err := runtime.Evaluate(items[0].SessionID)
	if err != nil || decision.Action != domain.DecisionAllow || decision.PolicyID != "publish-web" {
		t.Fatalf("DNAT decision=%+v err=%v", decision, err)
	}
	_ = runtime.Stop()
}

func TestM2RuntimeAutomaticallyEvaluatesObservedForwardSession(t *testing.T) {
	source := conntrack.NewFakeSource(10)
	program, err := connectivity.Compile(domain.Config{DefaultDeny: true, Policies: []domain.SecurityPolicy{{
		ID: "allow-web", Priority: 1, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Enabled: true,
	}}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: runtimeRecord(70)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := runtime.Store.List()
		if len(items) == 1 && items[0].CacheState == domain.CacheCached {
			if items[0].Decision != domain.DecisionAllow || items[0].MatchedPolicyID != "allow-web" || items[0].DecisionReason == "" {
				t.Fatalf("automatic decision=%+v", items[0])
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("observed session was not evaluated: %+v", runtime.Store.List())
}

func TestM2RuntimeMarksLoopbackDecisionUnavailable(t *testing.T) {
	source := conntrack.NewFakeSource(10)
	config := domain.Config{
		DefaultDeny: true,
		Interfaces:  []domain.Interface{{ID: "wan-if", ZoneID: "wan", IPv4Addresses: []string{"192.0.2.2/24"}}},
		Routes:      []domain.Route{{ID: "default", DestinationCIDR: "0.0.0.0/0", InterfaceID: "wan-if", Enabled: true}},
	}
	program, err := connectivity.Compile(config, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	original := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("127.0.0.1"), SrcPort: 41000, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 8080, Protocol: 6}
	reply := original.Reverse()
	record := conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Family: domain.FamilyIPv4, ID: 71, KernelStart: 71, Original: original}, OriginalTuple: original, ReplyTuple: &reply, Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true}}
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := runtime.Store.List()
		if len(items) == 1 && items[0].DecisionReason != "" {
			got := items[0]
			if got.SourceZone != connectivity.ZoneLocal || got.DestinationZone != connectivity.ZoneLocal || got.Decision != "" || got.CacheState != domain.CacheNotEvaluated || !strings.Contains(got.DecisionReason, "outside") {
				t.Fatalf("loopback session=%+v", got)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("loopback session not classified: %+v", runtime.Store.List())
}

func TestM2RuntimePeriodicResyncRefreshesMissingCounters(t *testing.T) {
	source := conntrack.NewFakeSource(10)
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	runtime.resyncInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	record := runtimeRecord(72)
	record.Presence.Counters = false
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: record}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(runtime.Store.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	record.Presence.Counters = true
	record.PacketsOriginal, record.BytesOriginal = 9, 900
	record.PacketsReply, record.BytesReply = 7, 700
	source.SetSnapshot(record)
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := runtime.Store.List()
		if len(items) == 1 && items[0].BytesOriginal == 900 && items[0].BytesReply == 700 {
			for _, missing := range items[0].Quality.MissingFields {
				if missing == "counters" {
					t.Fatalf("counter availability was not refreshed: %+v", items[0])
				}
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("periodic resync did not refresh counters: %+v", runtime.Store.List())
}
