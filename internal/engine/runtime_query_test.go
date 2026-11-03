package engine

import (
	"context"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/dataplane"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

type queryGetSource struct {
	conntrack.Source
	gets int
	get  func(context.Context, conntrack.Identity) (conntrack.Record, error)
}

func (s *queryGetSource) Get(ctx context.Context, id conntrack.Identity) (conntrack.Record, error) {
	s.gets++
	if s.get != nil {
		return s.get(ctx, id)
	}
	return s.Source.Get(ctx, id)
}

func TestM2NarrowSessionQueryRefreshesShortFlowCounters(t *testing.T) {
	base := conntrack.NewFakeSource(4)
	source := &queryGetSource{Source: base}
	program, err := connectivity.Compile(domain.Config{DefaultDeny: false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(source, program, 1, session.RuntimeLimits{MaxSessions: 4})
	record := runtimeRecord(91)
	record.Presence.Timestamp = true
	record.KernelStart = time.Unix(91, 0).UTC()
	created, _, err := runtime.Store.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if created.PacketsOriginal != 0 || created.PacketsReply != 0 {
		t.Fatalf("event unexpectedly contained counters: %+v", created)
	}
	record.Presence.CountersOriginal, record.Presence.CountersReply = true, true
	record.PacketsOriginal, record.BytesOriginal = 6, 398
	record.PacketsReply, record.BytesReply = 5, 1696
	base.SetSnapshot(record)
	service := NewRuntimeServiceAdapter(runtime, nil, nil)

	// The ordinary session list must also show counters for a small flow set.
	all, err := service.ListSessions(context.Background(), domain.SessionQuery{})
	if err != nil || len(all.Items) != 1 || source.gets != 1 || all.Items[0].PacketsOriginal != 6 || all.Items[0].PacketsReply != 5 {
		t.Fatalf("small unfiltered query did not refresh: page=%+v gets=%d err=%v", all, source.gets, err)
	}
	page, err := service.ListSessions(context.Background(), domain.SessionQuery{SourceIP: record.OriginalTuple.SrcIP.String(), DestinationIP: record.OriginalTuple.DstIP.String()})
	if err != nil || len(page.Items) != 1 || source.gets != 2 {
		t.Fatalf("narrow query failed: page=%+v gets=%d err=%v", page, source.gets, err)
	}
	value := page.Items[0]
	if value.PacketsOriginal != 6 || value.PacketsReply != 5 || value.BytesOriginal != 398 || value.BytesReply != 1696 {
		t.Fatalf("kernel counters were not merged: %+v", value)
	}
	for _, missing := range value.Quality.MissingFields {
		if missing == "counters" || missing == "counters_original" || missing == "counters_reply" {
			t.Fatalf("counter quality stayed missing after exact Get: %+v", value.Quality)
		}
	}
	record.PacketsOriginal, record.PacketsReply = 8, 7
	base.SetSnapshot(record)
	value, err = service.GetSession(context.Background(), created.SessionID)
	if err != nil || value.PacketsOriginal != 8 || value.PacketsReply != 7 {
		t.Fatalf("single-session read did not refresh: value=%+v err=%v", value, err)
	}
}

func TestM2LargeUnfilteredSessionListBoundsKernelQueries(t *testing.T) {
	base := conntrack.NewFakeSource(16)
	source := &queryGetSource{Source: base}
	runtime := NewRuntime(source, connectivity.Program{Generation: 1}, 1, session.RuntimeLimits{MaxSessions: 16})
	for id := uint32(100); id < 109; id++ {
		if _, _, err := runtime.Store.Apply(runtimeRecord(id), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	page, err := NewRuntimeServiceAdapter(runtime, nil, nil).ListSessions(context.Background(), domain.SessionQuery{})
	if err != nil || page.Total != 9 || source.gets != maxQueryCounterRefresh {
		t.Fatalf("large unfiltered query was not bounded: total=%d gets=%d err=%v", page.Total, source.gets, err)
	}
}

func TestM2QueryGetRejectsDifferentIncarnation(t *testing.T) {
	base := conntrack.NewFakeSource(4)
	source := &queryGetSource{Source: base}
	runtime := NewRuntime(source, connectivity.Program{Generation: 1}, 1, session.RuntimeLimits{MaxSessions: 4})
	record := runtimeRecord(92)
	record.Presence.Timestamp = true
	record.KernelStart = time.Unix(92, 0).UTC()
	created, _, err := runtime.Store.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	source.get = func(context.Context, conntrack.Identity) (conntrack.Record, error) {
		wrong := record
		wrong.Identity.ID++
		wrong.Presence.CountersOriginal, wrong.Presence.CountersReply = true, true
		wrong.PacketsOriginal, wrong.PacketsReply = 100, 100
		return wrong, nil
	}
	service := NewRuntimeServiceAdapter(runtime, nil, nil)
	value, err := service.GetSession(context.Background(), created.SessionID)
	if err != nil || value.PacketsOriginal != 0 || value.PacketsReply != 0 || runtime.Store.Stats().Active != 1 {
		t.Fatalf("mismatched Get changed session: value=%+v err=%v", value, err)
	}
}

func TestM2LateQueryGetCannotRegressNewerEventOrResurrectClosedFlow(t *testing.T) {
	base := conntrack.NewFakeSource(4)
	source := &queryGetSource{Source: base}
	runtime := NewRuntime(source, connectivity.Program{Generation: 1}, 1, session.RuntimeLimits{MaxSessions: 4})
	record := runtimeRecord(93)
	record.Presence.Timestamp = true
	record.KernelStart = time.Unix(93, 0).UTC()
	candidate, _, err := runtime.Store.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	old := record
	old.ObservedAt = time.Now().Add(-time.Second)
	old.TCPState = "ESTABLISHED"
	old.Presence.CountersOriginal, old.Presence.CountersReply = true, true
	old.PacketsOriginal, old.PacketsReply = 2, 2
	source.get = func(context.Context, conntrack.Identity) (conntrack.Record, error) {
		newer := record
		newer.TCPState = "TIME_WAIT"
		newer.Presence.CountersOriginal, newer.Presence.CountersReply = true, true
		newer.PacketsOriginal, newer.PacketsReply = 6, 5
		if _, _, _, applyErr := runtime.Store.ApplyObserved(newer, time.Now().UTC()); applyErr != nil {
			t.Fatal(applyErr)
		}
		return old, nil
	}
	runtime.RefreshSessionCounters(context.Background(), candidate)
	current, ok := runtime.Store.Get(candidate.SessionID)
	if !ok || current.State != domain.SessionClosing || current.PacketsOriginal != 6 || current.PacketsReply != 5 {
		t.Fatalf("late Get regressed newer event: %+v", current)
	}
	source.get = func(context.Context, conntrack.Identity) (conntrack.Record, error) {
		if _, closed := runtime.Store.Close(record.Identity, "test destroy", time.Now().UTC()); !closed {
			t.Fatal("flow was not closed")
		}
		return old, nil
	}
	runtime.RefreshSessionCounters(context.Background(), current)
	if _, ok := runtime.Store.Get(candidate.SessionID); ok || runtime.Store.Stats().Active != 0 {
		t.Fatal("late Get resurrected closed flow")
	}
}

func TestM2APIVerifiesOnlyCurrentScopedKernelCacheMark(t *testing.T) {
	program := connectivity.Program{Generation: 5, Rules: []connectivity.Rule{{
		ID: "allow-web", Enabled: true, Action: domain.DecisionAllow,
		SourceZones: map[string]struct{}{"lan": {}}, DestinationZones: map[string]struct{}{"wan": {}},
	}}}
	runtime := NewRuntime(nil, program, 5, session.RuntimeLimits{MaxSessions: 4})
	service := NewRuntimeServiceAdapter(runtime, nil, nil)
	options := dataplane.M2CompileOptions{CacheEnabled: true, Epoch: 12, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}}
	appliedGeneration := uint64(5)
	service.CacheOptions = func() (dataplane.M2CompileOptions, uint64) { return options, appliedGeneration }
	mark, err := dataplane.PackCacheMark(dataplane.CacheMark{Epoch: 12, SourceZoneSlot: 1, DestinationZoneSlot: 2})
	if err != nil {
		t.Fatal(err)
	}
	value := domain.RuntimeSession{
		SourceZone: "lan", DestinationZone: "wan", KernelMark: mark | 0x5a,
		MatchedPolicyID: "allow-web", PolicyGeneration: 5, CacheState: domain.CacheCached,
		Decision: domain.DecisionAllow, EffectiveDecision: domain.DecisionAllow,
	}
	if !service.withKernelCacheVerification(value).KernelCacheVerified {
		t.Fatal("current scoped ALLOW mark was not verified")
	}
	options.Epoch = 13
	if service.withKernelCacheVerification(value).KernelCacheVerified {
		t.Fatal("stale epoch was trusted")
	}
	options.Epoch = 12
	appliedGeneration = 6
	if service.withKernelCacheVerification(value).KernelCacheVerified {
		t.Fatal("dataplane/runtime generation mismatch was trusted")
	}
	appliedGeneration = 5
	program.Rules[0].SourceZones = nil
	runtime.mu.Lock()
	runtime.program = program
	runtime.mu.Unlock()
	if service.withKernelCacheVerification(value).KernelCacheVerified {
		t.Fatal("unscoped ALLOW was treated as markable")
	}
	value.Revoked = true
	if service.withKernelCacheVerification(value).KernelCacheVerified {
		t.Fatal("revoked flow was treated as cached ALLOW")
	}
}
