package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/session"
)

type identityRefreshSource struct {
	conntrack.Source
	gets    atomic.Uint64
	gate    chan struct{}
	active  atomic.Int32
	maximum atomic.Int32
}

func (s *identityRefreshSource) Get(ctx context.Context, identity conntrack.Identity) (conntrack.Record, error) {
	s.gets.Add(1)
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for maximum := s.maximum.Load(); active > maximum; maximum = s.maximum.Load() {
		if s.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	if s.gate != nil {
		select {
		case <-ctx.Done():
			return conntrack.Record{}, ctx.Err()
		case <-s.gate:
		}
	}
	return s.Source.Get(ctx, identity)
}

func TestIdentityRefreshOverloadIsBoundedAndDoesNotBlockReducer(t *testing.T) {
	source := &identityRefreshSource{Source: conntrack.NewFakeSource(32), gate: make(chan struct{})}
	runtime := NewRuntime(source, m3RuntimeProgram(t), 1, session.RuntimeLimits{MaxSessions: 16})
	limits := domain.DefaultInspectionLimits()
	limits.ObservationQueueItems = 1
	coordinator := NewInspectionRuntimeWithScope(runtime, limits, nil, flow.Scope{NetworkNamespace: "init", ConntrackZone: 1})
	runtime.SetInspectionRuntime(coordinator)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := coordinator.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer coordinator.Stop()
	for index := uint32(120); index < 128; index++ {
		record := runtimeRecord(index)
		record.Identity.KernelStart = 0
		record.KernelStart = time.Time{}
		runtime.applyRecord(record, time.Now().UTC(), conntrack.EventNew, true)
		now := time.Now().UTC()
		observation := inspection.Observation{ID: record.OriginalTuple.String(), Tuple: &record.OriginalTuple, ObservedAt: &now, IngestedAt: now, Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "epoch", Mode: domain.InspectionModeIPS}, App: inspection.NormalizeApplication("HTTP")}
		started := time.Now()
		coordinator.HandleObservation(ctx, observation)
		if time.Since(started) > 100*time.Millisecond {
			t.Fatal("kernel identity IO blocked the reducer")
		}
		if index < 122 {
			deadline := time.Now().Add(200 * time.Millisecond)
			for source.active.Load() < int32(index-119) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		}
	}
	if source.maximum.Load() > 2 || source.maximum.Load() == 0 || len(coordinator.identityQueue) > 1 || coordinator.Stats()["identity_refresh_drops"] == 0 {
		t.Fatalf("unbounded/hidden overload: max workers=%d stats=%v", source.maximum.Load(), coordinator.Stats())
	}
	cancel()
	coordinator.Stop()
	if source.active.Load() != 0 {
		t.Fatal("identity worker leaked after cancellation")
	}
}

func TestEarlyAppIDRefreshesPartialIdentityWithoutAPIReads(t *testing.T) {
	fake := conntrack.NewFakeSource(32)
	source := &identityRefreshSource{Source: fake}
	runtime := NewRuntime(source, m3RuntimeProgram(t), 1, session.RuntimeLimits{MaxSessions: 32})
	coordinator := NewInspectionRuntimeWithScope(runtime, domain.DefaultInspectionLimits(), nil, flow.Scope{NetworkNamespace: "init", ConntrackZone: 1})
	runtime.SetInspectionRuntime(coordinator)
	var complete []conntrack.Record
	for index := uint32(100); index < 113; index++ {
		record := runtimeRecord(index)
		record.Presence.Timestamp = true
		complete = append(complete, record)
		partial := record
		partial.Identity.KernelStart = 0
		partial.KernelStart = time.Time{}
		partial.Presence.Timestamp = false
		runtime.applyRecord(partial, time.Now().UTC(), conntrack.EventNew, true)
	}
	for _, record := range complete {
		fake.SetSnapshot(record)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := coordinator.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer coordinator.Stop()
	target := complete[len(complete)-1]
	now := time.Now().UTC()
	observation := inspection.Observation{ID: "early-http", Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "epoch", Mode: domain.InspectionModeIPS}, Tuple: &target.OriginalTuple, ObservedAt: &now, IngestedAt: now, App: inspection.NormalizeApplication("HTTP")}
	if !coordinator.TrySubmit(observation) {
		t.Fatal("observation rejected")
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		for _, current := range runtime.Store.List() {
			if current.OriginalTuple == target.OriginalTuple && current.Inspection != nil && current.Inspection.Application.Name == "HTTP" {
				if current.Identity.KernelStart != target.Identity.KernelStart || current.Inspection.Application.Source != domain.ApplicationSourceSuricataAppProto || source.gets.Load() == 0 || len(runtime.Store.List()) != 13 {
					t.Fatalf("unsafe identity refresh: %#v, gets=%d", current, source.gets.Load())
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("App-ID depended on an API read or periodic resync: gets=%d stats=%v", source.gets.Load(), coordinator.Stats())
}
