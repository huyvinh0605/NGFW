package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

type runtimeSyncFunc func(context.Context, domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error)

func (f runtimeSyncFunc) Sync(ctx context.Context, beat domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error) {
	return f(ctx, beat)
}

type testManagedRuntime struct {
	closed  bool
	onClose func()
}

func (*testManagedRuntime) Snapshot() domain.RequestGateHeartbeat {
	return domain.RequestGateHeartbeat{HTTPListenerReady: true, HTTPSListenerReady: true, WorkersReady: 2}
}

func (r *testManagedRuntime) Close() {
	if !r.closed {
		r.closed = true
		if r.onClose != nil {
			r.onClose()
		}
	}
}

func testRuntimeDescriptor(generation uint64) domain.RequestGateRuntime {
	config := domain.DefaultRequestGateConfig()
	config.Enabled = true
	return domain.RequestGateRuntime{
		EngineInstanceID: "0123456789abcdef0123456789abcdef", ConfigGeneration: generation,
		Config: config, InterceptionReady: true,
	}
}

func TestRuntimeSupervisorReplacesAndRetiresBeforeStarting(t *testing.T) {
	current := testRuntimeDescriptor(1)
	var beats []domain.RequestGateHeartbeat
	var order []string
	var runtimes []*testManagedRuntime
	var unavailable bool
	supervisor := &RuntimeSupervisor{
		Synchronizer: runtimeSyncFunc(func(_ context.Context, beat domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error) {
			beats = append(beats, beat)
			if unavailable {
				return domain.RequestGateRuntime{}, errors.New("IPC unavailable")
			}
			return current, nil
		}),
		Factory: func(_ context.Context, descriptor domain.RequestGateRuntime) (ManagedRuntime, error) {
			order = append(order, "start")
			runtime := &testManagedRuntime{onClose: func() { order = append(order, "close") }}
			runtimes = append(runtimes, runtime)
			return runtime, nil
		},
	}
	ctx := context.Background()
	if err := supervisor.Reconcile(ctx); err != nil || len(runtimes) != 1 {
		t.Fatalf("initial synchronization: runtimes=%d err=%v", len(runtimes), err)
	}
	if !domain.ValidGateInstanceID(beats[0].ProxyInstanceID) || beats[0].Sequence != 1 || beats[0].HTTPListenerReady {
		t.Fatalf("initial heartbeat claimed a listener: %+v", beats[0])
	}
	if err := supervisor.Reconcile(ctx); err != nil || len(runtimes) != 1 || !beats[1].HTTPListenerReady || beats[1].Generation != 1 || beats[1].EngineInstanceID != current.EngineInstanceID {
		t.Fatalf("steady-state heartbeat/restart: %+v err=%v", beats[1], err)
	}
	current.ConfigGeneration = 2
	if err := supervisor.Reconcile(ctx); err != nil || len(runtimes) != 2 || !runtimes[0].closed || order[1] != "close" || order[2] != "start" {
		t.Fatalf("generation switch did not retire before replacement: order=%v err=%v", order, err)
	}
	unavailable = true
	if err := supervisor.Reconcile(ctx); err == nil || !runtimes[1].closed || supervisor.active != nil {
		t.Fatalf("IPC outage left a running listener: err=%v", err)
	}
	unavailable = false
	if err := supervisor.Reconcile(ctx); err != nil || len(runtimes) != 3 {
		t.Fatalf("recovery did not restart from engine descriptor: err=%v", err)
	}
	current.ConfigGeneration = 1
	if err := supervisor.Reconcile(ctx); err == nil || !runtimes[2].closed || supervisor.active != nil {
		t.Fatalf("stale generation kept runtime active: err=%v", err)
	}
}

func TestRuntimeSupervisorWaitsForVerifiedInterception(t *testing.T) {
	current := testRuntimeDescriptor(1)
	current.InterceptionReady = false
	starts := 0
	supervisor := &RuntimeSupervisor{
		Synchronizer: runtimeSyncFunc(func(context.Context, domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error) {
			return current, nil
		}),
		Factory: func(context.Context, domain.RequestGateRuntime) (ManagedRuntime, error) {
			starts++
			return &testManagedRuntime{}, nil
		},
	}
	if err := supervisor.Reconcile(context.Background()); err != nil || starts != 0 || supervisor.active != nil {
		t.Fatalf("unverified interception opened a listener: starts=%d err=%v", starts, err)
	}
	current.InterceptionReady = true
	if err := supervisor.Reconcile(context.Background()); err != nil || starts != 1 {
		t.Fatalf("verified interception did not start: starts=%d err=%v", starts, err)
	}
	current.InterceptionReady = false
	if err := supervisor.Reconcile(context.Background()); err != nil || supervisor.active != nil {
		t.Fatalf("withdrawn interception did not close runtime: err=%v", err)
	}
}

func TestRuntimeSupervisorPreparesPromotesAndAbortsWithoutStaleReuse(t *testing.T) {
	current := testRuntimeDescriptor(2)
	current.InterceptionReady = false
	current.PreparationID = "abcdef0123456789abcdef0123456789"
	var runtimes []*testManagedRuntime
	supervisor := &RuntimeSupervisor{
		Synchronizer: runtimeSyncFunc(func(context.Context, domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error) {
			return current, nil
		}),
		Factory: func(context.Context, domain.RequestGateRuntime) (ManagedRuntime, error) {
			r := &testManagedRuntime{}
			runtimes = append(runtimes, r)
			return r, nil
		},
	}
	defer supervisor.Close()
	if err := supervisor.Reconcile(context.Background()); err != nil || len(runtimes) != 1 {
		t.Fatalf("prepare failed: %v", err)
	}
	current.PreparationID = ""
	current.InterceptionReady = true
	if err := supervisor.Reconcile(context.Background()); err != nil || len(runtimes) != 1 || runtimes[0].closed {
		t.Fatalf("promotion discarded prepared resources: %v", err)
	}
	current.ConfigGeneration = 3
	current.InterceptionReady = false
	current.PreparationID = "1234567890abcdef1234567890abcdef"
	if err := supervisor.Reconcile(context.Background()); err != nil || len(runtimes) != 2 || !runtimes[0].closed {
		t.Fatalf("new preparation reused old resources: %v", err)
	}
	current.ConfigGeneration = 2
	current.InterceptionReady = true
	current.PreparationID = ""
	if err := supervisor.Reconcile(context.Background()); err != nil || len(runtimes) != 3 || !runtimes[1].closed {
		t.Fatalf("aborted preparation failed to return to Running: %v", err)
	}
}
