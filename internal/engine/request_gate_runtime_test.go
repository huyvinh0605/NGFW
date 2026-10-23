package engine

import (
	"context"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func TestRequestGateRuntimeHealthDoesNotClaimProxyReady(t *testing.T) {
	ctx := context.Background()
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	gate := gateTestService(t, gateTestConfig())
	service := &RuntimeServiceAdapter{Runtime: gate.Runtime, Gate: gate, Config: manager}
	initial, err := service.RequestGateHealth(ctx)
	if err != nil || initial.Enabled || initial.Status != "disabled" || initial.ProxyReachable {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	manager.SyncRunning(gateTestConfig(), domain.ConfigVersion{Version: 1})
	active, err := service.RequestGateHealth(ctx)
	if err != nil || !active.Enabled || active.Status != "down" || active.ProxyReachable || active.HTTPListenerReady || active.HTTPSListenerReady || active.WorkersReady != 0 || active.WorkersTotal != 2 || active.Generation != 1 {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	capabilities, err := service.RequestGateCapabilities(ctx)
	if err != nil || !capabilities.Supported || capabilities.ProductionReady || len(capabilities.HTTPVersions) != 2 || capabilities.RuntimeIPCVersion == 0 {
		t.Fatalf("capabilities=%+v err=%v", capabilities, err)
	}
	page, err := service.ListRequestGateEvidence(ctx, 0, 5)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestRequestGateHealthRequiresFreshBoundProxyHeartbeat(t *testing.T) {
	ctx := context.Background()
	running := gateTestConfig()
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	manager.SyncRunning(running, domain.ConfigVersion{Version: 1})
	gate := gateTestService(t, running)
	gate.RunningConfig = func() (domain.Config, uint64) { return running, 1 }
	gate.InterceptionReady = func(generation uint64) bool { return generation == 1 }
	now := time.Now().UTC()
	gate.healthNow = func() time.Time { return now }
	service := &RuntimeServiceAdapter{Runtime: gate.Runtime, Gate: gate, Config: manager}
	descriptor, err := gate.RuntimeDescriptor(ctx)
	if err != nil || !descriptor.InterceptionReady || !descriptor.RequiresCA {
		t.Fatalf("authoritative descriptor: %+v %v", descriptor, err)
	}
	beat := domain.RequestGateHeartbeat{
		ProxyInstanceID: "abcdef0123456789abcdef0123456789", Sequence: 1,
		HTTPListenerReady: true, HTTPSListenerReady: true,
		WorkersReady: 2, CALoaded: true,
	}
	if _, err := gate.SyncProxy(ctx, beat); err != nil {
		t.Fatalf("stale proxy must receive a new descriptor: %v", err)
	}
	initial, err := service.RequestGateHealth(ctx)
	if err != nil || initial.ProxyReachable || initial.Status != "down" {
		t.Fatalf("unbound heartbeat became healthy: %+v %v", initial, err)
	}
	beat.EngineInstanceID, beat.Generation, beat.Sequence = descriptor.EngineInstanceID, descriptor.ConfigGeneration, 2
	if _, err := gate.SyncProxy(ctx, beat); err != nil {
		t.Fatal(err)
	}
	health, err := service.RequestGateHealth(ctx)
	if err != nil || health.Status != "healthy" || !health.ProxyReachable || !health.HTTPListenerReady || !health.HTTPSListenerReady || health.WorkersReady != 2 || !health.CALoaded {
		t.Fatalf("fresh verified heartbeat was not healthy: %+v %v", health, err)
	}
	if _, err := gate.SyncProxy(ctx, beat); err == nil {
		t.Fatal("replayed heartbeat was accepted")
	}
	now = now.Add(gateHeartbeatTTL + time.Millisecond)
	expired, err := service.RequestGateHealth(ctx)
	if err != nil || expired.Status != "down" || expired.ProxyReachable {
		t.Fatalf("expired heartbeat kept production ready: %+v %v", expired, err)
	}
}
