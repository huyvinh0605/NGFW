package engine

import (
	"context"
	"testing"

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
