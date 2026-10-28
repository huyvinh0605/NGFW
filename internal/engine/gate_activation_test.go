package engine

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/dataplane"
	"github.com/kltngfw/ngfw/internal/domain"
)

func TestM4PreparationRequiresNonceArtifactsAndCannotAuthorizeTraffic(t *testing.T) {
	value := gateTestConfig()
	gate := gateTestService(t, value)
	gate.RunningConfig = func() (domain.Config, uint64) { return value, 1 }
	gate.InterceptionReady = func(uint64) bool { return true }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := gate.PrepareGateRuntime(ctx, value, 2); finished <- err }()
	var descriptor domain.RequestGateRuntime
	for {
		if prepared, ok := gate.preparedRuntime(); ok {
			descriptor = prepared
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	if descriptor.InterceptionReady || descriptor.PreparationID == "" {
		t.Fatal("preparation was presented as kernel readiness")
	}
	open := gateTestOpen(false)
	open.EngineInstanceID, open.ConfigGeneration = descriptor.EngineInstanceID, 1
	if _, err := gate.OpenConnection(ctx, open); err == nil {
		t.Fatal("preparation authorized old Running traffic")
	}
	beat := domain.RequestGateHeartbeat{ProxyInstanceID: strings.Repeat("a", 32), EngineInstanceID: descriptor.EngineInstanceID, Generation: 2, Sequence: 1, HTTPListenerReady: true, HTTPSListenerReady: true, CALoaded: true, WorkersReady: 2,
		Artifacts: domain.RequestGateArtifacts{RulesetID: descriptor.Config.RulesetID, RulesetHash: strings.Repeat("b", 64), WorkerConfigHash: strings.Repeat("c", 64), CAFingerprint: strings.Repeat("d", 64)}}
	if _, err := gate.SyncProxy(ctx, beat); err != nil {
		t.Fatal(err)
	}
	if gate.heartbeat.Sequence != 0 {
		t.Fatal("unbound preflight heartbeat accepted")
	}
	beat.PreparationID = descriptor.PreparationID
	if _, err := gate.SyncProxy(ctx, beat); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfirmGatePreparation(2); err != nil {
		t.Fatal(err)
	}
	beat.Sequence++
	beat.WorkersReady = 0
	beat.FailureCode = "GATE_SENSOR_UNAVAILABLE"
	if _, err := gate.SyncProxy(ctx, beat); err != nil {
		t.Fatal(err)
	}
	if err := gate.ConfirmGatePreparation(2); err == nil {
		t.Fatal("dead workers finalized activation")
	}
	gate.CompleteGatePreparation()
	if _, ok := gate.preparedRuntime(); ok {
		t.Fatal("preparation not cleared")
	}
}

func TestM4RuntimeCompilerRetainsGateOnCommit(t *testing.T) {
	program, err := compileRuntimeProgram(gateTestConfig(), 5)
	if err != nil {
		t.Fatal(err)
	}
	plan, ok := program.CompiledRequestGateForPolicy("web")
	if !ok || !plan.Enabled || plan.Generation != 5 {
		t.Fatal("management commit silently lost M4 gate plan")
	}
}

type gateActivationNetwork struct{}

func (gateActivationNetwork) Verify(context.Context, domain.Config) error { return nil }

func (gateActivationNetwork) Reconcile(context.Context, domain.Config, domain.Config) error {
	return nil
}

type gateActivationForwarding struct{}

func (gateActivationForwarding) Ensure(context.Context) error { return nil }

type gateActivationNft struct{ fail bool }

func (*gateActivationNft) ApplyRuleset(context.Context, string) error { return nil }
func (n *gateActivationNft) ApplyBundle(context.Context, dataplane.RulesetBundle) error {
	if n.fail {
		n.fail = false
		return errors.New("injected nft failure")
	}
	return nil
}
func (*gateActivationNft) VerifyBundle(context.Context, dataplane.RulesetBundle) error { return nil }
func (*gateActivationNft) ClearInspectionRuntimeState(context.Context) error           { return nil }

type gateActivationRoute struct{ active bool }

func (*gateActivationRoute) Preflight(context.Context) error { return nil }
func (r *gateActivationRoute) Ensure(context.Context) error  { r.active = true; return nil }
func (r *gateActivationRoute) Remove(context.Context) error  { r.active = false; return nil }
func (r *gateActivationRoute) Verify(context.Context) error {
	if !r.active {
		return errors.New("route absent")
	}
	return nil
}

func TestM4ManagementCommitRollbackAndCompensationKeepOneGeneration(t *testing.T) {
	value := gateTestConfig()
	value.Zones = []domain.Zone{{ID:"lan"},{ID:"wan"},{ID:"dmz"}}
	for i := range value.Interfaces {
		value.Interfaces[i].SystemName = value.Interfaces[i].ID
		value.Interfaces[i].Mode = domain.InterfaceL3
		value.Interfaces[i].MTU = 1500
		value.Interfaces[i].AdminState = true
	}
	value.RequestGate.Enabled = false
	manager, err := config.NewManager(t.TempDir(), value)
	if err != nil {
		t.Fatal(err)
	}
	manager.SyncRunning(value, domain.ConfigVersion{Version:1})
	gate := gateTestService(t, value)
	gate.RunningConfig = func() (domain.Config, uint64) { return manager.Running(), manager.Version().Version }
	nft := &gateActivationNft{}
	controller, err := dataplane.NewController(gateActivationNetwork{}, nft, gateActivationForwarding{}, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	controller.ProxyRouting = &gateActivationRoute{}
	controller.PrepareProxy = gate.PrepareGateRuntime
	gate.InterceptionReady = controller.M4InterceptionReady
	gate.ActivationArtifacts = controller.M4Artifacts
	service := NewRuntimeServiceAdapter(gate.Runtime, manager, nil)
	service.ApplyGeneration = func(ctx context.Context, c domain.Config, g uint64) error {
		err := controller.ApplyRuntimePrepared(ctx, c, dataplane.M2CompileOptions{}, g)
		if err != nil {
			gate.CompleteGatePreparation()
		}
		return err
	}
	service.FinalizeActivation = func(ctx context.Context, c domain.Config, g uint64) error {
		if err := gate.ConfirmGatePreparation(g); err != nil {
			return err
		}
		if err := controller.FinalizeActivation(ctx, c, g); err != nil {
			return err
		}
		gate.CompleteGatePreparation()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		var sequence uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			d, err := gate.RuntimeDescriptor(ctx)
			if err != nil {
				continue
			}
			sequence++
			b := domain.RequestGateHeartbeat{ProxyInstanceID: strings.Repeat("f", 32), EngineInstanceID: d.EngineInstanceID, Generation: d.ConfigGeneration, PreparationID: d.PreparationID, Sequence: sequence}
			if d.Config.Enabled && (d.InterceptionReady || d.PreparationID != "") {
				b.HTTPListenerReady = true
				b.HTTPSListenerReady = true
				b.WorkersReady = d.Config.WorkerCount
				b.CALoaded = d.RequiresCA
				b.Artifacts = domain.RequestGateArtifacts{RulesetID: d.Config.RulesetID, RulesetHash: strings.Repeat("b", 64), WorkerConfigHash: strings.Repeat("c", 64), CAFingerprint: strings.Repeat("d", 64)}
			}
			_, _ = gate.SyncProxy(ctx, b)
		}
	}()
	if err := service.ApplyGeneration(ctx, value, 1); err != nil {
		t.Fatal(err)
	}
	value.RequestGate.Enabled = true
	version, err := service.CommitConfig(ctx, value, 1, "test", "M4 enable", "")
	if err != nil || version.Version != 2 {
		t.Fatalf("commit: %+v %v", version, err)
	}
	if !controller.M4InterceptionReady(2) {
		t.Fatal("M4 did not become ready after commit")
	}
	open := gateTestOpen(false)
	open.EngineInstanceID, _ = gate.engineInstance()
	open.ConfigGeneration = 2
	decision, err := gate.OpenConnection(ctx, open)
	if err != nil || decision.Action != domain.TLSGateInspectHTTP {
		t.Fatalf("committed gate not authoritative: %+v %v", decision, err)
	}
	value.Policies[0].Services = []string{"tcp:80"}
	version, err = service.CommitConfig(ctx, value, 2, "test", "change", "")
	if err != nil || version.Version != 3 {
		t.Fatalf("update: %+v %v", version, err)
	}
	version, err = service.RollbackConfig(ctx, "test", "restore", "")
	if err != nil || version.Version != 4 {
		t.Fatalf("rollback: %+v %v", version, err)
	}
	if !controller.M4InterceptionReady(4) || len(manager.Running().Policies[0].Services) != 2 || gate.Runtime.CurrentGeneration() != 4 {
		t.Fatal("rollback generations diverged")
	}
	if _, err := gate.OpenConnection(ctx, open); err == nil {
		t.Fatal("old generation authorized after rollback")
	}
	nft.fail = true
	if _, err = service.CommitConfig(ctx, value, 4, "test", "failure", ""); err == nil {
		t.Fatal("injected failure not reported")
	}
	if manager.Version().Version != 4 || gate.Runtime.CurrentGeneration() != 4 || !controller.M4InterceptionReady(4) {
		t.Fatal("failed commit did not restore published generation")
	}
}
