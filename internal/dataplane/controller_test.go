package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestControllerRestoresNetworkAndNftablesAfterNftFailure(t *testing.T) {
	network := &fakeNetworkReconciler{}
	rules := &fakeRulesetApplier{}
	forwarding := &fakeForwarding{}
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	controller, err := NewController(network, rules, forwarding, statePath)
	if err != nil {
		t.Fatal(err)
	}
	old := baseM1Config()
	old.Interfaces[1].IPv4Addresses = []string{"192.168.10.1/24"}
	if err := controller.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	desired := baseM1Config()
	desired.Interfaces[1].IPv4Addresses = []string{"192.168.20.1/24"}
	rules.failNext = true
	if err := controller.Apply(context.Background(), desired); err == nil {
		t.Fatal("expected injected nftables failure")
	}
	if len(network.calls) != 4 {
		t.Fatalf("network reconcile calls=%d, want initial/apply/two restore passes", len(network.calls))
	}
	restore := network.calls[2]
	if restore.previous.Interfaces[1].IPv4Addresses[0] != "192.168.20.1/24" || restore.desired.Interfaces[1].IPv4Addresses[0] != "192.168.10.1/24" {
		t.Fatalf("unexpected network restore transition: %#v", restore)
	}
	if cleanup := network.calls[3]; cleanup.desired.Interfaces[1].IPv4Addresses[0] != "192.168.10.1/24" {
		t.Fatalf("source cleanup did not target old config: %#v", cleanup)
	}
	if len(rules.rulesets) != 3 {
		t.Fatalf("nft calls=%d, want initial/failed new/restored old", len(rules.rulesets))
	}
	if controller.current.Interfaces[1].IPv4Addresses[0] != "192.168.10.1/24" {
		t.Fatal("controller published failed desired state")
	}
}

func TestControllerLoadsSnapshotAndReconcilesOnStartup(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	first, err := NewController(&fakeNetworkReconciler{}, &fakeRulesetApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	running := baseM1Config()
	if err := first.Apply(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	network := &fakeNetworkReconciler{}
	second, err := NewController(network, &fakeRulesetApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !second.hasCurrent {
		t.Fatal("applied snapshot was not loaded")
	}
	if err := second.Apply(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	if len(network.calls) != 1 || len(network.calls[0].previous.Interfaces) != len(running.Interfaces) {
		t.Fatalf("startup did not reconcile from persisted snapshot: %#v", network.calls)
	}
}

func TestControllerUsesInterruptedTargetAsRecoverySource(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "dataplane-applied.json")
	previous := baseM1Config()
	attempted := baseM1Config()
	attempted.Interfaces[1].IPv4Addresses = []string{"192.168.99.1/24"}
	if err := saveAppliedState(statePath, previous); err != nil {
		t.Fatal(err)
	}
	if err := saveActivationState(statePath+".activation", activationState{Previous: previous, PreviousKnown: true, Desired: attempted}); err != nil {
		t.Fatal(err)
	}
	network := &fakeNetworkReconciler{}
	controller, err := NewController(network, &fakeRulesetApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !controller.RecoveryPending() {
		t.Fatal("interrupted activation was not detected")
	}
	if err := controller.Apply(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	if got := network.calls[0].previous.Interfaces[1].IPv4Addresses[0]; got != "192.168.99.1/24" {
		t.Fatalf("recovery source=%s, want interrupted target", got)
	}
}

type reconcileCall struct {
	previous domain.Config
	desired  domain.Config
}

type fakeNetworkReconciler struct{ calls []reconcileCall }

func (f *fakeNetworkReconciler) Reconcile(_ context.Context, previous, desired domain.Config) error {
	f.calls = append(f.calls, reconcileCall{previous: previous, desired: desired})
	return nil
}

type fakeRulesetApplier struct {
	rulesets []string
	failNext bool
}

func (f *fakeRulesetApplier) ApplyRuleset(_ context.Context, ruleset string) error {
	f.rulesets = append(f.rulesets, ruleset)
	if f.failNext {
		f.failNext = false
		return errors.New("injected nft failure")
	}
	return nil
}

type fakeForwarding struct{ calls int }

func (f *fakeForwarding) Ensure(context.Context) error {
	f.calls++
	return nil
}

type fakeBundleApplier struct {
	fakeRulesetApplier
	bundles []RulesetBundle
	clears  int
	fail    bool
}

func (f *fakeBundleApplier) ApplyBundle(_ context.Context, bundle RulesetBundle) error {
	f.bundles = append(f.bundles, bundle)
	if f.fail {
		f.fail = false
		return errors.New("injected bundle failure")
	}
	return nil
}

func (f *fakeBundleApplier) ClearInspectionRuntimeState(context.Context) error {
	f.clears++
	return nil
}

func TestControllerPersistsM3ActivationOptionsAndCleansDowngrade(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	rules := &fakeBundleApplier{}
	first, err := NewController(&fakeNetworkReconciler{}, rules, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	options := M2CompileOptions{Epoch: 7, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}
	if err := first.ApplyRuntime(context.Background(), m3DataplaneConfig(), options, 5); err != nil {
		t.Fatal(err)
	}
	restartedRules := &fakeBundleApplier{}
	restarted, err := NewController(&fakeNetworkReconciler{}, restartedRules, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.currentUsesM3 || restarted.currentGeneration != 5 || restarted.currentM2Options.Epoch != 7 || restarted.currentM2Options.ZoneSlots["wan"] != 2 {
		t.Fatalf("runtime activation metadata was not restored: %#v", restarted)
	}
	if err := restarted.ApplyRuntime(context.Background(), baseM1Config(), M2CompileOptions{Epoch: 8, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}, 6); err != nil {
		t.Fatal(err)
	}
	if len(restartedRules.bundles) != 1 || restartedRules.clears != 1 {
		t.Fatalf("M3 downgrade did not atomically replace selectors and clear guards: bundles=%d clears=%d", len(restartedRules.bundles), restartedRules.clears)
	}
	if strings.Contains(restartedRules.bundles[0].PolicyTransaction, "queue num 100") || strings.Contains(restartedRules.bundles[0].PolicyTransaction, "log group 100") {
		t.Fatalf("inspection remained active after downgrade:\n%s", restartedRules.bundles[0].PolicyTransaction)
	}
	loaded, exists, err := loadAppliedSnapshot(statePath)
	if err != nil || !exists || loaded.Generation != 6 || loaded.UsesM3 {
		t.Fatalf("unexpected persisted downgrade snapshot: %#v exists=%v err=%v", loaded, exists, err)
	}
}

func TestControllerAcceptsGenerationZeroAsInitialM3Baseline(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	rules := &fakeBundleApplier{}
	controller, err := NewController(&fakeNetworkReconciler{}, rules, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	options := M2CompileOptions{Epoch: 1, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}
	if err := controller.ApplyRuntime(context.Background(), m3DataplaneConfig(), options, 0); err != nil {
		t.Fatalf("version-zero startup reconciliation failed: %v", err)
	}
	if controller.currentGeneration != 0 || len(rules.bundles) != 1 {
		t.Fatalf("unexpected initial generation/bundle state: generation=%d bundles=%d", controller.currentGeneration, len(rules.bundles))
	}
	loaded, exists, err := loadAppliedSnapshot(statePath)
	if err != nil || !exists || loaded.Generation != 0 || !loaded.UsesM3 {
		t.Fatalf("version-zero applied snapshot was not durable: %#v exists=%v err=%v", loaded, exists, err)
	}
}

func TestControllerM3FailureRestoresPreviousRuntimeSnapshot(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	rules := &fakeBundleApplier{}
	controller, err := NewController(&fakeNetworkReconciler{}, rules, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	oldOptions := M2CompileOptions{Epoch: 3, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}
	if err := controller.ApplyRuntime(context.Background(), m3DataplaneConfig(), oldOptions, 3); err != nil {
		t.Fatal(err)
	}
	desired := m3DataplaneConfig()
	desired.Policies[0].Services = []string{"tcp:8080"}
	rules.fail = true
	if err := controller.ApplyRuntime(context.Background(), desired, M2CompileOptions{Epoch: 4, ZoneSlots: oldOptions.ZoneSlots, CacheEnabled: true}, 4); err == nil {
		t.Fatal("expected injected M3 bundle failure")
	}
	loaded, exists, err := loadAppliedSnapshot(statePath)
	if err != nil || !exists || loaded.Generation != 3 || loaded.Options == nil || loaded.Options.Epoch != 3 || !loaded.UsesM3 {
		t.Fatalf("previous runtime snapshot was not restored: %#v exists=%v err=%v", loaded, exists, err)
	}
}
