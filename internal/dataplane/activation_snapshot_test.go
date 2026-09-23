package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestActivationSnapshotBindsCompilerInputsAndStaticRules(t *testing.T) {
	config := m3DataplaneConfig()
	options := M2CompileOptions{Epoch: 9, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}
	first, _, firstBundle, err := PrepareM3Activation(config, 7, options)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := PrepareM3Activation(config, 7, options)
	if err != nil {
		t.Fatal(err)
	}
	if first.ArtifactHash == "" || first.StaticRulesetHash == "" || first.ArtifactHash != second.ArtifactHash || first.StaticRulesetHash != second.StaticRulesetHash {
		t.Fatalf("activation hashes are not deterministic: first=%#v second=%#v", first, second)
	}
	recompiled, err := CompileActivationSnapshot(first)
	if err != nil {
		t.Fatal(err)
	}
	if recompiled.PolicyTransaction != firstBundle.PolicyTransaction {
		t.Fatal("snapshot did not reproduce its exact static ruleset")
	}

	corrupt := cloneActivationSnapshot(first)
	corrupt.M2Options.Epoch++
	if _, err := CompileActivationSnapshot(corrupt); err == nil {
		t.Fatal("corrupt compiler options passed artifact verification")
	}
	corrupt = cloneActivationSnapshot(first)
	corrupt.InspectionPlan.Enabled = false
	if _, err := CompileActivationSnapshot(corrupt); err == nil {
		t.Fatal("corrupt inspection plan passed artifact verification")
	}
}

func TestPreparedActivationJournalSpansFinalizeAndCompensationUsesPreviousSnapshot(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	controller, err := NewController(&fakeNetworkReconciler{}, &fakeBundleApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	previous := m3DataplaneConfig()
	previousOptions := M2CompileOptions{Epoch: 3, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}
	if err := controller.ApplyRuntimePrepared(context.Background(), previous, previousOptions, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath + ".activation"); err != nil {
		t.Fatalf("prepared journal was removed before finalize: %v", err)
	}
	if err := controller.FinalizeActivation(context.Background(), previous, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath + ".activation"); !os.IsNotExist(err) {
		t.Fatalf("finalized journal still exists: %v", err)
	}

	target := m3DataplaneConfig()
	target.Policies[0].Services = []string{"tcp:8080"}
	if err := controller.ApplyRuntimePrepared(context.Background(), target, M2CompileOptions{Epoch: 8, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}, 4); err != nil {
		t.Fatal(err)
	}
	// Simulate Manager persistence compensation.  The caller-provided epoch is
	// deliberately wrong: the controller must recover epoch 3 from the journal.
	if err := controller.ApplyRuntimePrepared(context.Background(), previous, M2CompileOptions{Epoch: 99, ZoneSlots: map[string]uint8{"lan": 7, "wan": 8}, CacheEnabled: true}, 3); err != nil {
		t.Fatal(err)
	}
	if controller.currentSnapshot == nil || controller.currentSnapshot.M2Options.Epoch != 3 || controller.currentSnapshot.M2Options.ZoneSlots["wan"] != 2 {
		t.Fatalf("compensation borrowed caller target options: %#v", controller.currentSnapshot)
	}
	if err := controller.FinalizeActivation(context.Background(), previous, 3); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRejectsCorruptSnapshotBeforeKernelMutation(t *testing.T) {
	config := m3DataplaneConfig()
	snapshot, _, _, err := PrepareM3Activation(config, 2, M2CompileOptions{Epoch: 2, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.StaticRulesetHash = "tampered"
	network := &fakeNetworkReconciler{}
	rules := &fakeBundleApplier{}
	forwarding := &fakeForwarding{}
	controller, err := NewController(network, rules, forwarding, filepath.Join(t.TempDir(), "dataplane-applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.ApplySnapshot(context.Background(), snapshot); err == nil {
		t.Fatal("expected corrupt snapshot rejection")
	}
	if len(network.calls) != 0 || len(rules.bundles) != 0 || forwarding.calls != 0 {
		t.Fatalf("kernel adapters were called before snapshot verification: network=%d nft=%d forwarding=%d", len(network.calls), len(rules.bundles), forwarding.calls)
	}
}

func TestAppliedSnapshotPersistsPlanAndIndependentPreviousOptions(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	rules := &fakeBundleApplier{}
	controller, err := NewController(&fakeNetworkReconciler{}, rules, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	previousOptions := M2CompileOptions{Epoch: 3, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}
	if err := controller.ApplyRuntime(context.Background(), m3DataplaneConfig(), previousOptions, 3); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := loadAppliedSnapshot(statePath)
	if err != nil || !exists || loaded.Snapshot == nil {
		t.Fatalf("missing persisted activation snapshot: state=%#v exists=%v err=%v", loaded, exists, err)
	}
	if loaded.Snapshot.M2Options.Epoch != 3 || loaded.Snapshot.Generation != 3 || !loaded.Snapshot.InspectionPlan.Enabled {
		t.Fatalf("incomplete activation snapshot: %#v", loaded.Snapshot)
	}

	target := m3DataplaneConfig()
	target.Policies[0].Services = []string{"tcp:8080"}
	rules.fail = true
	if err := controller.ApplyRuntime(context.Background(), target, M2CompileOptions{Epoch: 8, ZoneSlots: map[string]uint8{"lan": 1, "wan": 2}, CacheEnabled: true}, 4); err == nil {
		t.Fatal("expected target bundle failure")
	}
	loaded, exists, err = loadAppliedSnapshot(statePath)
	if err != nil || !exists || loaded.Snapshot == nil {
		t.Fatalf("previous activation snapshot was not restored: state=%#v exists=%v err=%v", loaded, exists, err)
	}
	if loaded.Snapshot.M2Options.Epoch != 3 || loaded.Snapshot.Generation != 3 {
		t.Fatalf("rollback borrowed target compiler options: %#v", loaded.Snapshot)
	}
}
