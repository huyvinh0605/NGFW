package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUbuntuSchema2SnapshotUpgradesWithoutLosingGeneration(t *testing.T) {
	// Captured from the real VM's pre-M4 activation journal. Its hashes must
	// authenticate unchanged; calculating an old hash with the new compiler
	// would not detect a compatibility regression.
	raw, err := os.ReadFile("testdata/activation-schema2.json")
	if err != nil {
		t.Fatal(err)
	}
	var old ActivationSnapshot
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileActivationSnapshot(old); err != nil {
		t.Fatalf("real historical snapshot no longer verifies: %v", err)
	}
	next, err := upgradeActivationSnapshot(old)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := CompileActivationSnapshot(next)
	if err != nil {
		t.Fatal(err)
	}
	if next.Generation != old.Generation || next.M2Options.Epoch != old.M2Options.Epoch || next.ArtifactHash == old.ArtifactHash || next.Schema != 3 {
		t.Fatalf("incorrect upgrade metadata: %+v", next)
	}
	if !strings.Contains(bundle.InspectionSchema, "schema=2") || strings.Contains(bundle.InspectionSchema, "typeof ct zone . ct id") {
		t.Fatal("upgrade retained unsupported nft concatenation")
	}
	statePath := filepath.Join(t.TempDir(), "applied.json")
	if err := saveAppliedRuntimeSnapshot(statePath, old); err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(&fakeNetworkReconciler{}, &fakeBundleApplier{}, &fakeForwarding{}, statePath)
	if err != nil || controller.currentSnapshot.Schema != 3 {
		t.Fatalf("controller did not upgrade historical applied state: %v", err)
	}
}

func TestInspectionGuardSharedIDKeepsZonesAndTuplesIsolated(t *testing.T) {
	fake := &fakeInspectionNft{contains: true}
	manager := NewInspectionGuardManager(fake, 3)
	first, _ := BuildInspectionGuardKey(guardIdentity())
	second := first
	second.ConntrackZone++
	third := first
	third.Original.SrcPort++
	for _, key := range []InspectionGuardKey{first, second, third} {
		if err := manager.InstallAppGuard(context.Background(), key, 0); err != nil {
			t.Fatal(err)
		}
	}
	last := fake.scripts[len(fake.scripts)-1]
	if !strings.Contains(last, "ct zone 2 "+inspectionGuardTuple+" @app_denied_z2_i99") || !strings.Contains(last, "ct zone 3 "+inspectionGuardTuple+" @app_denied_z3_i99") {
		t.Fatalf("same ID across zones lost an exact group: %s", last)
	}
	if err := manager.RemoveAppGuard(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if removal := fake.scripts[len(fake.scripts)-1]; strings.Contains(removal, "delete set") || strings.Contains(removal, "delete chain") {
		t.Fatalf("removing one tuple removed a shared group: %s", removal)
	}
	if err := manager.RemoveAppGuard(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	removal := fake.scripts[len(fake.scripts)-1]
	if !strings.Contains(removal, "delete set inet ngfw_inspection app_denied_z2_i99") || strings.Contains(removal, "ct zone 2 ") || !strings.Contains(removal, "ct zone 3 ") || strings.Contains(removal, "delete chain") {
		t.Fatalf("removing zone 2 damaged the remaining zone: %s", removal)
	}
	if err := manager.RemoveAppGuard(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	removal = fake.scripts[len(fake.scripts)-1]
	if !strings.Contains(removal, "delete chain inet ngfw_inspection app_guard_i99") || !strings.Contains(removal, "delete element inet ngfw_inspection app_denied_v4 { 99 }") {
		t.Fatalf("last guard leaked its dispatch resources: %s", removal)
	}
}
