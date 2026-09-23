package sensor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestCompositeSHA256SumChangesWithAnyArtifact(t *testing.T) {
	directory := t.TempDir()
	paths := []string{filepath.Join(directory, "ids.yaml"), filepath.Join(directory, "app.rules"), filepath.Join(directory, "ids.rules")}
	for index, path := range paths {
		if err := os.WriteFile(path, []byte{byte('a' + index)}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := CompositeSHA256Sum(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := CompositeSHA256Sum(paths)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first == second {
		t.Fatalf("artifact hash did not change: first=%s second=%s", first, second)
	}
}

func TestValidateActivationArtifactsRejectsModifiedRegisteredFile(t *testing.T) {
	configRoot := t.TempDir()
	managedRoot := filepath.Join(configRoot, "runtime")
	if err := os.MkdirAll(filepath.Join(configRoot, "rules"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(managedRoot, "ids"), 0700); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(configRoot, "ids.yaml"), filepath.Join(configRoot, "rules", "app-discovery.rules"), filepath.Join(configRoot, "rules", "ids-demo.rules")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := CompositeSHA256Sum(paths)
	if err != nil {
		t.Fatal(err)
	}
	manifest := SensorManifest{Version: 1, ManagedRoot: managedRoot, Sensors: []SensorDefinition{{ID: "ids", Mode: domain.InspectionModeIDS, Epoch: "epoch", EpochPath: filepath.Join(managedRoot, "ids", "sensor.epoch"), ConfigHash: hash, RulesetID: "m3-builtin-v1", EVEPath: filepath.Join(managedRoot, "ids", "eve.json"), ControlSocket: filepath.Join(managedRoot, "ids", "control.sock"), ServiceUnit: "ngfw-suricata-ids.service"}}}
	payload, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(configRoot, "manifest.json")
	if err := os.WriteFile(manifestPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	requested := map[domain.InspectionMode]bool{domain.InspectionModeIDS: true}
	allowed := map[string]struct{}{"m3-builtin-v1": {}}
	trust := func(string) error { return nil }
	if _, err := validateActivationArtifacts(manifestPath, managedRoot, requested, allowed, trust); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[2], []byte("modified\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateActivationArtifacts(manifestPath, managedRoot, requested, allowed, trust); err == nil {
		t.Fatal("modified rules artifact matched registered manifest hash")
	}
}
