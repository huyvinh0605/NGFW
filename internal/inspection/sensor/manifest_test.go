package sensor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestLoadManifestRestrictsManagedPaths(t *testing.T) {
	root := t.TempDir()
	manifest := SensorManifest{Version: 1, ManagedRoot: root, Sensors: []SensorDefinition{{ID: "ids", Mode: domain.InspectionModeIDS, Epoch: "e1", ConfigHash: "h", RulesetID: "m3-builtin-v1", EVEPath: filepath.Join(root, "ids/eve.json"), ControlSocket: filepath.Join(root, "ids/control.sock"), ServiceUnit: "ngfw-suricata-ids.service"}}}
	data, _ := json.Marshal(manifest)
	path := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path, root); err != nil {
		t.Fatal(err)
	}
	manifest.Sensors[0].EVEPath = filepath.Join(filepath.Dir(root), "escape.json")
	data, _ = json.Marshal(manifest)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path, root); err == nil {
		t.Fatal("escaped path accepted")
	}
}

func TestHealthReducerRequiresRecoveryHysteresis(t *testing.T) {
	h := NewHealthReducer("ids", true)
	now := time.Now()
	h.RecordProbe(now, false, "down")
	h.RecordProbe(now, true, "")
	if h.HealthSnapshot().State == "HEALTHY" {
		t.Fatal("single success recovered health")
	}
	h.RecordProbe(now.Add(time.Second), true, "")
	if !h.CaptureLive(now.Add(time.Second)) {
		t.Fatalf("health did not recover: %#v", h.HealthSnapshot())
	}
	h.SetBacklog(true)
	if h.CaptureLive(now.Add(8 * time.Second)) {
		t.Fatal("stalled backlog considered live")
	}
}

func TestLoadManifestRejectsFinalSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(outside, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "ids")
	if err := os.MkdirAll(inside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inside, "eve.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	manifest := SensorManifest{Version: 1, ManagedRoot: root, Sensors: []SensorDefinition{{ID: "ids", Mode: domain.InspectionModeIDS, Epoch: "e1", ConfigHash: "h", RulesetID: "m3-builtin-v1", EVEPath: link, ControlSocket: filepath.Join(inside, "control.sock"), ServiceUnit: "ngfw-suricata-ids.service"}}}
	data, _ := json.Marshal(manifest)
	path := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path, root); err == nil {
		t.Fatal("final-component symlink escaped managed root")
	}
}

func TestLoadManifestRejectsArbitraryRecoveryUnit(t *testing.T) {
	root := t.TempDir()
	manifest := SensorManifest{Version: 1, ManagedRoot: root, Sensors: []SensorDefinition{{ID: "ips", Mode: domain.InspectionModeIPS, Epoch: "e1", ConfigHash: "h", RulesetID: "m3-builtin-v1", EVEPath: filepath.Join(root, "ips/eve.json"), ControlSocket: filepath.Join(root, "ips/control.sock"), ServiceUnit: "ssh.service"}}}
	data, _ := json.Marshal(manifest)
	path := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path, root); err == nil {
		t.Fatal("arbitrary recovery unit was accepted")
	}
}
