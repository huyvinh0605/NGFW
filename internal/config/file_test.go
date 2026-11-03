package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestLabExampleLoads(t *testing.T) {
	for _, path := range []string{"../../configs/examples/lab.json", "../../configs/examples/m1-vlan.json", "../../configs/examples/m2-lab.json"} {
		if _, err := LoadFile(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestLoadRunningFileRejectsMissingMalformedAndCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "running.json")
	if _, _, err := LoadRunningFile(path); err == nil {
		t.Fatal("missing Running fell back to defaults")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("read-only load created a state directory")
	}
	path = filepath.Join(t.TempDir(), "running.json")
	value := Defaults()
	digest, _ := checksum(value)
	version := domain.ConfigVersion{Version: 42, Checksum: digest}
	data, _ := json.Marshal(map[string]any{"config": value, "version": version})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, got, err := LoadRunningFile(path); err != nil || got.Version != 42 {
		t.Fatalf("valid Running rejected: %#v %v", got, err)
	}
	for _, bad := range []string{`{}`, `null`, `{"config":{},"version":{"checksum":"bad"}}`, `{"config":{"interfaces":[{"id":"bad","system_name":"oops;"}]},"version":{}}`} {
		_ = os.WriteFile(path, []byte(bad), 0600)
		if _, _, err := LoadRunningFile(path); err == nil {
			t.Fatalf("invalid persisted Running accepted: %s", bad)
		}
	}
}
