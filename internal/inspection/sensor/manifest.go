package sensor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

const MaxManifestBytes = 64 << 10

type SensorDefinition struct {
	ID            string                `json:"id"`
	Mode          domain.InspectionMode `json:"mode"`
	Epoch         string                `json:"epoch"`
	EpochPath     string                `json:"epoch_path,omitempty"`
	ConfigHash    string                `json:"config_hash"`
	RulesetID     string                `json:"ruleset_id"`
	EVEPath       string                `json:"eve_path"`
	ControlSocket string                `json:"control_socket"`
	ServiceUnit   string                `json:"service_unit"`
	DiscoverySIDs []uint32              `json:"discovery_sids,omitempty"`
}

type SensorManifest struct {
	Version     int                `json:"version"`
	ManagedRoot string             `json:"managed_root"`
	Sensors     []SensorDefinition `json:"sensors"`
}

func LoadManifest(path, expectedRoot string) (SensorManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return SensorManifest{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxManifestBytes+1))
	if err != nil {
		return SensorManifest{}, err
	}
	if len(data) > MaxManifestBytes {
		return SensorManifest{}, errors.New("sensor manifest exceeds 64 KiB")
	}
	var manifest SensorManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return SensorManifest{}, fmt.Errorf("decode sensor manifest: %w", err)
	}
	if manifest.Version != 1 {
		return SensorManifest{}, fmt.Errorf("unsupported sensor manifest version %d", manifest.Version)
	}
	root, err := filepath.Abs(expectedRoot)
	if err != nil {
		return SensorManifest{}, err
	}
	declared, err := filepath.Abs(manifest.ManagedRoot)
	if err != nil {
		return SensorManifest{}, err
	}
	if filepath.Clean(root) != filepath.Clean(declared) {
		return SensorManifest{}, errors.New("sensor manifest managed_root mismatch")
	}
	seen := map[string]struct{}{}
	for _, sensor := range manifest.Sensors {
		if sensor.ID != "ids" && sensor.ID != "ips" {
			return SensorManifest{}, fmt.Errorf("unsupported sensor id %q", sensor.ID)
		}
		expectedUnit := "ngfw-suricata-" + sensor.ID + ".service"
		if sensor.ServiceUnit != expectedUnit {
			return SensorManifest{}, fmt.Errorf("sensor %s service_unit must be %s", sensor.ID, expectedUnit)
		}
		if _, ok := seen[sensor.ID]; ok {
			return SensorManifest{}, fmt.Errorf("duplicate sensor id %q", sensor.ID)
		}
		seen[sensor.ID] = struct{}{}
		if !sensor.Mode.Valid() || sensor.Mode == domain.InspectionModeOff {
			return SensorManifest{}, fmt.Errorf("sensor %s has invalid mode", sensor.ID)
		}
		if sensor.Epoch == "" || sensor.ConfigHash == "" || sensor.RulesetID == "" {
			return SensorManifest{}, fmt.Errorf("sensor %s is missing epoch/config_hash/ruleset_id", sensor.ID)
		}
		for _, candidate := range []string{sensor.EVEPath, sensor.ControlSocket, sensor.EpochPath} {
			if candidate == "" {
				continue
			}
			if err := pathWithinRoot(root, candidate); err != nil {
				return SensorManifest{}, fmt.Errorf("sensor %s: %w", sensor.ID, err)
			}
		}
	}
	return manifest, nil
}

func pathWithinRoot(root, value string) error {
	if !filepath.IsAbs(value) {
		return fmt.Errorf("path %q must be absolute", value)
	}
	// Resolve the complete existing target first.  Resolving only the parent
	// would allow an existing final symlink to escape managed_root.
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(value))
		if parentErr != nil {
			parent = filepath.Dir(value)
		}
		resolved = filepath.Join(parent, filepath.Base(value))
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q escapes managed root", value)
	}
	return nil
}

func (m SensorManifest) Sensor(id string) (SensorDefinition, bool) {
	for _, sensor := range m.Sensors {
		if sensor.ID == id {
			return sensor, true
		}
	}
	return SensorDefinition{}, false
}
