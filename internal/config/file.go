package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kltngfw/ngfw/internal/domain"
)

// LoadRunningFile is a read-only load of the engine's durable Running wrapper.
// Unlike NewManager it never creates a directory or falls back to defaults.
func LoadRunningFile(path string) (domain.Config, domain.ConfigVersion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.Config{}, domain.ConfigVersion{}, err
	}
	var stored struct {
		Config  *domain.Config        `json:"config"`
		Version *domain.ConfigVersion `json:"version"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return domain.Config{}, domain.ConfigVersion{}, fmt.Errorf("decode Running %s: %w", path, err)
	}
	if stored.Config == nil || stored.Version == nil {
		return domain.Config{}, domain.ConfigVersion{}, fmt.Errorf("%s is not a persisted Running configuration", path)
	}
	if errs := (Validator{}).Validate(*stored.Config); len(errs) != 0 {
		return domain.Config{}, domain.ConfigVersion{}, fmt.Errorf("invalid Running %s: %v", path, errs)
	}
	if digest, err := checksum(*stored.Config); err != nil || stored.Version.Checksum != "" && digest != stored.Version.Checksum {
		return domain.Config{}, domain.ConfigVersion{}, fmt.Errorf("Running checksum mismatch in %s", path)
	}
	return *stored.Config, *stored.Version, nil
}

func LoadFile(path string) (domain.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.Config{}, err
	}
	var c domain.Config
	if err := json.Unmarshal(data, &c); err != nil {
		return domain.Config{}, fmt.Errorf("decode config %s: %w", path, err)
	}
	if errs := (Validator{}).Validate(c); len(errs) > 0 {
		return domain.Config{}, fmt.Errorf("invalid config %s: %v", path, errs)
	}
	return c, nil
}
