package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/kltngfw/ngfw/internal/domain"
)

// NewEditorManager keeps API drafts in its own writable directory. It never
// publishes the engine's running.json or restores validation across a restart.
func NewEditorManager(dir string, initial domain.Config) (*Manager, error) {
	m, err := NewManager(dir, initial)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(m.dir, "candidate.json"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		var stored struct {
			SchemaVersion int                   `json:"schema_version"`
			Running       *domain.Config        `json:"base_running"`
			Version       *domain.ConfigVersion `json:"base_version"`
			Candidate     *domain.Config        `json:"candidate"`
		}
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, fmt.Errorf("decode saved candidate: %w", err)
		}
		if stored.SchemaVersion != 1 || stored.Running == nil || stored.Version == nil || stored.Candidate == nil {
			return nil, errors.New("invalid saved candidate envelope")
		}
		if len(m.validator.Validate(*stored.Running)) != 0 {
			return nil, errors.New("invalid saved candidate base configuration")
		}
		// Pending drafts may be incomplete; they still require normal validation
		// before commit. The cached base only lets SyncRunning distinguish a
		// pending edit from an untouched editor when the engine has moved on.
		m.running, m.version = cloneConfig(*stored.Running), *stored.Version
		m.candidate = cloneConfig(*stored.Candidate)
	}
	m.persistEditor = true
	return m, nil
}

func (m *Manager) persistEditorLocked(candidate, running domain.Config, version domain.ConfigVersion) error {
	if !m.persistEditor {
		return nil
	}
	payload, err := json.MarshalIndent(struct {
		SchemaVersion int                  `json:"schema_version"`
		Running       domain.Config        `json:"base_running"`
		Version       domain.ConfigVersion `json:"base_version"`
		Candidate     domain.Config        `json:"candidate"`
	}{1, running, version, candidate}, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(m.dir, ".candidate-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0640); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(m.dir, "candidate.json")); err != nil {
		return err
	}
	directory, err := os.Open(m.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
