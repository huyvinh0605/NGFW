package eve

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Checkpoint struct {
	FileGeneration string `json:"file_generation"`
	Offset         int64  `json:"offset"`
	SensorEpoch    string `json:"sensor_epoch"`
}

type CheckpointStore interface {
	Load() (Checkpoint, error)
	Save(Checkpoint) error
}

type FileCheckpointStore struct{ Path string }

func (s FileCheckpointStore) Load() (Checkpoint, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, nil
	}
	if err != nil {
		return Checkpoint{}, err
	}
	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return Checkpoint{}, err
	}
	if checkpoint.Offset < 0 {
		return Checkpoint{}, errors.New("negative checkpoint offset")
	}
	return checkpoint, nil
}

func (s FileCheckpointStore) Save(checkpoint Checkpoint) error {
	if s.Path == "" {
		return errors.New("checkpoint path is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0750); err != nil {
		return err
	}
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.Path), ".checkpoint-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(0640); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.Path); err != nil {
		return err
	}
	if directory, err := os.Open(filepath.Dir(s.Path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	ok = true
	return nil
}

type MemoryCheckpointStore struct {
	Value Checkpoint
	Err   error
}

func (m *MemoryCheckpointStore) Load() (Checkpoint, error) {
	if m.Err != nil {
		return Checkpoint{}, m.Err
	}
	return m.Value, nil
}
func (m *MemoryCheckpointStore) Save(v Checkpoint) error {
	if m.Err != nil {
		return m.Err
	}
	m.Value = v
	return nil
}
