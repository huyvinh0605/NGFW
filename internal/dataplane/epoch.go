package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type EpochState struct {
	Schema    int       `json:"schema"`
	BootID    string    `json:"boot_id"`
	Highest   uint16    `json:"highest_epoch"`
	UpdatedAt time.Time `json:"updated_at"`
	Checksum  string    `json:"checksum"`
}

type EpochAllocator struct {
	mu     sync.Mutex
	path   string
	bootID string
	state  EpochState
}

func NewEpochAllocator(path string) (*EpochAllocator, error) {
	if path == "" {
		return nil, errors.New("epoch state path is required")
	}
	bootID := kernelBootID()
	a := &EpochAllocator{path: path, bootID: bootID, state: EpochState{Schema: 1, BootID: bootID}}
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	var state EpochState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("decode epoch state: %w", err)
	}
	checksum := state.Checksum
	state.Checksum = ""
	expected, err := epochChecksum(state)
	if err != nil || checksum == "" || checksum != expected {
		return nil, errors.New("epoch state checksum mismatch")
	}
	state.Checksum = checksum
	if state.Schema != 1 {
		return nil, errors.New("unsupported epoch state schema")
	}
	if state.BootID != bootID {
		state.Highest = 0
		state.BootID = bootID
	}
	a.state = state
	return a, nil
}

func (a *EpochAllocator) Allocate() (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Highest >= MaxKernelEpoch {
		return 0, errors.New("kernel epoch exhausted; disable cache")
	}
	a.state.Highest++
	a.state.UpdatedAt = time.Now().UTC()
	if err := a.persistLocked(); err != nil {
		a.state.Highest--
		return 0, err
	}
	return a.state.Highest, nil
}
func (a *EpochAllocator) Current() EpochState { a.mu.Lock(); defer a.mu.Unlock(); return a.state }
func (a *EpochAllocator) persistLocked() error {
	state := a.state
	state.Checksum = ""
	checksum, err := epochChecksum(state)
	if err != nil {
		return err
	}
	state.Checksum = checksum
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0700); err != nil {
		return err
	}
	return writeAtomic(a.path, payload, 0640)
}
func epochChecksum(state EpochState) (string, error) {
	state.Checksum = ""
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func kernelBootID() string {
	if data, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return string(data)
	}
	return "unknown"
}
