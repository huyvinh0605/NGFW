package eve

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

type Reader struct {
	Path            string
	Source          inspection.SourcePosition
	Files           FileSource
	Checkpoints     CheckpointStore
	LineBytes       int
	NormalizedBytes int
	PollInterval    time.Duration
	StartAtEnd      bool
	DiscoverySIDs   map[uint32]struct{}
	// EpochPath is a root-owned deployment-selected file written atomically by
	// the sensor launcher on every process start. It is never derived from EVE.
	EpochPath string
	mu        sync.RWMutex
	health    inspection.SourceHealth
	parsed    atomic.Uint64
	invalid   atomic.Uint64
	ignored   atomic.Uint64
	oversize  atomic.Uint64
	queueDrop atomic.Uint64
	readerGap atomic.Uint64
}

func NewReader(path string, source inspection.SourcePosition, checkpoint CheckpointStore) *Reader {
	return &Reader{Path: path, Source: source, Files: OSFileSource{}, Checkpoints: checkpoint, LineBytes: MaxDefaultLineBytes, NormalizedBytes: MaxNormalizedBytes, PollInterval: 200 * time.Millisecond, health: inspection.SourceHealth{SensorID: source.SensorID, Mode: source.Mode, State: "STARTING"}}
}

func (r *Reader) Snapshot() inspection.SourceHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := r.health
	result.ReaderStats = map[string]uint64{"parsed": r.parsed.Load(), "invalid": r.invalid.Load(), "ignored": r.ignored.Load(), "oversize": r.oversize.Load(), "queue_dropped": r.queueDrop.Load(), "reader_gap": r.readerGap.Load()}
	return result
}
func (r *Reader) setHealth(state, reason string, read *time.Time) {
	r.mu.Lock()
	r.health.State, r.health.Reason = state, reason
	if read != nil {
		value := *read
		r.health.LastRead = &value
	}
	r.mu.Unlock()
}

func (r *Reader) Run(ctx context.Context, sink inspection.ObservationSink) error {
	if r.Files == nil {
		r.Files = OSFileSource{}
	}
	if r.LineBytes <= 0 {
		r.LineBytes = MaxDefaultLineBytes
	}
	if r.NormalizedBytes <= 0 {
		r.NormalizedBytes = MaxNormalizedBytes
	}
	if r.PollInterval <= 0 {
		r.PollInterval = 200 * time.Millisecond
	}
	checkpoint := Checkpoint{}
	if r.Checkpoints != nil {
		loaded, err := r.Checkpoints.Load()
		if err != nil {
			r.setHealth("DEGRADED", "checkpoint load failed: "+err.Error(), nil)
		} else {
			checkpoint = loaded
		}
	}
	var current OpenedFile
	var generation string
	var offset int64
	defer func() {
		if current != nil {
			_ = current.Close()
		}
	}()
	ticker := time.NewTicker(r.PollInterval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if epoch, epochErr := readSensorEpoch(r.EpochPath); epochErr != nil {
			r.setHealth("DEGRADED", "sensor epoch unavailable: "+epochErr.Error(), nil)
		} else if epoch != "" && epoch != r.Source.SensorEpoch {
			// Drain the renamed old file using its original epoch before changing
			// event identity. The launcher rotates EVE before publishing a new
			// epoch, so records from separate sensor processes never share IDs.
			if current != nil {
				if oldInfo, statErr := current.Stat(); statErr == nil {
					_, _ = r.consumeAvailable(current, generation, &offset, oldInfo.Size(), sink)
				}
				_ = current.Close()
				current = nil
			}
			r.Source.SensorEpoch = epoch
			checkpoint = Checkpoint{}
			generation, offset = "", 0
			r.setHealth("STARTING", "sensor epoch changed; resynchronizing EVE", nil)
		}
		info, err := r.Files.Stat(r.Path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				r.setHealth("UNAVAILABLE", err.Error(), nil)
			} else {
				r.setHealth("UNAVAILABLE", "EVE file unavailable", nil)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				continue
			}
		}
		observedGeneration := r.Files.Generation(info)
		if current != nil && generation != observedGeneration {
			// A rename can be followed by final writes through the old file
			// descriptor. Drain complete records before switching to the new inode.
			if oldInfo, statErr := current.Stat(); statErr == nil {
				_, _ = r.consumeAvailable(current, generation, &offset, oldInfo.Size(), sink)
			}
			_ = current.Close()
			current = nil
			generation, offset = "", 0
		}
		if current == nil || info.Size() < offset {
			if current != nil && info.Size() < offset {
				r.readerGap.Add(1)
			}
			if current != nil {
				_ = current.Close()
			}
			current, err = r.Files.Open(r.Path)
			if err != nil {
				r.setHealth("UNAVAILABLE", err.Error(), nil)
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					continue
				}
			}
			generation = observedGeneration
			offset = 0
			if checkpoint.FileGeneration == generation && checkpoint.SensorEpoch == r.Source.SensorEpoch && checkpoint.Offset <= info.Size() {
				offset = checkpoint.Offset
			} else if r.StartAtEnd && checkpoint.FileGeneration == "" {
				offset = info.Size()
			}
		}
		progressed, _ := r.consumeAvailable(current, generation, &offset, info.Size(), sink)
		if !progressed {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}
}

func (r *Reader) consumeAvailable(current OpenedFile, generation string, offset *int64, size int64, sink inspection.ObservationSink) (bool, error) {
	progressed := false
	for *offset < size {
		line, start, end, tooLarge, complete, readErr := readCompleteLine(current, *offset, r.LineBytes)
		if readErr != nil {
			r.setHealth("DEGRADED", readErr.Error(), nil)
			return progressed, readErr
		}
		if !complete {
			break
		}
		*offset = end
		progressed = true
		position := r.Source
		position.FileGeneration = generation
		position.ByteStart = start
		position.ByteEnd = end
		if tooLarge {
			r.oversize.Add(1)
			r.setHealth("DEGRADED", inspection.ErrEVETooLarge.Error(), nil)
		} else if obs, parseErr := ParseLineWithLimit(line, position, r.NormalizedBytes); parseErr != nil {
			if errors.Is(parseErr, inspection.ErrEVETooLarge) {
				r.oversize.Add(1)
				r.setHealth("DEGRADED", parseErr.Error(), nil)
			} else if errors.Is(parseErr, inspection.ErrEVEUnknownType) {
				r.ignored.Add(1)
			} else {
				r.invalid.Add(1)
				r.setHealth("DEGRADED", parseErr.Error(), nil)
			}
		} else {
			r.parsed.Add(1)
			if obs.Alert != nil {
				if _, ok := r.DiscoverySIDs[obs.Alert.SignatureID]; ok {
					obs.Alert.InternalDiscovery = true
					obs.Kind = "discovery"
				}
			}
			obs.ID = EventID(position, line)
			if !sink.TrySubmit(obs) {
				r.queueDrop.Add(1)
				r.setHealth("DEGRADED", "observation queue full", nil)
			} else {
				now := time.Now().UTC()
				r.setHealth("HEALTHY", "", &now)
			}
		}
		if r.Checkpoints != nil {
			if saveErr := r.Checkpoints.Save(Checkpoint{FileGeneration: generation, Offset: *offset, SensorEpoch: r.Source.SensorEpoch}); saveErr != nil {
				r.setHealth("DEGRADED", "checkpoint save failed: "+saveErr.Error(), nil)
			}
		}
	}
	return progressed, nil
}

func readSensorEpoch(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", err
	}
	if len(data) > 256 {
		return "", errors.New("epoch file exceeds 256 bytes")
	}
	epoch := strings.TrimSpace(string(data))
	if epoch == "" || strings.ContainsAny(epoch, " \t\r\n/\\") {
		return "", errors.New("epoch file is empty or invalid")
	}
	return epoch, nil
}

func readCompleteLine(file OpenedFile, offset int64, max int) (line []byte, start, end int64, tooLarge, complete bool, err error) {
	if _, err = file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, offset, false, false, err
	}
	start = offset
	reader := bufio.NewReaderSize(file, 4096)
	collected := make([]byte, 0, 4096)
	for {
		fragment, readErr := reader.ReadSlice('\n')
		offset += int64(len(fragment))
		if len(collected)+len(fragment) > max {
			tooLarge = true
		} else if !tooLarge {
			collected = append(collected, fragment...)
		}
		if readErr == nil {
			if len(collected) > 0 && collected[len(collected)-1] == '\n' {
				collected = collected[:len(collected)-1]
			}
			if len(collected) > 0 && collected[len(collected)-1] == '\r' {
				collected = collected[:len(collected)-1]
			}
			return collected, start, offset, tooLarge, true, nil
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return nil, start, start, false, false, nil
		}
		return nil, start, offset, tooLarge, false, readErr
	}
}
