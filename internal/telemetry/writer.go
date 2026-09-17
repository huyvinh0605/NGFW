package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// Writer is the development/appliance fallback persistence boundary. It is
// asynchronous and bounded; production deployments can replace the sink with
// a batch SQLite writer without changing engine or detector code.
type Writer struct {
	queue    chan domain.SecurityEvent
	dir      string
	dropped  atomic.Uint64
	maxBytes int64
}

func NewWriter(dir string, capacity int, maxBytes int64) *Writer {
	if capacity <= 0 {
		capacity = 10000
	}
	if maxBytes <= 0 {
		maxBytes = 5 << 30
	}
	return &Writer{queue: make(chan domain.SecurityEvent, capacity), dir: dir, maxBytes: maxBytes}
}
func (w *Writer) Submit(ev domain.SecurityEvent) {
	select {
	case w.queue <- ev:
	default:
		w.dropped.Add(1)
	}
}
func (w *Writer) Dropped() uint64 { return w.dropped.Load() }
func (w *Writer) Run(ctx context.Context) error {
	if err := os.MkdirAll(w.dir, 0700); err != nil {
		return err
	}
	file, err := w.open()
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriterSize(file, 64*1024)
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = writer.Flush()
			return nil
		case ev := <-w.queue:
			line, marshalErr := json.Marshal(ev)
			if marshalErr != nil {
				continue
			}
			if _, err := writer.Write(append(line, '\n')); err != nil {
				return fmt.Errorf("write telemetry: %w", err)
			}
			if fileInfo, statErr := file.Stat(); statErr == nil && fileInfo.Size() >= w.maxBytes {
				_ = writer.Flush()
				_ = file.Close()
				file, err = w.open()
				if err != nil {
					return err
				}
				writer = bufio.NewWriterSize(file, 64*1024)
			}
		case <-flush.C:
			_ = writer.Flush()
		}
	}
}
func (w *Writer) open() (*os.File, error) {
	path := filepath.Join(w.dir, "events.jsonl")
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
}
