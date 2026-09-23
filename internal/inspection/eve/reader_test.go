package eve

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

type collectingSink struct {
	mu    sync.Mutex
	items []inspection.Observation
}

func (s *collectingSink) TrySubmit(v inspection.Observation) bool {
	s.mu.Lock()
	s.items = append(s.items, v)
	s.mu.Unlock()
	return true
}
func (s *collectingSink) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.items) }
func (s *collectingSink) Items() []inspection.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]inspection.Observation(nil), s.items...)
}

func TestReaderWaitsForCompleteLineAndCheckpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(`{"event_type":"flow"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cp := &MemoryCheckpointStore{}
	reader := NewReader(path, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1", Mode: domain.InspectionModeIDS}, cp)
	reader.PollInterval = 10 * time.Millisecond
	sink := &collectingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reader.Run(ctx, sink) }()
	time.Sleep(30 * time.Millisecond)
	if sink.Len() != 0 {
		t.Fatal("partial line emitted")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("\n")
	_ = file.Close()
	deadline := time.Now().Add(time.Second)
	for sink.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if sink.Len() != 1 || cp.Value.Offset == 0 {
		t.Fatalf("reader did not emit/checkpoint: %d %#v", sink.Len(), cp.Value)
	}
}

func TestReaderDrainsOversizeThenReadsGoodLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	data := append(make([]byte, 100), '\n')
	data = append(data, []byte("{\"event_type\":\"flow\"}\n")...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(path, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1"}, nil)
	reader.LineBytes = 32
	reader.PollInterval = 5 * time.Millisecond
	sink := &collectingSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = reader.Run(ctx, sink)
	if sink.Len() != 1 {
		t.Fatalf("good line after oversized record lost: %d", sink.Len())
	}
	stats := reader.Snapshot().ReaderStats
	if stats["oversize"] != 1 || stats["parsed"] != 1 {
		t.Fatalf("reader counters=%#v", stats)
	}
}

type rejectingSink struct{}

func (rejectingSink) TrySubmit(inspection.Observation) bool { return false }

func TestReaderCountsQueueLossWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte("{\"event_type\":\"flow\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(path, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1"}, nil)
	reader.PollInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = reader.Run(ctx, rejectingSink{})
	stats := reader.Snapshot().ReaderStats
	if stats["parsed"] != 1 || stats["queue_dropped"] != 1 {
		t.Fatalf("reader counters=%#v", stats)
	}
}

func TestReaderSwitchesSensorEpochWithoutReusingEventIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	epochPath := filepath.Join(dir, "sensor.epoch")
	if err := os.WriteFile(epochPath, []byte("epoch-one\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first := []byte("{\"timestamp\":\"2026-09-23T00:00:00Z\",\"event_type\":\"flow\",\"flow_id\":1}\n")
	if err := os.WriteFile(path, first, 0600); err != nil {
		t.Fatal(err)
	}
	reader := NewReader(path, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "install-epoch", Mode: domain.InspectionModeIDS}, nil)
	reader.EpochPath = epochPath
	reader.PollInterval = 5 * time.Millisecond
	sink := &collectingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reader.Run(ctx, sink) }()
	waitForItems(t, sink, 1)

	if err := os.Rename(path, filepath.Join(dir, "eve.json.old")); err != nil {
		cancel()
		<-done
		t.Skipf("platform cannot rename an open EVE fixture: %v", err)
	}
	second := []byte("{\"timestamp\":\"2026-09-23T00:00:01Z\",\"event_type\":\"flow\",\"flow_id\":2}\n")
	if err := os.WriteFile(path, second, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(epochPath, []byte("epoch-two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitForItems(t, sink, 2)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	items := sink.Items()
	if items[0].Source.SensorEpoch != "epoch-one" || items[1].Source.SensorEpoch != "epoch-two" {
		t.Fatalf("sensor epochs were not separated: %#v", items)
	}
	if items[0].ID == items[1].ID {
		t.Fatal("events from separate process epochs shared an identity")
	}
}

func waitForItems(t *testing.T, sink *collectingSink, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for sink.Len() < count && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if sink.Len() < count {
		t.Fatalf("timed out waiting for %d observations; got %d", count, sink.Len())
	}
}

func TestReadSensorEpochRejectsOversizeAndWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epoch")
	if err := os.WriteFile(path, []byte("bad epoch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSensorEpoch(path); err == nil {
		t.Fatal("epoch containing whitespace was accepted")
	}
	if err := os.WriteFile(path, make([]byte, 257), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSensorEpoch(path); err == nil {
		t.Fatal("oversized epoch was accepted")
	}
}
