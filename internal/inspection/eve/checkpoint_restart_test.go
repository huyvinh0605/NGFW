package eve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestReaderRestartKeepsCheckpointForPublishedSensorEpoch(t *testing.T) {
	directory := t.TempDir()
	path, epochPath := filepath.Join(directory, "eve.json"), filepath.Join(directory, "sensor.epoch")
	if err := os.WriteFile(path, []byte("{\"event_type\":\"http\",\"flow_id\":1}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(epochPath, []byte("live-sensor-epoch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	checkpoint := FileCheckpointStore{Path: filepath.Join(directory, "checkpoint.json")}
	read := func() []inspection.Observation {
		t.Helper()
		// The root-owned manifest keeps its install epoch. The sensor launcher
		// publishes the live epoch independently, including across engine restarts.
		reader := NewReader(path, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "install-epoch", Mode: domain.InspectionModeIDS}, checkpoint)
		reader.EpochPath = epochPath
		reader.PollInterval = 5 * time.Millisecond
		sink := &collectingSink{}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
		defer cancel()
		if err := reader.Run(ctx, sink); err != nil {
			t.Fatal(err)
		}
		return sink.Items()
	}
	if initial := read(); len(initial) != 1 || initial[0].FlowID != 1 {
		t.Fatalf("initial read=%#v", initial)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString("{\"event_type\":\"http\",\"flow_id\":2}\n")
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if restarted := read(); len(restarted) != 1 || restarted[0].FlowID != 2 || restarted[0].Source.SensorEpoch != "live-sensor-epoch" {
		t.Fatalf("restart replayed previously checkpointed sensor records: %#v", restarted)
	}
}
