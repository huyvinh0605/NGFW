package sensor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

type stoppedSource struct{ health inspection.SourceHealth }

func (s *stoppedSource) Run(context.Context, inspection.ObservationSink) error {
	return errors.New("reader stopped")
}
func (s *stoppedSource) Snapshot() inspection.SourceHealth { return s.health }

func TestMonitoredSourceDoesNotTreatExistingEVEFileAsCaptureLiveness(t *testing.T) {
	source := &stoppedSource{health: inspection.SourceHealth{SensorID: "ips", State: "HEALTHY"}}
	monitor := NewMonitoredSource("ips", source, t.TempDir()+"/missing.sock")
	err := monitor.Run(context.Background(), sinkFunc(func(inspection.Observation) bool { return true }))
	if err == nil {
		t.Fatal("expected stopped reader error")
	}
	if monitor.CaptureLive(time.Now()) {
		t.Fatal("old reader health must not prove capture liveness")
	}
}

type sinkFunc func(inspection.Observation) bool

func (f sinkFunc) TrySubmit(value inspection.Observation) bool { return f(value) }
