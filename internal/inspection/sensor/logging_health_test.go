package sensor

import (
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestLiveControlCannotHideStalledEVEStats(t *testing.T) {
	now := time.Now()
	reader := &stoppedSource{health: inspection.SourceHealth{SensorID: "ips", State: "HEALTHY", ReaderActive: true}}
	monitor := NewMonitoredSource("ips", reader, "unused")
	monitor.Health.RecordStats(now, inspection.SensorCounters{})
	monitor.Health.RecordRead(now)
	monitor.Health.RecordProbe(now, true, "")
	monitor.Health.RecordProbe(now.Add(time.Second), true, "")
	if !monitor.CaptureLive(now.Add(time.Second)) {
		t.Fatal("healthy quiet source with fresh periodic stats was not live")
	}
	// A responsive process does not prove its EVE writer is still working.
	monitor.Health.RecordProbe(now.Add(8*time.Second), true, "")
	if monitor.CaptureLive(now.Add(8 * time.Second)) {
		t.Fatal("control heartbeat concealed an EVE writer with no progress")
	}
	monitor.Health.RecordStats(now.Add(9*time.Second), inspection.SensorCounters{})
	monitor.Health.RecordRead(now.Add(9 * time.Second))
	if !monitor.CaptureLive(now.Add(9 * time.Second)) {
		t.Fatal("source did not recover after real stats resumed")
	}
}

func TestMonitoredCaptureRequiresReadableActiveEVE(t *testing.T) {
	for _, state := range []string{"UNAVAILABLE", "DEGRADED", "ERROR"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now()
			reader := &stoppedSource{health: inspection.SourceHealth{State: state, Reason: "EVE inaccessible", ReaderActive: false}}
			monitor := NewMonitoredSource("ids", reader, "unused")
			monitor.Health.RecordStats(now, inspection.SensorCounters{})
			monitor.Health.RecordProbe(now, true, "")
			monitor.Health.RecordProbe(now, true, "")
			if monitor.CaptureLive(now) || monitor.Snapshot().CaptureLive {
				t.Fatal("reachable control socket overrode an unavailable reader")
			}
		})
	}
}
