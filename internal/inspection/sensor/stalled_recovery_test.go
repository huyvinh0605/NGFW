package sensor

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

type activeQuietSource struct{ state string }

func (activeQuietSource) Run(ctx context.Context, _ inspection.ObservationSink) error {
	<-ctx.Done()
	return nil
}
func (s activeQuietSource) Snapshot() inspection.SourceHealth {
	state := s.state
	if state == "" {
		state = "HEALTHY"
	}
	return inspection.SourceHealth{SensorID: "ips", SensorEnabled: true, ReaderActive: state == "HEALTHY", State: state}
}

func responsiveControlSocket(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				decoder := json.NewDecoder(connection)
				var request map[string]any
				if decoder.Decode(&request) == nil {
					_ = writeControlJSON(connection, map[string]string{"return": "OK"})
					if decoder.Decode(&request) == nil {
						_ = writeControlJSON(connection, map[string]any{"return": "OK", "message": 42})
					}
				}
			}()
		}
	}()
	return path
}

func TestMonitorRecoversStalledEVEWithResponsiveControl(t *testing.T) {
	path := responsiveControlSocket(t)
	monitor := NewMonitoredSource("ips", activeQuietSource{}, path)
	monitor.ProbeEvery, monitor.RecoveryWait = 5*time.Millisecond, time.Hour
	old := time.Now().Add(-10 * time.Second)
	monitor.Health.RecordStats(old, inspection.SensorCounters{})
	monitor.Health.RecordRead(old)
	monitor.Health.RecordProbe(old, true, "")
	monitor.Health.RecordProbe(old, true, "")
	var calls atomic.Int32
	recovered := make(chan struct{}, 1)
	monitor.Recover = func(context.Context, string) error {
		calls.Add(1)
		select {
		case recovered <- struct{}{}:
		default:
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx, sinkFunc(func(inspection.Observation) bool { return true })) }()
	defer func() { cancel(); <-done }()
	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatal("responsive control concealed stale EVE and prevented recovery")
	}
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("recovery cooldown ignored: %d calls", calls.Load())
	}
	now := time.Now()
	monitor.Health.RecordStats(now, inspection.SensorCounters{})
	monitor.Health.RecordRead(now)
	if !monitor.Snapshot().CaptureLive {
		t.Fatal("fresh stats did not restore capture after recovery")
	}
}

func TestMonitorWaitsForInitialEVEGraceBeforeRecovery(t *testing.T) {
	for _, path := range []string{responsiveControlSocket(t), filepath.Join(t.TempDir(), "not-yet-created.sock")} {
		t.Run(path, func(t *testing.T) {
			monitor := NewMonitoredSource("ips", activeQuietSource{state: "UNAVAILABLE"}, path)
			monitor.ProbeEvery = 5 * time.Millisecond
			var calls atomic.Int32
			monitor.Recover = func(context.Context, string) error { calls.Add(1); return nil }
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- monitor.Run(ctx, sinkFunc(func(inspection.Observation) bool { return true })) }()
			time.Sleep(50 * time.Millisecond)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Fatalf("missing initial EVE file caused premature restart: %d", calls.Load())
			}
		})
	}
}
