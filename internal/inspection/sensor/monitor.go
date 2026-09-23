package sensor

import (
	"context"
	"errors"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

// MonitoredSource combines an EVE source with Suricata's fixed Unix control
// socket. Quiet traffic is therefore still considered live when the capture
// process answers probes; merely having an old eve.json file never renews the
// IPS lease.
type MonitoredSource struct {
	SensorID     string
	Source       inspection.EventSource
	Control      ControlClient
	ProbeEvery   time.Duration
	Health       *HealthReducer
	Recover      func(context.Context, string) error
	RecoveryWait time.Duration
	probeTimeout time.Duration
}

func NewMonitoredSource(sensorID string, source inspection.EventSource, controlSocket string) *MonitoredSource {
	client := ControlClient{SocketPath: controlSocket, Timeout: 500 * time.Millisecond, MaxReplyBytes: 64 << 10}
	return &MonitoredSource{SensorID: sensorID, Source: source, Control: client, ProbeEvery: time.Second, Health: NewHealthReducer(sensorID, true), Recover: RecoverSensor, RecoveryWait: 30 * time.Second, probeTimeout: client.Timeout}
}

type monitoredSink struct {
	owner *MonitoredSource
	next  inspection.ObservationSink
}

func (s monitoredSink) TrySubmit(observation inspection.Observation) bool {
	now := time.Now().UTC()
	if observation.Stats != nil {
		s.owner.Health.RecordStats(now, *observation.Stats)
	}
	accepted := s.next.TrySubmit(observation)
	s.owner.Health.SetBacklog(!accepted)
	if accepted {
		s.owner.Health.RecordRead(now)
	}
	return accepted
}

func (m *MonitoredSource) Run(ctx context.Context, sink inspection.ObservationSink) error {
	if m == nil || m.Source == nil || m.Health == nil {
		return errors.New("sensor monitor is not configured")
	}
	interval := m.ProbeEvery
	if interval <= 0 {
		interval = time.Second
	}
	readerErrors := make(chan error, 1)
	go func() { readerErrors <- m.Source.Run(ctx, monitoredSink{owner: m, next: sink}) }()
	var failedProbes int
	var lastRecovery time.Time
	probe := func() {
		probeCtx, cancel := context.WithTimeout(ctx, m.Control.Timeout)
		result, err := m.Control.Probe(probeCtx)
		cancel()
		if err != nil {
			failedProbes++
			m.Health.RecordProbe(time.Now().UTC(), false, err.Error())
		} else {
			m.Health.RecordProbe(time.Now().UTC(), result.OK, result.Message)
			if result.OK {
				failedProbes = 0
			} else {
				failedProbes++
			}
		}
		now := time.Now().UTC()
		stalled := m.Health.HealthSnapshot().State == "HEALTHY" && !m.Health.CaptureLive(now)
		wait := m.RecoveryWait
		if wait <= 0 {
			wait = 30 * time.Second
		}
		if m.Recover != nil && (failedProbes >= 2 || stalled) && (lastRecovery.IsZero() || now.Sub(lastRecovery) >= wait) {
			recoveryCtx, recoveryCancel := context.WithTimeout(ctx, 5*time.Second)
			recoveryErr := m.Recover(recoveryCtx, m.SensorID)
			recoveryCancel()
			lastRecovery = now
			failedProbes = 0
			if recoveryErr != nil {
				m.Health.RecordProbe(now, false, "sensor recovery failed: "+recoveryErr.Error())
			}
		}
	}
	probe()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-readerErrors:
			if err != nil && ctx.Err() == nil {
				m.Health.RecordParseError(err.Error())
				return err
			}
			return nil
		case <-ticker.C:
			probe()
		}
	}
}

func (m *MonitoredSource) Snapshot() inspection.SourceHealth {
	if m == nil || m.Health == nil {
		return inspection.SourceHealth{State: "UNAVAILABLE", Reason: "sensor monitor is not configured"}
	}
	result := m.Health.HealthSnapshot()
	if m.Source != nil {
		reader := m.Source.Snapshot()
		result.Mode = reader.Mode
		result.Counters = reader.Counters
		result.ReaderStats = cloneStats(reader.ReaderStats)
		if result.LastRead == nil {
			result.LastRead = reader.LastRead
		}
		if reader.State == "DEGRADED" && result.State == "HEALTHY" {
			result.State = "DEGRADED"
			result.Reason = reader.Reason
		}
	}
	return result
}

func cloneStats(value map[string]uint64) map[string]uint64 {
	if value == nil {
		return nil
	}
	result := make(map[string]uint64, len(value))
	for key, count := range value {
		result[key] = count
	}
	return result
}

func (m *MonitoredSource) CaptureLive(now time.Time) bool {
	return m != nil && m.Health != nil && m.Health.CaptureLive(now)
}
