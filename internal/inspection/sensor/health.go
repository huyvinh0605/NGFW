package sensor

import (
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

type HealthReducer struct {
	mu            sync.RWMutex
	snapshot      inspection.SourceHealth
	enabled       bool
	successes     int
	backlog       bool
	lastProgress  *time.Time
	statsTimeout  time.Duration
	statsStarted  time.Time
	lastStatsRead *time.Time
}

func NewHealthReducer(sensorID string, enabled bool) *HealthReducer {
	state := "DISABLED"
	if enabled {
		state = "STARTING"
	}
	return &HealthReducer{enabled: enabled, snapshot: inspection.SourceHealth{SensorID: sensorID, SensorEnabled: enabled, State: state}}
}

func (h *HealthReducer) RecordProbe(now time.Time, ok bool, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.enabled {
		h.snapshot.State = "DISABLED"
		return
	}
	if ok {
		h.snapshot.ProcessReachable = true
		h.successes++
		h.snapshot.LastHeartbeat = timePointer(now)
		if h.successes >= 2 {
			h.snapshot.State = "HEALTHY"
			h.snapshot.Reason = ""
		}
	} else {
		h.snapshot.ProcessReachable = false
		h.successes = 0
		h.snapshot.State = "DEGRADED"
		h.snapshot.Reason = reason
	}
}
func (h *HealthReducer) RecordRead(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snapshot.LastRead = timePointer(now)
	h.lastProgress = timePointer(now)
	if h.enabled && h.snapshot.State == "STARTING" {
		h.snapshot.State = "HEALTHY"
	}
}
func (h *HealthReducer) RecordStats(now time.Time, counters inspection.SensorCounters) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snapshot.Counters = cloneCounters(counters)
	h.lastStatsRead = timePointer(now)
	heartbeat := now.UTC()
	if counters.SourceTimestamp != nil {
		heartbeat = counters.SourceTimestamp.UTC()
	}
	h.snapshot.LastHeartbeat = timePointer(heartbeat)
}
func (h *HealthReducer) RecordParseError(reason string) {
	h.mu.Lock()
	h.snapshot.State = "DEGRADED"
	h.snapshot.Reason = reason
	h.mu.Unlock()
}
func (h *HealthReducer) SetBacklog(value bool) { h.mu.Lock(); h.backlog = value; h.mu.Unlock() }
func (h *HealthReducer) CaptureLive(now time.Time) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.captureLiveLocked(now)
}
func (h *HealthReducer) captureLiveLocked(now time.Time) bool {
	if !h.enabled || !h.snapshot.ProcessReachable {
		return false
	}
	if h.statsTimeout > 0 && (h.lastStatsRead == nil || now.Sub(*h.lastStatsRead) > h.statsTimeout) {
		return false
	}
	if h.backlog && h.lastProgress != nil && now.Sub(*h.lastProgress) > 6*time.Second {
		return false
	}
	if h.snapshot.LastHeartbeat != nil && now.Sub(*h.snapshot.LastHeartbeat) > 6*time.Second {
		return false
	}
	return h.snapshot.State == "HEALTHY"
}
func (h *HealthReducer) HealthSnapshot() inspection.SourceHealth {
	return h.snapshotAt(time.Now().UTC())
}

func (h *HealthReducer) awaitingInitialStats(now time.Time) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.statsTimeout > 0 && h.lastStatsRead == nil && now.Sub(h.statsStarted) <= h.statsTimeout
}

func (h *HealthReducer) snapshotAt(now time.Time) inspection.SourceHealth {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := h.snapshot
	result.CaptureLive = h.captureLiveLocked(now)
	if h.enabled && result.State == "HEALTHY" && h.statsTimeout > 0 {
		switch {
		case h.lastStatsRead == nil:
			result.State, result.Reason = "STARTING", "waiting for periodic EVE stats heartbeat"
			if now.Sub(h.statsStarted) > h.statsTimeout {
				result.State, result.Reason = "DEGRADED", "periodic EVE stats heartbeat unavailable"
			}
		case now.Sub(*h.lastStatsRead) > h.statsTimeout:
			result.State, result.Reason = "DEGRADED", "periodic EVE stats heartbeat stalled; logging or reader progress unavailable"
		}
	}
	result.Counters = cloneCounters(h.snapshot.Counters)
	return result
}
func timePointer(value time.Time) *time.Time { value = value.UTC(); return &value }

func cloneCounters(value inspection.SensorCounters) inspection.SensorCounters {
	result := value
	if value.UptimeSeconds != nil {
		v := *value.UptimeSeconds
		result.UptimeSeconds = &v
	}
	if value.CapturedPackets != nil {
		v := *value.CapturedPackets
		result.CapturedPackets = &v
	}
	if value.CaptureDrops != nil {
		v := *value.CaptureDrops
		result.CaptureDrops = &v
	}
	if value.NFQueueDrops != nil {
		v := *value.NFQueueDrops
		result.NFQueueDrops = &v
	}
	if value.SourceTimestamp != nil {
		v := *value.SourceTimestamp
		result.SourceTimestamp = &v
	}
	return result
}
