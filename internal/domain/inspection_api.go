package domain

import "time"

type InspectionSourceStatus struct {
	SensorID      string            `json:"sensor_id"`
	Mode          InspectionMode    `json:"mode,omitempty"`
	State         string            `json:"state"`
	Reason        string            `json:"reason,omitempty"`
	LastRead      *time.Time        `json:"last_read,omitempty"`
	LastHeartbeat *time.Time        `json:"last_heartbeat,omitempty"`
	Counters      SensorCounters    `json:"counters"`
	ReaderStats   map[string]uint64 `json:"reader_stats,omitempty"`
}

// SensorCounters uses pointers so an unavailable kernel/sensor counter is
// represented as null instead of being reported as a measured zero.
type SensorCounters struct {
	UptimeSeconds   *uint64    `json:"uptime_seconds,omitempty"`
	CapturedPackets *uint64    `json:"captured_packets,omitempty"`
	CaptureDrops    *uint64    `json:"capture_drops,omitempty"`
	NFQueueDrops    *uint64    `json:"nfqueue_drops,omitempty"`
	SourceTimestamp *time.Time `json:"source_timestamp,omitempty"`
}

// InspectionQueueStatus deliberately separates configuration intent from
// runtime evidence. In particular, a requested IPS profile does not imply a
// configured listener, a live capture source, or an active kernel lease.
type InspectionQueueStatus struct {
	Requested   bool       `json:"requested"`
	Configured  bool       `json:"configured"`
	CaptureLive bool       `json:"capture_live"`
	LeaseActive bool       `json:"lease_active"`
	LastRenewal *time.Time `json:"last_renewal,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

type InspectionHealth struct {
	Enabled    bool                              `json:"enabled"`
	Status     string                            `json:"status"`
	Reason     string                            `json:"reason,omitempty"`
	Generation uint64                            `json:"generation"`
	Sources    map[string]InspectionSourceStatus `json:"sources"`
	IPSQueue   InspectionQueueStatus             `json:"ips_queue"`
	Stats      map[string]uint64                 `json:"stats"`
	UpdatedAt  time.Time                         `json:"updated_at"`
}

type InspectionCapabilities struct {
	Supported             bool             `json:"supported"`
	Modes                 []InspectionMode `json:"modes"`
	Applications          []string         `json:"applications"`
	FailModes             []string         `json:"fail_modes"`
	Rulesets              []string         `json:"rulesets"`
	ApplicationMatchModes []string         `json:"application_match_modes"`
	Limitations           []string         `json:"limitations"`
}
