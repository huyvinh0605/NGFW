package domain

// InspectionConfig contains only policy-visible inspection settings. Paths,
// binaries, NFLOG/NFQUEUE groups and service credentials stay in the
// root-owned deployment manifest and cannot be selected from candidate JSON.
type InspectionConfig struct {
	Enabled           bool             `json:"enabled"`
	IncludeManagement bool             `json:"include_management"`
	Limits            InspectionLimits `json:"limits"`
}

type InspectionLimits struct {
	EVELineBytes              int `json:"eve_line_bytes"`
	NormalizedEventBytes      int `json:"normalized_event_bytes"`
	ObservationQueueItems     int `json:"observation_queue_items"`
	ObservationQueueBytes     int `json:"observation_queue_bytes"`
	SecurityEvents            int `json:"security_events"`
	SecurityEventBytes        int `json:"security_event_bytes"`
	CorrelationPending        int `json:"correlation_pending"`
	CorrelationWaitMillis     int `json:"correlation_wait_ms"`
	RecentSessions            int `json:"recent_sessions"`
	RecentSessionTTLSeconds   int `json:"recent_session_ttl_seconds"`
	AppDetectionTimeoutMillis int `json:"app_detection_timeout_ms"`
}

type InspectionProfile struct {
	Mode      InspectionMode `json:"mode"`
	FailMode  string         `json:"fail_mode"`
	RulesetID string         `json:"ruleset_id"`
}

func DefaultInspectionLimits() InspectionLimits {
	return InspectionLimits{
		EVELineBytes:              1 << 20,
		NormalizedEventBytes:      8 << 10,
		ObservationQueueItems:     4096,
		ObservationQueueBytes:     8 << 20,
		SecurityEvents:            5000,
		SecurityEventBytes:        16 << 20,
		CorrelationPending:        2048,
		CorrelationWaitMillis:     2000,
		RecentSessions:            5000,
		RecentSessionTTLSeconds:   60,
		AppDetectionTimeoutMillis: 5000,
	}
}

func (l InspectionLimits) WithDefaults() InspectionLimits {
	d := DefaultInspectionLimits()
	if l.EVELineBytes == 0 {
		l.EVELineBytes = d.EVELineBytes
	}
	if l.NormalizedEventBytes == 0 {
		l.NormalizedEventBytes = d.NormalizedEventBytes
	}
	if l.ObservationQueueItems == 0 {
		l.ObservationQueueItems = d.ObservationQueueItems
	}
	if l.ObservationQueueBytes == 0 {
		l.ObservationQueueBytes = d.ObservationQueueBytes
	}
	if l.SecurityEvents == 0 {
		l.SecurityEvents = d.SecurityEvents
	}
	if l.SecurityEventBytes == 0 {
		l.SecurityEventBytes = d.SecurityEventBytes
	}
	if l.CorrelationPending == 0 {
		l.CorrelationPending = d.CorrelationPending
	}
	if l.CorrelationWaitMillis == 0 {
		l.CorrelationWaitMillis = d.CorrelationWaitMillis
	}
	if l.RecentSessions == 0 {
		l.RecentSessions = d.RecentSessions
	}
	if l.RecentSessionTTLSeconds == 0 {
		l.RecentSessionTTLSeconds = d.RecentSessionTTLSeconds
	}
	if l.AppDetectionTimeoutMillis == 0 {
		l.AppDetectionTimeoutMillis = d.AppDetectionTimeoutMillis
	}
	return l
}

// EffectiveInspectionConfig applies defaults on a value copy. It never
// mutates the Config stored by the manager and therefore does not change its
// checksum/version merely because an old M2 file was read.
func EffectiveInspectionConfig(c Config) InspectionConfig {
	if c.Inspection == nil {
		return InspectionConfig{Limits: DefaultInspectionLimits()}
	}
	effective := *c.Inspection
	effective.Limits = effective.Limits.WithDefaults()
	return effective
}

func UsesM3(c Config) bool {
	// Profiles are candidate definitions, not runtime activation requests.
	// Keeping an unreferenced M3 profile while the global switch is disabled
	// must preserve the exact M1/M2 startup path and must not require Suricata.
	return c.Inspection != nil && c.Inspection.Enabled
}
