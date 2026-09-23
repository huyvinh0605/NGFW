package domain

import (
	"errors"
	"time"
)

var ErrSecurityEventNotFound = errors.New("security event not found")

// ThreatEvent is the bounded, typed security event exposed by M3. It is
// intentionally separate from the legacy risk/security event DTO.
type ThreatEvent struct {
	EventID             string              `json:"event_id"`
	Sequence            uint64              `json:"sequence"`
	ObservedAt          *time.Time          `json:"observed_at,omitempty"`
	IngestedAt          time.Time           `json:"ingested_at"`
	EventClass          string              `json:"event_class"`
	Source              string              `json:"source"`
	SensorID            string              `json:"sensor_id,omitempty"`
	SensorEpoch         string              `json:"sensor_epoch,omitempty"`
	SensorConfigHash    string              `json:"sensor_config_hash,omitempty"`
	RulesetID           string              `json:"ruleset_id,omitempty"`
	CaptureMode         InspectionMode      `json:"capture_mode"`
	SuricataFlowID      string              `json:"suricata_flow_id,omitempty"`
	TransactionID       *string             `json:"transaction_id,omitempty"`
	ObservedTuple       *Tuple              `json:"observed_tuple,omitempty"`
	FlowTuple           *Tuple              `json:"flow_tuple,omitempty"`
	ProtocolRaw         string              `json:"protocol_raw,omitempty"`
	SessionID           string              `json:"session_id,omitempty"`
	PolicyID            string              `json:"policy_id,omitempty"`
	PolicyGeneration    uint64              `json:"policy_generation,omitempty"`
	CorrelationState    CorrelationState    `json:"correlation_state"`
	CorrelationReason   string              `json:"correlation_reason,omitempty"`
	CorrelationRevision uint64              `json:"correlation_revision"`
	SignatureID         uint32              `json:"signature_id,omitempty"`
	SignatureRevision   uint32              `json:"signature_revision,omitempty"`
	Signature           string              `json:"signature,omitempty"`
	Category            string              `json:"category,omitempty"`
	SourceSeverity      *int                `json:"source_severity,omitempty"`
	Severity            Severity            `json:"severity"`
	Application         ApplicationIdentity `json:"application"`
	SignatureAction     string              `json:"signature_action,omitempty"`
	PacketVerdict       string              `json:"packet_verdict,omitempty"`
	Verdict             LatestVerdict       `json:"verdict"`
	Enforcement         EnforcementResult   `json:"enforcement"`
}

type SecurityQuery struct {
	SessionID     string           `json:"session_id,omitempty"`
	SensorID      string           `json:"sensor_id,omitempty"`
	Mode          InspectionMode   `json:"mode,omitempty"`
	Severity      Severity         `json:"severity,omitempty"`
	Verdict       LatestVerdict    `json:"verdict,omitempty"`
	Correlation   CorrelationState `json:"correlation_state,omitempty"`
	Application   string           `json:"application,omitempty"`
	AfterSequence uint64           `json:"after_sequence,omitempty"`
	StreamID      string           `json:"stream_id,omitempty"`
	Limit         int              `json:"limit,omitempty"`
}

type SecurityEventPage struct {
	Items          []ThreatEvent `json:"items"`
	StreamID       string        `json:"stream_id"`
	GapFrom        uint64        `json:"gap_from,omitempty"`
	NextSequence   uint64        `json:"next_sequence"`
	NextCursor     string        `json:"next_cursor"`
	HasMore        bool          `json:"has_more"`
	OldestSequence uint64        `json:"oldest_sequence"`
	Gap            bool          `json:"gap"`
	ResetRequired  bool          `json:"reset_required,omitempty"`
	EvictedCount   uint64        `json:"evicted_count"`
}

type SecurityEventStats struct {
	CurrentEvents uint64 `json:"current_events"`
	CurrentBytes  uint64 `json:"current_bytes"`
	Added         uint64 `json:"added"`
	Duplicates    uint64 `json:"duplicates"`
	Evicted       uint64 `json:"evicted"`
	RejectedBytes uint64 `json:"rejected_bytes"`
}

func (e ThreatEvent) Clone() ThreatEvent {
	c := e
	if e.ObservedAt != nil {
		v := *e.ObservedAt
		c.ObservedAt = &v
	}
	if e.TransactionID != nil {
		v := *e.TransactionID
		c.TransactionID = &v
	}
	if e.ObservedTuple != nil {
		v := *e.ObservedTuple
		c.ObservedTuple = &v
	}
	if e.FlowTuple != nil {
		v := *e.FlowTuple
		c.FlowTuple = &v
	}
	if e.SourceSeverity != nil {
		v := *e.SourceSeverity
		c.SourceSeverity = &v
	}
	if e.Application.FirstSeen != nil {
		v := *e.Application.FirstSeen
		c.Application.FirstSeen = &v
	}
	if e.Application.LastSeen != nil {
		v := *e.Application.LastSeen
		c.Application.LastSeen = &v
	}
	if e.Enforcement.ObservedAt != nil {
		v := *e.Enforcement.ObservedAt
		c.Enforcement.ObservedAt = &v
	}
	return c
}
