package inspection

import (
	"context"
	"errors"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type ObservationSink interface{ TrySubmit(Observation) bool }

type EventSource interface {
	Run(context.Context, ObservationSink) error
	Snapshot() SourceHealth
}

var (
	ErrEVEMalformed       = errors.New("EVE_MALFORMED")
	ErrEVETooLarge        = errors.New("EVE_TOO_LARGE")
	ErrEVEUnknownType     = errors.New("EVE_UNKNOWN_TYPE")
	ErrSourceUnavailable  = errors.New("SOURCE_UNAVAILABLE")
	ErrSourceEpochChanged = errors.New("SOURCE_EPOCH_CHANGED")
	ErrSessionMissing     = errors.New("SESSION_MISSING")
	ErrSessionAmbiguous   = errors.New("SESSION_AMBIGUOUS")
)

type SourcePosition struct {
	SensorID         string                `json:"sensor_id"`
	SensorEpoch      string                `json:"sensor_epoch"`
	SensorConfigHash string                `json:"sensor_config_hash,omitempty"`
	RulesetID        string                `json:"ruleset_id,omitempty"`
	Mode             domain.InspectionMode `json:"mode"`
	FileGeneration   string                `json:"file_generation,omitempty"`
	ByteStart        int64                 `json:"byte_start"`
	ByteEnd          int64                 `json:"byte_end"`
}

type Observation struct {
	ID              string                     `json:"id"`
	Source          SourcePosition             `json:"source"`
	Kind            string                     `json:"kind"`
	ObservedAt      *time.Time                 `json:"observed_at,omitempty"`
	IngestedAt      time.Time                  `json:"ingested_at"`
	FlowID          uint64                     `json:"-"`
	HasFlowID       bool                       `json:"has_flow_id"`
	TransactionID   *uint64                    `json:"transaction_id,omitempty"`
	Tuple           *domain.Tuple              `json:"tuple,omitempty"`
	FlowTuple       *domain.Tuple              `json:"flow_tuple,omitempty"`
	FlowStart       *time.Time                 `json:"flow_start,omitempty"`
	FlowEnd         *time.Time                 `json:"flow_end,omitempty"`
	Direction       string                     `json:"direction,omitempty"`
	App             domain.ApplicationIdentity `json:"app"`
	Alert           *AlertObservation          `json:"alert,omitempty"`
	Protocol        *ProtocolMetadata          `json:"protocol,omitempty"`
	Stats           *SensorCounters            `json:"stats,omitempty"`
	MissingEvidence []string                   `json:"missing_evidence,omitempty"`
	Truncated       bool                       `json:"truncated"`
}

type AlertObservation struct {
	SignatureID       uint32  `json:"signature_id,omitempty"`
	HasSignatureID    bool    `json:"has_signature_id"`
	SignatureRevision uint32  `json:"signature_revision,omitempty"`
	Signature         string  `json:"signature,omitempty"`
	Category          string  `json:"category,omitempty"`
	Severity          *int    `json:"severity,omitempty"`
	SignatureAction   string  `json:"signature_action,omitempty"`
	PacketVerdict     *string `json:"packet_verdict,omitempty"`
	InternalDiscovery bool    `json:"internal_discovery"`
}

type ProtocolMetadata struct {
	HTTPHost      string   `json:"http_host,omitempty"`
	HTTPMethod    string   `json:"http_method,omitempty"`
	HTTPPath      string   `json:"http_path,omitempty"`
	TLSSNI        string   `json:"tls_sni,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	DNSQuery      string   `json:"dns_query,omitempty"`
	DNSRecordType string   `json:"dns_record_type,omitempty"`
	SSHBanner     string   `json:"ssh_banner,omitempty"`
}

type SensorCounters struct {
	UptimeSeconds   *uint64    `json:"uptime_seconds,omitempty"`
	CapturedPackets *uint64    `json:"captured_packets,omitempty"`
	CaptureDrops    *uint64    `json:"capture_drops,omitempty"`
	NFQueueDrops    *uint64    `json:"nfqueue_drops,omitempty"`
	SourceTimestamp *time.Time `json:"source_timestamp,omitempty"`
}

type SourceHealth struct {
	SensorID      string                `json:"sensor_id"`
	Mode          domain.InspectionMode `json:"mode,omitempty"`
	State         string                `json:"state"`
	Reason        string                `json:"reason,omitempty"`
	LastRead      *time.Time            `json:"last_read,omitempty"`
	LastHeartbeat *time.Time            `json:"last_heartbeat,omitempty"`
	Counters      SensorCounters        `json:"counters"`
	ReaderStats   map[string]uint64     `json:"reader_stats,omitempty"`
}
