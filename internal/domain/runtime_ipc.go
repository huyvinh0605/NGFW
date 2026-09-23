package domain

import "time"

type SessionQuery struct {
	SourceIP        string       `json:"source_ip,omitempty"`
	DestinationIP   string       `json:"destination_ip,omitempty"`
	Protocol        uint8        `json:"protocol,omitempty"`
	SourceZone      string       `json:"source_zone,omitempty"`
	DestinationZone string       `json:"destination_zone,omitempty"`
	State           SessionState `json:"state,omitempty"`
	Decision        Decision     `json:"decision,omitempty"`
	TupleView       string       `json:"tuple_view,omitempty"`
	Page            int          `json:"page,omitempty"`
	PageSize        int          `json:"page_size,omitempty"`
}

type SessionPage struct {
	Items         []RuntimeSession `json:"items"`
	Page          int              `json:"page"`
	PageSize      int              `json:"page_size"`
	Total         int              `json:"total"`
	HasMore       bool             `json:"has_more"`
	StoreRevision uint64           `json:"store_revision"`
	SnapshotTime  time.Time        `json:"snapshot_time"`
}

type RuntimeStats struct {
	ActiveSessions uint64 `json:"active_sessions"`
	Created        uint64 `json:"created"`
	Closed         uint64 `json:"closed"`
	Invalidated    uint64 `json:"invalidated"`
	TrackingDrops  uint64 `json:"tracking_drops"`
	CapacityDrops  uint64 `json:"capacity_drops"`
	EventDrops     uint64 `json:"event_drops"`
	Resyncs        uint64 `json:"resyncs"`
}

type RuntimeHealth struct {
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	Generation uint64    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type RuntimeEventPage struct {
	Items        []RuntimeEvent `json:"items"`
	StreamID     string         `json:"stream_id"`
	GapFrom      uint64         `json:"gap_from,omitempty"`
	NextSequence uint64         `json:"next_sequence"`
}
