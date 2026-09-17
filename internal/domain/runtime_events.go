package domain

import "time"

type RuntimeEventKind string

const (
	EventSessionCreated     RuntimeEventKind = "SessionCreated"
	EventSessionUpdated     RuntimeEventKind = "SessionUpdated"
	EventSessionClosed      RuntimeEventKind = "SessionClosed"
	EventSessionInvalidated RuntimeEventKind = "SessionInvalidated"
	EventDecisionChanged    RuntimeEventKind = "DecisionChanged"
)

type RuntimeEvent struct {
	Sequence      uint64           `json:"sequence"`
	Kind          RuntimeEventKind `json:"kind"`
	SessionID     string           `json:"session_id"`
	Timestamp     time.Time        `json:"timestamp"`
	Generation    uint64           `json:"generation,omitempty"`
	Revision      uint64           `json:"revision,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	DroppedBefore uint64           `json:"dropped_before,omitempty"`
}
