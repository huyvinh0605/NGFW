package domain

import "time"

type RuntimeEventKind string
type RuntimeEventClass string

const (
	EventSessionCreated     RuntimeEventKind = "SessionCreated"
	EventSessionUpdated     RuntimeEventKind = "SessionUpdated"
	EventSessionClosed      RuntimeEventKind = "SessionClosed"
	EventSessionInvalidated RuntimeEventKind = "SessionInvalidated"
	EventDecisionChanged    RuntimeEventKind = "DecisionChanged"

	EventClassRuntime  RuntimeEventClass = "runtime"
	EventClassPolicy   RuntimeEventClass = "policy"
	EventClassSecurity RuntimeEventClass = "security"
)

type RuntimeEvent struct {
	Sequence      uint64            `json:"sequence"`
	Kind          RuntimeEventKind  `json:"kind"`
	Class         RuntimeEventClass `json:"event_class"`
	SessionID     string            `json:"session_id"`
	Timestamp     time.Time         `json:"timestamp"`
	Generation    uint64            `json:"generation,omitempty"`
	Revision      uint64            `json:"revision,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	DroppedBefore uint64            `json:"dropped_before,omitempty"`
}
