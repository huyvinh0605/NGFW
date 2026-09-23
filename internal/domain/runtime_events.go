package domain

import "time"

type RuntimeEventKind string
type RuntimeEventClass string

const (
	EventSessionCreated          RuntimeEventKind = "SessionCreated"
	EventSessionUpdated          RuntimeEventKind = "SessionUpdated"
	EventSessionClosed           RuntimeEventKind = "SessionClosed"
	EventSessionInvalidated      RuntimeEventKind = "SessionInvalidated"
	EventDecisionChanged         RuntimeEventKind = "DecisionChanged"
	EventApplicationIdentified   RuntimeEventKind = "ApplicationIdentified"
	EventInspectionStateChanged  RuntimeEventKind = "InspectionStateChanged"
	EventSecurityAlert           RuntimeEventKind = "SecurityAlert"
	EventSecurityEventUpdated    RuntimeEventKind = "SecurityEventUpdated"
	EventInspectionHealthChanged RuntimeEventKind = "InspectionHealthChanged"

	EventClassRuntime    RuntimeEventClass = "runtime"
	EventClassPolicy     RuntimeEventClass = "policy"
	EventClassSecurity   RuntimeEventClass = "security"
	EventClassInspection RuntimeEventClass = "inspection"
)

type RuntimeEvent struct {
	Sequence           uint64            `json:"sequence"`
	Kind               RuntimeEventKind  `json:"kind"`
	Class              RuntimeEventClass `json:"event_class"`
	SessionID          string            `json:"session_id"`
	Timestamp          time.Time         `json:"timestamp"`
	Generation         uint64            `json:"generation,omitempty"`
	Revision           uint64            `json:"revision,omitempty"`
	Reason             string            `json:"reason,omitempty"`
	DroppedBefore      uint64            `json:"dropped_before,omitempty"`
	EventID            string            `json:"event_id,omitempty"`
	InspectionRevision uint64            `json:"inspection_revision,omitempty"`
}
