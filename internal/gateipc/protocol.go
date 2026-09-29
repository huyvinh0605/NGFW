package gateipc

import (
	"context"
	"encoding/json"
)

// Gate IPC uses one bounded request/response exchange per Unix connection.
// Domain payloads remain the types in internal/domain; this is only transport.
const DefaultSocketPath = "/run/ngfw/request-gate.sock"

type Operation string

const (
	OpenConnection      Operation = "open_connection"
	EvaluateRequest     Operation = "evaluate_request"
	ReportRequestResult Operation = "report_request_result"
	GateHealthPing      Operation = "gate_health_ping"
)

func (operation Operation) Valid() bool {
	switch operation {
	case OpenConnection, EvaluateRequest, ReportRequestResult, GateHealthPing:
		return true
	default:
		return false
	}
}

type requestFrame struct {
	Version       uint16          `json:"version"`
	CorrelationID string          `json:"correlation_id"`
	Operation     Operation       `json:"operation"`
	Payload       json.RawMessage `json:"payload"`
}

type responseFrame struct {
	Version          uint16          `json:"version"`
	CorrelationID    string          `json:"correlation_id"`
	OK               bool            `json:"ok"`
	Code             string          `json:"code,omitempty"`
	ConfigGeneration uint64          `json:"config_generation"`
	DecisionID       string          `json:"decision_id"`
	Data             json.RawMessage `json:"data,omitempty"`
}

type ResponseMeta struct {
	ConfigGeneration uint64
	DecisionID       string
}

type Result struct {
	Meta ResponseMeta
	Data any
}

type Handler interface {
	HandleGate(ctx context.Context, operation Operation, payload json.RawMessage) (Result, error)
}

type HandlerFunc func(context.Context, Operation, json.RawMessage) (Result, error)

func (f HandlerFunc) HandleGate(ctx context.Context, operation Operation, payload json.RawMessage) (Result, error) {
	return f(ctx, operation, payload)
}
