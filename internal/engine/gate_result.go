package engine

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

// ReportRequestResult only annotates an existing, allowed, generation-bound
// request. It never evaluates policy, changes an ALLOW, or creates M2 state.
func (service *GateService) ReportRequestResult(ctx context.Context, input domain.ProxyRequestResult) (domain.RequestResultReceipt, error) {
	if service == nil || service.Runtime == nil {
		return domain.RequestResultReceipt{}, &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
	}
	if err := ctx.Err(); err != nil {
		return domain.RequestResultReceipt{}, err
	}
	if err := service.checkProxyRuntime(input.EngineInstanceID, input.ConfigGeneration); err != nil {
		return domain.RequestResultReceipt{}, err
	}
	bad := func() (domain.RequestResultReceipt, error) {
		return domain.RequestResultReceipt{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	if !domain.ValidGateInstanceID(input.RequestID) || !domain.ValidGateInstanceID(input.ConnectionID) ||
		!domain.ValidGateInstanceID(input.DecisionID) || !domain.ValidRequestResult(input.ReasonCode, input.HTTPStatus) {
		return bad()
	}
	now := time.Now().UTC()
	var event *domain.RuntimeEvent
	service.gateMu.Lock()
	defer func() {
		service.gateMu.Unlock()
		if event != nil {
			service.Runtime.publish(*event)
		}
	}()
	record, ok := service.gateDecisions[input.RequestID]
	if !ok || !now.Before(record.expires) {
		if ok {
			service.removeGateDecisionLocked(input.RequestID, record)
		}
		return bad()
	}
	evidence := record.evidence.Clone()
	if evidence.Context.ConnectionID != input.ConnectionID || evidence.Decision.DecisionID != input.DecisionID ||
		evidence.Decision.ConfigGeneration != input.ConfigGeneration || input.ConfigGeneration != service.Runtime.CurrentGeneration() ||
		evidence.Decision.Verdict != domain.RequestAllow ||
		(input.ClientCertificateRequested || len(input.ReasonCode) >= 4 && input.ReasonCode[:4] == "TLS_") && evidence.Context.Scheme != "https" ||
		input.ReasonCode == "TLS_UPSTREAM_MTLS_UNSUPPORTED" && !input.ClientCertificateRequested {
		return bad()
	}
	receipt := domain.RequestResultReceipt{RequestID: input.RequestID, DecisionID: input.DecisionID, ConfigGeneration: input.ConfigGeneration}
	if prior := evidence.Forward; prior != nil {
		if prior.HTTPStatus != input.HTTPStatus || prior.ReasonCode != input.ReasonCode || prior.ClientCertificateRequested != input.ClientCertificateRequested {
			return bad()
		}
		return receipt, nil // retries are idempotent; no TTL extension or duplicate event
	}
	evidence.Forward = &domain.RequestForwardResult{HTTPStatus: input.HTTPStatus, ReasonCode: input.ReasonCode,
		ClientCertificateRequested: input.ClientCertificateRequested, ObservedAt: now}
	evidence.Sequence = service.gateSequence + 1
	encoded, err := json.Marshal(evidence)
	maxBytes := service.MaxEvidenceBytes
	if maxBytes <= 0 || maxBytes > 64<<20 {
		maxBytes = defaultEvidenceBytes
	}
	if err != nil || len(encoded) > maxBytes {
		return bad()
	}
	// Preserve the byte budget even when an annotation grows an existing record.
	for service.gateDecisionBytes-record.size+len(encoded) > maxBytes {
		front := service.gateDecisionOrder.Front()
		if front != nil && front.Value.(string) == input.RequestID {
			front = front.Next()
		}
		if front == nil {
			return bad()
		}
		id := front.Value.(string)
		service.removeGateDecisionLocked(id, service.gateDecisions[id])
	}
	service.gateSequence++
	service.gateDecisionBytes += len(encoded) - record.size
	record.evidence, record.size = evidence, len(encoded)
	service.gateDecisionOrder.MoveToBack(record.node)
	service.gateDecisions[input.RequestID] = record
	event = &domain.RuntimeEvent{Kind: domain.EventRequestGateResult, Class: domain.EventClassInspection,
		EventID: input.DecisionID, SessionID: evidence.Decision.SessionID, Timestamp: now,
		Generation: input.ConfigGeneration, Reason: input.ReasonCode}
	return receipt, nil
}
