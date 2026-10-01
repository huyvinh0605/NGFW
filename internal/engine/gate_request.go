package engine

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

const (
	defaultGateConnections = 50000
	defaultGateDecisions   = 10000
	defaultEvidenceBytes   = 16 << 20
	gateConnectionTTL      = 5 * time.Minute
	gateDecisionTTL        = 10 * time.Minute
)

type gateConnectionRecord struct {
	open    domain.ProxyConnectionOpen
	expires time.Time
}

type gateDecisionRecord struct {
	evidence domain.RequestGateEvidence
	expires  time.Time
	size     int
	node     *list.Element
}

func (service *GateService) rememberGateConnection(open domain.ProxyConnectionOpen, decision *domain.ProxyConnectionDecision) bool {
	service.gateMu.Lock()
	defer service.gateMu.Unlock()
	if service.gateConnections == nil {
		service.gateConnections = make(map[string]gateConnectionRecord)
	}
	if existing, exists := service.gateConnections[open.ConnectionID]; exists && time.Now().Before(existing.expires) && !sameGateConnection(existing.open, open) {
		delete(service.gateConnections, open.ConnectionID)
		return false
	}
	if decision.Action != domain.TLSGateInspectHTTP && decision.Action != domain.TLSGateDecrypt {
		// Retain a prior connection identity until TTL so a request racing a
		// new deny/block still gets an explicit policy denial instead of losing
		// its tuple and looking like an unknown proxy connection.
		return true
	}
	limit := service.MaxConnections
	if limit <= 0 || limit > defaultGateConnections {
		limit = defaultGateConnections
	}
	if _, exists := service.gateConnections[open.ConnectionID]; !exists && len(service.gateConnections) >= limit {
		now := time.Now()
		for key, value := range service.gateConnections {
			if !now.Before(value.expires) {
				delete(service.gateConnections, key)
			}
		}
		if len(service.gateConnections) >= limit {
			return false
		}
	}
	copyOpen := open
	copyTLS := *open.IsTLS
	copyOpen.IsTLS = &copyTLS
	service.gateConnections[open.ConnectionID] = gateConnectionRecord{open: copyOpen, expires: time.Now().Add(gateConnectionTTL)}
	return true
}

func sameGateConnection(a, b domain.ProxyConnectionOpen) bool {
	return a.ConnectionID == b.ConnectionID && a.SourceIP == b.SourceIP && a.SourcePort == b.SourcePort && a.OriginalIP == b.OriginalIP && a.OriginalPort == b.OriginalPort && a.Protocol == b.Protocol && a.TLSFailureCode == b.TLSFailureCode && a.IsTLS != nil && b.IsTLS != nil && *a.IsTLS == *b.IsTLS
}

func (service *GateService) gateConnection(id string) (domain.ProxyConnectionOpen, bool) {
	service.gateMu.Lock()
	defer service.gateMu.Unlock()
	value, exists := service.gateConnections[id]
	if !exists || !time.Now().Before(value.expires) {
		delete(service.gateConnections, id)
		return domain.ProxyConnectionOpen{}, false
	}
	return value.open, true
}

func (service *GateService) storeGateDecision(context domain.RequestContext, inspection domain.RequestInspectionResult, decision domain.RequestDecision) {
	now := time.Now().UTC()
	evidence := domain.RequestGateEvidence{
		EventID: decision.DecisionID, ObservedAt: now,
		Context: context.Clone(), Inspection: inspection.Clone(), Decision: decision,
		AlertCount: len(inspection.Alerts),
	}
	evidence.Context.Path, evidence.PathTruncated = truncateEvidenceText(evidence.Context.Path, 256)
	if len(evidence.Inspection.Alerts) > 4 {
		evidence.Inspection.Alerts = evidence.Inspection.Alerts[:4]
		evidence.AlertsTruncated = true
	}
	for index := range evidence.Inspection.Alerts {
		evidence.Inspection.Alerts[index].Message, _ = truncateEvidenceText(evidence.Inspection.Alerts[index].Message, 128)
	}
	service.gateMu.Lock()
	if service.gateDecisions == nil {
		service.gateDecisions = make(map[string]gateDecisionRecord)
		service.gateDecisionOrder = list.New()
	}
	limit := service.MaxDecisions
	if limit <= 0 || limit > defaultGateDecisions {
		limit = defaultGateDecisions
	}
	maxBytes := service.MaxEvidenceBytes
	if maxBytes <= 0 || maxBytes > 64<<20 {
		maxBytes = defaultEvidenceBytes
	}
	evidence.Sequence = service.gateSequence + 1
	encoded, err := json.Marshal(evidence)
	if err != nil || len(encoded) > maxBytes {
		service.gateMu.Unlock()
		return
	}
	if prior, exists := service.gateDecisions[context.RequestID]; exists {
		service.removeGateDecisionLocked(context.RequestID, prior)
	}
	for len(service.gateDecisions) >= limit || service.gateDecisionBytes+len(encoded) > maxBytes {
		front := service.gateDecisionOrder.Front()
		if front == nil {
			break
		}
		id := front.Value.(string)
		service.removeGateDecisionLocked(id, service.gateDecisions[id])
	}
	service.gateSequence++
	node := service.gateDecisionOrder.PushBack(context.RequestID)
	service.gateDecisions[context.RequestID] = gateDecisionRecord{evidence: evidence, expires: now.Add(gateDecisionTTL), size: len(encoded), node: node}
	service.gateDecisionBytes += len(encoded)
	service.gateMu.Unlock()
	service.Runtime.publish(domain.RuntimeEvent{
		Kind: domain.EventRequestGateDecision, Class: domain.EventClassSecurity,
		EventID: decision.DecisionID, SessionID: decision.SessionID,
		Timestamp: now, Generation: decision.ConfigGeneration, Reason: decision.ReasonCode,
	})
}

func (service *GateService) removeGateDecisionLocked(id string, record gateDecisionRecord) {
	delete(service.gateDecisions, id)
	if record.node != nil {
		service.gateDecisionOrder.Remove(record.node)
	}
	service.gateDecisionBytes -= record.size
}

func truncateEvidenceText(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end], true
}

// GetRequestDecision exposes a bounded engine-owned record for T27. It never
// includes raw headers, query or body.
func (service *GateService) GetRequestDecision(requestID string) (domain.RequestContext, domain.RequestDecision, bool) {
	if service == nil {
		return domain.RequestContext{}, domain.RequestDecision{}, false
	}
	service.gateMu.Lock()
	defer service.gateMu.Unlock()
	value, ok := service.gateDecisions[requestID]
	if !ok || !time.Now().Before(value.expires) {
		if ok {
			service.removeGateDecisionLocked(requestID, value)
		}
		return domain.RequestContext{}, domain.RequestDecision{}, false
	}
	return value.evidence.Context.Clone(), value.evidence.Decision, true
}

// RequestEvidenceForSession enriches one management detail read. It scans a
// bounded engine-owned store, returns newest first and never changes M2 state.
func (service *GateService) RequestEvidenceForSession(sessionID string, limit int) []domain.RequestGateEvidence {
	if service == nil || sessionID == "" {
		return nil
	}
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	service.gateMu.Lock()
	items := make([]domain.RequestGateEvidence, 0, limit)
	now := time.Now()
	for id, record := range service.gateDecisions {
		if !now.Before(record.expires) {
			service.removeGateDecisionLocked(id, record)
			continue
		}
		if record.evidence.Context.SessionID == sessionID {
			if len(items) < limit {
				items = append(items, record.evidence)
			} else {
				oldest := 0
				for i := 1; i < len(items); i++ {
					if items[i].Sequence < items[oldest].Sequence {
						oldest = i
					}
				}
				if record.evidence.Sequence > items[oldest].Sequence {
					items[oldest] = record.evidence
				}
			}
		}
	}
	service.gateMu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Sequence > items[j].Sequence })
	for i := range items {
		items[i] = items[i].Clone()
	}
	return items
}

func (service *GateService) ListRequestGateEvidence(after uint64, limit int) domain.RequestGateEvidencePage {
	page := domain.RequestGateEvidencePage{NextSequence: after}
	if service == nil {
		return page
	}
	if limit <= 0 || limit > 128 {
		limit = 128
	}
	service.gateMu.Lock()
	items := make([]domain.RequestGateEvidence, 0, limit)
	now := time.Now()
	var matching int
	for id, record := range service.gateDecisions {
		if !now.Before(record.expires) {
			service.removeGateDecisionLocked(id, record)
			continue
		}
		if record.evidence.Sequence > after {
			matching++
			if len(items) < limit {
				items = append(items, record.evidence)
			} else {
				newest := 0
				for i := 1; i < len(items); i++ {
					if items[i].Sequence > items[newest].Sequence {
						newest = i
					}
				}
				if record.evidence.Sequence < items[newest].Sequence {
					items[newest] = record.evidence
				}
			}
		}
	}
	service.gateMu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Sequence < items[j].Sequence })
	page.HasMore = matching > len(items)
	for i := range items {
		items[i] = items[i].Clone()
	}
	page.Items = items
	if len(items) > 0 {
		page.NextSequence = items[len(items)-1].Sequence
	}
	return page
}

// EvaluateRequest reopens the authoritative connectivity gate on every
// request. A stale generation, revoked session or new block can therefore
// supersede the original connection authorization before any upstream write.
func (service *GateService) EvaluateRequest(ctx context.Context, input domain.ProxyRequestEvaluation) (domain.RequestDecision, error) {
	if service == nil || service.Runtime == nil {
		return domain.RequestDecision{}, &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
	}
	if err := ctx.Err(); err != nil {
		return domain.RequestDecision{}, err
	}
	request := input.Context
	if !validGateRequest(request, input.Inspection) {
		return domain.RequestDecision{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return domain.RequestDecision{}, err
	}
	decision := domain.RequestDecision{
		DecisionID: hex.EncodeToString(random[:]), RequestID: request.RequestID,
		Verdict: domain.RequestBlock, Coverage: domain.RequestCoverageUnavailable,
		HTTPStatus: 503, ReasonCode: "GATE_ENGINE_UNAVAILABLE",
	}
	open, exists := service.gateConnection(request.ConnectionID)
	if !exists {
		decision.ConfigGeneration = service.Runtime.CurrentGeneration()
		service.storeGateDecision(request, input.Inspection, decision)
		return decision, nil
	}
	fresh, err := service.OpenConnection(ctx, open)
	if err != nil {
		return domain.RequestDecision{}, err
	}
	decision.ConfigGeneration = fresh.ConfigGeneration
	decision.SessionID, decision.PolicyID, decision.ProfileID = fresh.SessionID, fresh.PolicyID, fresh.ProfileID
	if fresh.Action != domain.TLSGateInspectHTTP && fresh.Action != domain.TLSGateDecrypt || fresh.SessionID != request.SessionID || request.Scheme == "https" && (open.IsTLS == nil || !*open.IsTLS) || request.Scheme == "http" && (open.IsTLS == nil || *open.IsTLS) {
		decision.HTTPStatus = 403
		decision.ReasonCode = "GATE_POLICY_NOT_ALLOWED"
		service.storeGateDecision(request, input.Inspection, decision)
		return decision, nil
	}
	program := service.Runtime.CurrentProgram()
	plan, ok := program.CompiledRequestGateForPolicy(fresh.PolicyID)
	if !ok || !plan.Enabled || plan.Generation != fresh.ConfigGeneration || plan.ProfileID != fresh.ProfileID || !plan.FailMode.Valid() || service.Runtime.CurrentGeneration() != fresh.ConfigGeneration {
		service.storeGateDecision(request, input.Inspection, decision)
		return decision, nil
	}
	if input.Inspection.ErrorCode == "GATE_REQUEST_MALFORMED" {
		decision.Coverage = domain.RequestCoverageUnavailable
		decision.HTTPStatus, decision.ReasonCode = 400, "GATE_REQUEST_MALFORMED"
	} else if input.Inspection.ErrorCode == "GATE_UNSUPPORTED_ENCODING" {
		decision.Coverage = domain.RequestCoverageUnavailable
		decision.HTTPStatus, decision.ReasonCode = 503, "GATE_UNSUPPORTED_ENCODING"
		if plan.FailMode == domain.GateFailOpen && plan.EncodingAction == "ALLOW_PARTIAL" {
			decision.Verdict, decision.HTTPStatus = domain.RequestAllow, 0
		}
	} else if input.Inspection.Completed && (input.Inspection.Coverage == domain.CoverageComplete || input.Inspection.Coverage == domain.RequestCoveragePartial) && input.Inspection.ErrorCode == "" && hasBlockingGateAlert(input.Inspection.Alerts) {
		decision.Coverage = input.Inspection.Coverage
		decision.HTTPStatus, decision.ReasonCode = 403, "GATE_SIGNATURE_BLOCK"
	} else if request.Truncated {
		decision.Coverage = domain.RequestCoveragePartial
		decision.HTTPStatus, decision.ReasonCode = 413, "GATE_REQUEST_TOO_LARGE"
		if plan.FailMode == domain.GateFailOpen && plan.OversizeAction == "ALLOW_PARTIAL" {
			decision.Verdict, decision.HTTPStatus = domain.RequestAllow, 0
		}
	} else {
		decision = decideInspectedRequest(decision, input.Inspection, plan.FailMode)
	}
	if service.Runtime.CurrentGeneration() != fresh.ConfigGeneration {
		decision.Verdict = domain.RequestBlock
		decision.Coverage = domain.RequestCoverageUnavailable
		decision.HTTPStatus = 503
		decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
	}
	service.storeGateDecision(request, input.Inspection, decision)
	return decision, nil
}

func hasBlockingGateAlert(alerts []domain.RequestAlert) bool {
	for _, alert := range alerts {
		switch strings.ToLower(strings.TrimSpace(alert.Action)) {
		case "blocked", "drop", "reject", "deny":
			return true
		}
	}
	return false
}

func validGateRequest(request domain.RequestContext, inspection domain.RequestInspectionResult) bool {
	if len(request.RequestID) != 32 || len(request.ConnectionID) != 32 || request.RequestOrdinal == 0 || request.SessionID != "" && len(request.SessionID) > 128 || len(request.Method) == 0 || len(request.Method) > 32 || len(request.Host) == 0 || len(request.Host) > 255 || len(request.Path) > 16<<10 || request.HeaderBytes < 0 || request.HeaderBytes > 64<<10 || request.BodyBytes < 0 || request.BodyBytes > 1<<20 || request.DecodedBodyBytes < 0 || request.DecodedBodyBytes > 4<<20 || len(inspection.Alerts) > 128 || inspection.RequestID != request.RequestID || !inspection.Coverage.Valid() {
		return false
	}
	if _, err := hex.DecodeString(request.RequestID); err != nil {
		return false
	}
	if _, err := hex.DecodeString(request.ConnectionID); err != nil {
		return false
	}
	if request.Scheme != "http" && request.Scheme != "https" || request.HTTPVersion != "HTTP/1.1" && request.HTTPVersion != "HTTP/2.0" {
		return false
	}
	if len(inspection.ErrorCode) > 64 || len(inspection.RulesetID) > 128 || len(inspection.RulesetHash) > 128 {
		return false
	}
	for _, alert := range inspection.Alerts {
		if len(alert.SignatureID) > 32 || len(alert.Category) > 128 || len(alert.Message) > 512 || len(alert.Action) > 32 || len(alert.Severity) > 16 || len(alert.Timestamp) > 64 {
			return false
		}
	}
	return true
}

func decideInspectedRequest(base domain.RequestDecision, inspection domain.RequestInspectionResult, failMode domain.GateFailMode) domain.RequestDecision {
	base.Coverage = inspection.Coverage
	if inspection.Completed && inspection.Coverage == domain.CoverageComplete && inspection.ErrorCode == "" {
		for _, alert := range inspection.Alerts {
			switch strings.ToLower(strings.TrimSpace(alert.Action)) {
			case "blocked", "drop", "reject", "deny":
				base.Verdict, base.HTTPStatus, base.ReasonCode = domain.RequestBlock, 403, "GATE_SIGNATURE_BLOCK"
				return base
			case "allowed", "pass", "alert":
				// An alert action is evidence, not itself the proxy verdict.
			default:
				base.Coverage = domain.RequestCoverageUnavailable
				base.ReasonCode = "GATE_SENSOR_UNAVAILABLE"
				return applyGateFailure(base, failMode)
			}
		}
		base.Verdict, base.HTTPStatus, base.ReasonCode = domain.RequestAllow, 0, "GATE_INSPECTION_COMPLETE"
		return base
	}
	if inspection.Coverage == domain.CoverageComplete {
		base.Coverage = domain.RequestCoverageUnavailable
	}
	base.ReasonCode = stableInspectionFailure(inspection.ErrorCode)
	return applyGateFailure(base, failMode)
}

func applyGateFailure(decision domain.RequestDecision, mode domain.GateFailMode) domain.RequestDecision {
	if mode == domain.GateFailOpen {
		decision.Verdict, decision.HTTPStatus = domain.RequestAllow, 0
	} else {
		decision.Verdict, decision.HTTPStatus = domain.RequestBlock, 503
	}
	return decision
}

func stableInspectionFailure(code string) string {
	switch code {
	case "GATE_QUEUE_FULL", "GATE_INSPECTION_TIMEOUT", "GATE_SENSOR_UNAVAILABLE", "GATE_UNSUPPORTED_ENCODING", "GATE_DECOMPRESSION_LIMIT", "GATE_EVE_MALFORMED", "GATE_EVE_INCOMPLETE", "GATE_EVE_MISMATCH":
		return code
	default:
		return "GATE_SENSOR_UNAVAILABLE"
	}
}
