package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

type InspectionReduction struct {
	Next          domain.SessionInspection
	Threat        *domain.ThreatEvent
	Intents       []domain.InspectionIntent
	Notifications []domain.RuntimeEvent
}

func ReduceInspection(current domain.RuntimeSession, selection connectivity.InspectionSelection, obs inspection.Observation, now time.Time) InspectionReduction {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	next := domain.DefaultSessionInspection()
	if current.Inspection != nil {
		next = current.Inspection.Clone()
	}
	next.Generation = selection.Generation
	next.ProfileID = selection.ProfileID
	next.Mode = selection.Mode
	if selection.Mode == domain.InspectionModeOff {
		next.State, next.Coverage, next.AppPolicyState, next.Reason = domain.InspectionStateNotRequested, domain.CoverageNone, domain.AppPolicyNotApplicable, "policy does not select inspection"
		return InspectionReduction{Next: next}
	}
	next.State = domain.InspectionStateInspecting
	if obs.ID != "" {
		next.Coverage = domain.CoverageObserved
		if next.FirstObservedAt == nil {
			observed := obs.IngestedAt
			if obs.ObservedAt != nil {
				observed = *obs.ObservedAt
			}
			next.FirstObservedAt = timePtr(observed)
		}
		observed := obs.IngestedAt
		if obs.ObservedAt != nil {
			observed = *obs.ObservedAt
		}
		next.LastObservedAt = timePtr(observed)
		next.Sources = boundedStrings(next.Sources, obs.Source.SensorID+":"+obs.Source.SensorEpoch, 2)
	}
	identity := inspection.ApplicationFromObservation(obs)
	identity.EvidenceID = obs.ID
	if identity.Name != "UNKNOWN" {
		next.Application = inspection.MergeApplication(next.Application, identity)
	} else {
		next.Application = next.Application.NormalizeZero()
	}
	if obs.Alert != nil && !obs.Alert.InternalDiscovery {
		threat := ThreatFromObservation(obs, current, selection)
		if next.LastEventID != threat.EventID {
			next.ThreatCount++
			next.LastEventID = threat.EventID
			next.MaxSeverity = maxThreatSeverity(next.MaxSeverity, threat.Severity)
			next.LatestVerdict = threat.Verdict
			next.Enforcement = threat.Enforcement
		}
	}
	state, reason := EvaluateAppRestriction(selection, next.Application, next.AppDeadline, now)
	next.AppPolicyState, next.Reason = state, reason
	if len(selection.AllowedApps) > 0 && next.AppDeadline == nil {
		timeout := time.Duration(selection.AppDetectionTimeoutMillis) * time.Millisecond
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		deadline := now.Add(timeout)
		next.AppDeadline = &deadline
	}
	result := InspectionReduction{Next: next}
	if obs.Alert != nil && !obs.Alert.InternalDiscovery {
		threat := ThreatFromObservation(obs, current, selection)
		result.Threat = &threat
		result.Notifications = append(result.Notifications, domain.RuntimeEvent{Kind: domain.EventSecurityAlert, Class: domain.EventClassSecurity, SessionID: current.SessionID, EventID: threat.EventID, Generation: selection.Generation, Timestamp: now})
	}
	guardInFlightOrApplied := next.Enforcement.Mechanism == domain.EnforcementNFTSessionGuard && next.Enforcement.RequestedAction == domain.DecisionDrop && (next.Enforcement.Status == domain.EnforcementPending || next.Enforcement.Status == domain.EnforcementApplied)
	if state == domain.AppPolicyMismatch && selection.Mode == domain.InspectionModeIPS && !next.Application.Conflicted && strongApplication(next.Application) && !guardInFlightOrApplied {
		next.Enforcement = domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: domain.DecisionDrop, Status: domain.EnforcementPending, Reason: reason, OperationID: fmt.Sprintf("app-guard-%s-%d", current.SessionID, next.Revision+1)}
		result.Next = next
		result.Intents = append(result.Intents, domain.InspectionIntent{Kind: domain.IntentInstallAppGuard, OperationID: next.Enforcement.OperationID, SessionID: current.SessionID, Identity: current.Identity, Generation: selection.Generation, ExpectedInspectionRevision: next.Revision + 1, RequestedAction: domain.DecisionDrop, Owner: "APP_POLICY", Reason: reason})
	}
	if current.Inspection == nil || current.Inspection.Application.Name != next.Application.Name {
		result.Notifications = append(result.Notifications, domain.RuntimeEvent{Kind: domain.EventApplicationIdentified, Class: domain.EventClassInspection, SessionID: current.SessionID, Generation: selection.Generation, Timestamp: now})
	}
	return result
}

func EvaluateAppRestriction(selection connectivity.InspectionSelection, app domain.ApplicationIdentity, deadline *time.Time, now time.Time) (domain.AppPolicyState, string) {
	if len(selection.AllowedApps) == 0 {
		return domain.AppPolicyNotApplicable, "policy has no application restriction"
	}
	app = app.NormalizeZero()
	if app.Conflicted {
		return domain.AppPolicyUnknownAllowed, "application evidence conflicts; fail-open"
	}
	if app.Name == "UNKNOWN" || !strongApplication(app) {
		if deadline != nil && !now.Before(*deadline) {
			return domain.AppPolicyUnknownAllowed, "application detection timeout; fail-open"
		}
		return domain.AppPolicyPending, "waiting for strong application evidence"
	}
	for _, allowed := range selection.AllowedApps {
		if strings.EqualFold(strings.TrimSpace(allowed), app.Name) {
			return domain.AppPolicyMatched, "application is allowed by policy"
		}
	}
	return domain.AppPolicyMismatch, "application is not allowed by policy"
}

func ComputeEffectiveDecision(base domain.Decision, inspectionState *domain.SessionInspection, revoked bool) domain.Decision {
	if revoked {
		return domain.DecisionDrop
	}
	if inspectionState != nil && inspectionState.Enforcement.Mechanism == domain.EnforcementNFTSessionGuard && inspectionState.Enforcement.Status == domain.EnforcementApplied && inspectionState.Enforcement.RequestedAction == domain.DecisionDrop {
		return domain.DecisionDrop
	}
	return base
}

func ThreatFromObservation(obs inspection.Observation, session domain.RuntimeSession, selection connectivity.InspectionSelection) domain.ThreatEvent {
	event := domain.ThreatEvent{EventID: obs.ID, ObservedAt: cloneTime(obs.ObservedAt), IngestedAt: obs.IngestedAt, EventClass: "security", Source: "SURICATA", SensorID: obs.Source.SensorID, SensorEpoch: obs.Source.SensorEpoch, SensorConfigHash: obs.Source.SensorConfigHash, RulesetID: obs.Source.RulesetID, CaptureMode: obs.Source.Mode, ObservedTuple: cloneDomainTuple(obs.Tuple), FlowTuple: cloneDomainTuple(obs.FlowTuple), SessionID: session.SessionID, PolicyID: selection.PolicyID, PolicyGeneration: selection.Generation, CorrelationState: domain.CorrelationCorrelated, CorrelationReason: "runtime session resolved", Application: inspection.ApplicationFromObservation(obs), Severity: domain.SeverityUnknown, Verdict: domain.VerdictAlert, Enforcement: domain.EnforcementResult{Mechanism: domain.EnforcementNone, Scope: domain.EnforcementScopePacket, Status: domain.EnforcementNotRequested}}
	if obs.HasFlowID {
		event.SuricataFlowID = fmt.Sprint(obs.FlowID)
	}
	if obs.TransactionID != nil {
		value := fmt.Sprint(*obs.TransactionID)
		event.TransactionID = &value
	}
	if obs.Tuple != nil {
		event.ProtocolRaw = fmt.Sprint(obs.Tuple.Protocol)
	}
	if obs.Alert != nil {
		event.SignatureID, event.SignatureRevision, event.Signature, event.Category, event.SourceSeverity, event.SignatureAction = obs.Alert.SignatureID, obs.Alert.SignatureRevision, obs.Alert.Signature, obs.Alert.Category, cloneIntPtr(obs.Alert.Severity), obs.Alert.SignatureAction
		if obs.Alert.PacketVerdict != nil {
			event.PacketVerdict = *obs.Alert.PacketVerdict
		}
		event.Severity = mapSuricataSeverity(obs.Alert.Severity)
		if strings.EqualFold(event.PacketVerdict, "drop") || strings.EqualFold(event.PacketVerdict, "blocked") {
			event.Verdict = domain.VerdictDrop
			if selection.Mode == domain.InspectionModeIPS {
				event.Enforcement = domain.EnforcementResult{Mechanism: domain.EnforcementSuricataNFQueue, Scope: domain.EnforcementScopePacket, RequestedAction: domain.DecisionDrop, Status: domain.EnforcementReported, Reason: "packet verdict reported by Suricata", ObservedAt: cloneTime(obs.ObservedAt)}
			}
		}
	}
	return event
}

func strongApplication(app domain.ApplicationIdentity) bool {
	if app.Conflicted || app.Source == domain.ApplicationSourcePortHeuristic {
		return false
	}
	return app.Confidence == domain.ApplicationConfidenceHigh || app.Confidence == domain.ApplicationConfidenceVerified
}
func mapSuricataSeverity(raw *int) domain.Severity {
	if raw == nil {
		return domain.SeverityUnknown
	}
	switch *raw {
	case 1:
		return domain.SeverityHigh
	case 2:
		return domain.SeverityMedium
	case 3:
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}
func maxThreatSeverity(a, b domain.Severity) domain.Severity {
	rank := func(v domain.Severity) int {
		switch v {
		case domain.SeverityHigh, domain.SeverityCritical:
			return 3
		case domain.SeverityMedium:
			return 2
		case domain.SeverityLow:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}
func boundedStrings(values []string, value string, max int) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, max)
	for _, item := range append(append([]string(nil), values...), value) {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	if len(result) > max {
		result = result[:max]
	}
	return result
}
func timePtr(value time.Time) *time.Time { value = value.UTC(); return &value }
func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
func cloneDomainTuple(value *domain.Tuple) *domain.Tuple {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
func cloneIntPtr(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
