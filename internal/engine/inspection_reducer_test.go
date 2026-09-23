package engine

import (
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestEvaluateAppRestrictionDecisionTable(t *testing.T) {
	selection := connectivity.InspectionSelection{Mode: domain.InspectionModeIPS, AllowedApps: []string{"HTTP"}}
	now := time.Now().UTC()
	deadline := now.Add(-time.Second)
	cases := []struct {
		name     string
		app      domain.ApplicationIdentity
		deadline *time.Time
		want     domain.AppPolicyState
	}{
		{"unknown-pending", domain.UnknownApplication(), nil, domain.AppPolicyPending},
		{"unknown-timeout", domain.UnknownApplication(), &deadline, domain.AppPolicyUnknownAllowed},
		{"matched", domain.ApplicationIdentity{Name: "HTTP", Confidence: domain.ApplicationConfidenceHigh}, nil, domain.AppPolicyMatched},
		{"mismatch", domain.ApplicationIdentity{Name: "TLS", Confidence: domain.ApplicationConfidenceHigh}, nil, domain.AppPolicyMismatch},
		{"weak", domain.ApplicationIdentity{Name: "TLS", Confidence: domain.ApplicationConfidenceLow}, nil, domain.AppPolicyPending},
		{"conflict", domain.ApplicationIdentity{Name: "TLS", Confidence: domain.ApplicationConfidenceHigh, Conflicted: true}, nil, domain.AppPolicyUnknownAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := EvaluateAppRestriction(selection, tc.app, tc.deadline, now)
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestReduceInspectionOnlyIPSStrongMismatchCreatesGuard(t *testing.T) {
	now := time.Now().UTC()
	obs := inspection.Observation{ID: "o1", ObservedAt: &now, IngestedAt: now, Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "e1", Mode: domain.InspectionModeIPS}, App: domain.ApplicationIdentity{Name: "TLS", Source: domain.ApplicationSourceSuricataAppProto, Confidence: domain.ApplicationConfidenceHigh}}
	session := domain.RuntimeSession{SessionID: "s1", Identity: domain.ConntrackIdentity{BootID: "b", ID: 1}, Decision: domain.DecisionAllow}
	selection := connectivity.InspectionSelection{PolicyID: "p1", ProfileID: "ips", Mode: domain.InspectionModeIPS, AllowedApps: []string{"HTTP"}, Generation: 2}
	result := ReduceInspection(session, selection, obs, now)
	if result.Next.AppPolicyState != domain.AppPolicyMismatch || len(result.Intents) != 1 || result.Next.Enforcement.Status != domain.EnforcementPending {
		t.Fatalf("guard not requested: %#v", result)
	}
	selection.Mode = domain.InspectionModeIDS
	result = ReduceInspection(session, selection, obs, now)
	if len(result.Intents) != 0 {
		t.Fatal("IDS produced a guard intent")
	}
}

func TestThreatVerdictDoesNotTurnPacketDropIntoSessionDrop(t *testing.T) {
	now := time.Now().UTC()
	rawSeverity := 1
	verdict := "drop"
	obs := inspection.Observation{ID: "alert1", ObservedAt: &now, IngestedAt: now, Source: inspection.SourcePosition{SensorID: "ips", Mode: domain.InspectionModeIPS}, Alert: &inspection.AlertObservation{Severity: &rawSeverity, PacketVerdict: &verdict}}
	session := domain.RuntimeSession{SessionID: "s1", Decision: domain.DecisionAllow}
	selection := connectivity.InspectionSelection{Mode: domain.InspectionModeIPS, Generation: 1}
	result := ReduceInspection(session, selection, obs, now)
	if result.Threat == nil || result.Threat.Enforcement.Status != domain.EnforcementReported || ComputeEffectiveDecision(session.Decision, &result.Next, false) != domain.DecisionAllow {
		t.Fatalf("packet/session verdict conflated: %#v", result)
	}
}

func TestReduceInspectionUsesConfiguredApplicationDeadline(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	selection := connectivity.InspectionSelection{PolicyID: "p", Mode: domain.InspectionModeIPS, AllowedApps: []string{"HTTP"}, AppDetectionTimeoutMillis: 1200, Generation: 1}
	result := ReduceInspection(domain.RuntimeSession{SessionID: "s"}, selection, inspection.Observation{ID: "o", IngestedAt: now}, now)
	if result.Next.AppDeadline == nil || !result.Next.AppDeadline.Equal(now.Add(1200*time.Millisecond)) {
		t.Fatalf("application deadline=%v", result.Next.AppDeadline)
	}
}
