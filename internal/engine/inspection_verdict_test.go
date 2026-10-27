package engine

import (
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestThreatEvidenceKeepsSignaturePacketAndSessionActionsSeparate(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     domain.InspectionMode
		action   string
		packet   string
		want     domain.LatestVerdict
		reported bool
	}{
		{"IDS alert", domain.InspectionModeIDS, "allowed", "", domain.VerdictAlert, false},
		{"IDS unexpected blocked", domain.InspectionModeIDS, "blocked", "", domain.VerdictUnknown, false},
		{"IDS unexpected drop", domain.InspectionModeIDS, "allowed", "drop", domain.VerdictUnknown, false},
		{"IPS no verdict", domain.InspectionModeIPS, "allowed", "", domain.VerdictAlert, false},
		{"IPS final drop", domain.InspectionModeIPS, "allowed", "drop", domain.VerdictDrop, true},
		{"IPS signature blocked", domain.InspectionModeIPS, "blocked", "", domain.VerdictDrop, true},
		{"IPS final accept wins", domain.InspectionModeIPS, "blocked", "accept", domain.VerdictAlert, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			alert := &inspection.AlertObservation{SignatureAction: test.action}
			if test.packet != "" {
				alert.PacketVerdict = &test.packet
			}
			observation := inspection.Observation{ID: "physical-alert", Source: inspection.SourcePosition{SensorID: "sensor", Mode: test.mode}, Alert: alert, ObservedAt: &now, IngestedAt: now}
			current := domain.RuntimeSession{SessionID: "session", Decision: domain.DecisionAllow}
			// The source's actual capture mode governs a historical packet
			// report even if the current policy now selects another mode.
			selection := connectivity.InspectionSelection{Mode: domain.InspectionModeIPS, Generation: 1}
			result := ReduceInspection(current, selection, observation, now)
			if result.Threat == nil || result.Threat.Verdict != test.want || result.Threat.PacketVerdict != test.packet || result.Threat.SignatureAction != test.action {
				t.Fatalf("raw/derived evidence lost: %#v", result.Threat)
			}
			enforcement := result.Threat.Enforcement
			if test.reported {
				if enforcement.Status != domain.EnforcementReported || enforcement.Scope != domain.EnforcementScopePacket || enforcement.Mechanism != domain.EnforcementSuricataNFQueue || enforcement.Reason == "" {
					t.Fatalf("packet report incorrect: %#v", enforcement)
				}
			} else if enforcement.Status != domain.EnforcementNotRequested || enforcement.Mechanism != domain.EnforcementNone {
				t.Fatalf("unexpected enforcement: %#v", enforcement)
			}
			if len(result.Intents) != 0 || ComputeEffectiveDecision(current.Decision, &result.Next, false) != domain.DecisionAllow {
				t.Fatal("detector packet report changed session connectivity")
			}
		})
	}
}
