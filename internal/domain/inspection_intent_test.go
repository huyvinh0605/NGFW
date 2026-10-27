package domain

import (
	"net/netip"
	"testing"
)

func TestGuardIntentMetadataAdvanceRetainsSafetyFences(t *testing.T) {
	identity := ConntrackIdentity{BootID: "boot", NetworkNS: "lab", Zone: 1, Family: FamilyIPv4, ID: 99, KernelStart: 123,
		Original: Tuple{Family: FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 40000, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 22, Protocol: 6}}
	intent := InspectionIntent{Kind: IntentInstallAppGuard, SessionID: "session", Identity: identity, Generation: 7, ExpectedInspectionRevision: 2, OperationID: "guard-operation", RequestedAction: DecisionDrop}
	base := RuntimeSession{SessionID: "session", Identity: identity, PolicyGeneration: 7, Inspection: &SessionInspection{Generation: 7, Revision: 3, Mode: InspectionModeIPS, AppPolicyState: AppPolicyMismatch,
		Application: ApplicationIdentity{Name: "SSH", Source: ApplicationSourceSuricataAppProto, Confidence: ApplicationConfidenceHigh},
		Enforcement: EnforcementResult{Mechanism: EnforcementNFTSessionGuard, RequestedAction: DecisionDrop, Status: EnforcementPending, OperationID: "guard-operation"}}}
	if !intent.MatchesSession(base, 7) {
		t.Fatal("metadata-only advance invalidated the pending operation")
	}
	for _, test := range []struct {
		name string
		edit func(*RuntimeSession)
	}{
		{"reused kernel ID", func(s *RuntimeSession) { s.Identity.ID++ }},
		{"reused start", func(s *RuntimeSession) { s.Identity.KernelStart++ }},
		{"new boot", func(s *RuntimeSession) { s.Identity.BootID = "new" }},
		{"new zone", func(s *RuntimeSession) { s.Identity.Zone++ }},
		{"new tuple", func(s *RuntimeSession) { s.Identity.Original.SrcPort++ }},
		{"new operation", func(s *RuntimeSession) { s.Inspection.Enforcement.OperationID = "new" }},
		{"new generation", func(s *RuntimeSession) { s.Inspection.Generation++ }},
		{"old snapshot", func(s *RuntimeSession) { s.Inspection.Revision = 1 }},
		{"no longer forbidden", func(s *RuntimeSession) { s.Inspection.AppPolicyState = AppPolicyMatched }},
		{"IDS", func(s *RuntimeSession) { s.Inspection.Mode = InspectionModeIDS }},
		{"weak evidence", func(s *RuntimeSession) { s.Inspection.Application.Confidence = ApplicationConfidenceLow }},
		{"conflicting evidence", func(s *RuntimeSession) { s.Inspection.Application.Conflicted = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := base.Clone()
			test.edit(&changed)
			if intent.MatchesSession(changed, 7) {
				t.Fatal("stale or unsupported guard intent accepted")
			}
		})
	}
	if intent.MatchesSession(base, 8) {
		t.Fatal("new running generation accepted old work")
	}
}
