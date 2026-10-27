package domain

type InspectionIntentKind string

const (
	IntentInstallAppGuard InspectionIntentKind = "INSTALL_APP_GUARD"
	IntentRenewAppGuard   InspectionIntentKind = "RENEW_APP_GUARD"
	IntentRemoveAppGuard  InspectionIntentKind = "REMOVE_APP_GUARD"
)

type InspectionIntent struct {
	Kind                       InspectionIntentKind `json:"kind"`
	OperationID                string               `json:"operation_id"`
	SessionID                  string               `json:"session_id"`
	Identity                   ConntrackIdentity    `json:"identity"`
	Generation                 uint64               `json:"generation"`
	ExpectedInspectionRevision uint64               `json:"expected_inspection_revision"`
	RequestedAction            Decision             `json:"requested_action"`
	Owner                      string               `json:"owner"`
	Reason                     string               `json:"reason"`
}

// MatchesSession fences kernel work to one incarnation and policy generation.
// Additional metadata may advance the inspection revision while the same
// pending install operation remains valid; a new operation or changed app
// decision must still invalidate it.
func (i InspectionIntent) MatchesSession(current RuntimeSession, generation uint64) bool {
	a, b := current.Identity, i.Identity
	if current.SessionID != i.SessionID || a.BootID != b.BootID || a.NetworkNS != b.NetworkNS || a.Zone != b.Zone || a.Family != b.Family || a.ID != b.ID || a.KernelStart != b.KernelStart || a.Original != b.Original || generation != i.Generation || current.Inspection == nil {
		return false
	}
	inspection := current.Inspection
	if inspection.Generation != i.Generation || inspection.Revision < i.ExpectedInspectionRevision {
		return false
	}
	if i.Kind == IntentInstallAppGuard {
		enforcement := inspection.Enforcement
		app := inspection.Application
		strong := !app.Conflicted && app.Source != ApplicationSourcePortHeuristic && (app.Confidence == ApplicationConfidenceHigh || app.Confidence == ApplicationConfidenceVerified)
		return inspection.Mode == InspectionModeIPS && inspection.AppPolicyState == AppPolicyMismatch && strong &&
			i.OperationID != "" && enforcement.OperationID == i.OperationID && enforcement.Mechanism == EnforcementNFTSessionGuard && enforcement.RequestedAction == DecisionDrop && enforcement.Status == EnforcementPending
	}
	return inspection.Revision == i.ExpectedInspectionRevision
}
