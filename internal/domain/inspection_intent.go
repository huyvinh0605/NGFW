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
