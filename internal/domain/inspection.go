package domain

import "time"

// ApplicationSource identifies the component that produced an application
// identity. UNKNOWN is explicit: an absent observation is never interpreted
// as a verified application.
type ApplicationSource string

const (
	ApplicationSourceUnknown          ApplicationSource = "UNKNOWN"
	ApplicationSourceSuricataAppProto ApplicationSource = "SURICATA_APP_PROTO"
	ApplicationSourceDPIParser        ApplicationSource = "DPI_PARSER"
	ApplicationSourceTLSMetadata      ApplicationSource = "TLS_METADATA"
	ApplicationSourcePortHeuristic    ApplicationSource = "PORT_HEURISTIC"
)

func (s ApplicationSource) Valid() bool {
	switch s {
	case ApplicationSourceUnknown, ApplicationSourceSuricataAppProto, ApplicationSourceDPIParser, ApplicationSourceTLSMetadata, ApplicationSourcePortHeuristic:
		return true
	default:
		return false
	}
}

type ApplicationConfidence string

const (
	ApplicationConfidenceUnknown  ApplicationConfidence = "UNKNOWN"
	ApplicationConfidenceLow      ApplicationConfidence = "LOW"
	ApplicationConfidenceMedium   ApplicationConfidence = "MEDIUM"
	ApplicationConfidenceHigh     ApplicationConfidence = "HIGH"
	ApplicationConfidenceVerified ApplicationConfidence = "VERIFIED"
)

func (c ApplicationConfidence) Valid() bool {
	switch c {
	case ApplicationConfidenceUnknown, ApplicationConfidenceLow, ApplicationConfidenceMedium, ApplicationConfidenceHigh, ApplicationConfidenceVerified:
		return true
	default:
		return false
	}
}

type InspectionMode string

const (
	InspectionModeOff InspectionMode = "OFF"
	InspectionModeIDS InspectionMode = "IDS"
	InspectionModeIPS InspectionMode = "IPS"
)

func (m InspectionMode) Valid() bool {
	return m == InspectionModeOff || m == InspectionModeIDS || m == InspectionModeIPS
}

type InspectionState string

const (
	InspectionStateNotRequested InspectionState = "NOT_REQUESTED"
	InspectionStateQueued       InspectionState = "QUEUED"
	InspectionStateInspecting   InspectionState = "INSPECTING"
	InspectionStateDegraded     InspectionState = "DEGRADED"
	InspectionStateError        InspectionState = "ERROR"
	InspectionStateComplete     InspectionState = "COMPLETE"
)

func (s InspectionState) Valid() bool {
	switch s {
	case InspectionStateNotRequested, InspectionStateQueued, InspectionStateInspecting, InspectionStateDegraded, InspectionStateError, InspectionStateComplete:
		return true
	default:
		return false
	}
}

type CoverageState string

const (
	CoverageNone        CoverageState = "NONE"
	CoverageObserved    CoverageState = "OBSERVED"
	CoveragePartial     CoverageState = "PARTIAL"
	CoverageUnavailable CoverageState = "UNAVAILABLE"
)

func (s CoverageState) Valid() bool {
	return s == CoverageNone || s == CoverageObserved || s == CoveragePartial || s == CoverageUnavailable
}

type AppPolicyState string

const (
	AppPolicyNotApplicable  AppPolicyState = "NOT_APPLICABLE"
	AppPolicyPending        AppPolicyState = "PENDING"
	AppPolicyMatched        AppPolicyState = "MATCHED"
	AppPolicyMismatch       AppPolicyState = "MISMATCH"
	AppPolicyUnknownAllowed AppPolicyState = "UNKNOWN_ALLOWED"
)

func (s AppPolicyState) Valid() bool {
	switch s {
	case AppPolicyNotApplicable, AppPolicyPending, AppPolicyMatched, AppPolicyMismatch, AppPolicyUnknownAllowed:
		return true
	default:
		return false
	}
}

type CorrelationState string

const (
	CorrelationCorrelated   CorrelationState = "CORRELATED"
	CorrelationUncorrelated CorrelationState = "UNCORRELATED"
	CorrelationAmbiguous    CorrelationState = "AMBIGUOUS"
)

func (s CorrelationState) Valid() bool {
	return s == CorrelationCorrelated || s == CorrelationUncorrelated || s == CorrelationAmbiguous
}

type EnforcementMechanism string

const (
	EnforcementNone            EnforcementMechanism = "NONE"
	EnforcementSuricataNFQueue EnforcementMechanism = "SURICATA_NFQUEUE"
	EnforcementNFTSessionGuard EnforcementMechanism = "NFT_SESSION_GUARD"
)

func (m EnforcementMechanism) Valid() bool {
	return m == EnforcementNone || m == EnforcementSuricataNFQueue || m == EnforcementNFTSessionGuard
}

type EnforcementScope string

const (
	EnforcementScopePacket  EnforcementScope = "PACKET"
	EnforcementScopeSession EnforcementScope = "SESSION"
)

func (s EnforcementScope) Valid() bool {
	return s == EnforcementScopePacket || s == EnforcementScopeSession
}

type EnforcementStatus string

const (
	EnforcementNotRequested EnforcementStatus = "NOT_REQUESTED"
	EnforcementPending      EnforcementStatus = "PENDING"
	EnforcementReported     EnforcementStatus = "REPORTED"
	EnforcementApplied      EnforcementStatus = "APPLIED"
	EnforcementFailed       EnforcementStatus = "FAILED"
	EnforcementUnavailable  EnforcementStatus = "UNAVAILABLE"
)

func (s EnforcementStatus) Valid() bool {
	switch s {
	case EnforcementNotRequested, EnforcementPending, EnforcementReported, EnforcementApplied, EnforcementFailed, EnforcementUnavailable:
		return true
	default:
		return false
	}
}

type LatestVerdict string

const (
	VerdictUnknown LatestVerdict = "UNKNOWN"
	VerdictAlert   LatestVerdict = "ALERT"
	VerdictDrop    LatestVerdict = "DROP"
	VerdictError   LatestVerdict = "ERROR"
)

func (v LatestVerdict) Valid() bool {
	return v == VerdictUnknown || v == VerdictAlert || v == VerdictDrop || v == VerdictError
}

type ApplicationIdentity struct {
	Name       string                `json:"name"`
	RawName    string                `json:"raw_name,omitempty"`
	Source     ApplicationSource     `json:"source"`
	Confidence ApplicationConfidence `json:"confidence"`
	FirstSeen  *time.Time            `json:"first_seen,omitempty"`
	LastSeen   *time.Time            `json:"last_seen,omitempty"`
	Revision   uint64                `json:"revision"`
	Conflicted bool                  `json:"conflicted"`
	EvidenceID string                `json:"evidence_id,omitempty"`
}

func (a ApplicationIdentity) Clone() ApplicationIdentity {
	c := a
	if a.FirstSeen != nil {
		v := *a.FirstSeen
		c.FirstSeen = &v
	}
	if a.LastSeen != nil {
		v := *a.LastSeen
		c.LastSeen = &v
	}
	return c
}

func UnknownApplication() ApplicationIdentity {
	return ApplicationIdentity{Name: "UNKNOWN", Source: ApplicationSourceUnknown, Confidence: ApplicationConfidenceUnknown}
}

func (a ApplicationIdentity) NormalizeZero() ApplicationIdentity {
	if a.Name == "" {
		a.Name = "UNKNOWN"
	}
	if a.Source == "" {
		a.Source = ApplicationSourceUnknown
	}
	if a.Confidence == "" {
		a.Confidence = ApplicationConfidenceUnknown
	}
	return a
}

type EnforcementResult struct {
	Mechanism       EnforcementMechanism `json:"mechanism"`
	Scope           EnforcementScope     `json:"scope"`
	RequestedAction Decision             `json:"requested_action,omitempty"`
	Status          EnforcementStatus    `json:"status"`
	Reason          string               `json:"reason,omitempty"`
	ObservedAt      *time.Time           `json:"observed_at,omitempty"`
	OperationID     string               `json:"operation_id,omitempty"`
}

type SessionInspection struct {
	Generation      uint64              `json:"generation"`
	Revision        uint64              `json:"revision"`
	ProfileID       string              `json:"profile_id,omitempty"`
	Mode            InspectionMode      `json:"mode"`
	State           InspectionState     `json:"state"`
	Reason          string              `json:"reason,omitempty"`
	Coverage        CoverageState       `json:"coverage"`
	Application     ApplicationIdentity `json:"application"`
	AppPolicyState  AppPolicyState      `json:"app_policy_state"`
	AppDeadline     *time.Time          `json:"app_deadline,omitempty"`
	ThreatCount     uint64              `json:"threat_count"`
	LastEventID     string              `json:"last_event_id,omitempty"`
	MaxSeverity     Severity            `json:"max_severity,omitempty"`
	LatestVerdict   LatestVerdict       `json:"latest_verdict"`
	Enforcement     EnforcementResult   `json:"enforcement"`
	Sources         []string            `json:"sources,omitempty"`
	FirstObservedAt *time.Time          `json:"first_observed_at,omitempty"`
	LastObservedAt  *time.Time          `json:"last_observed_at,omitempty"`
	MissingEvidence []string            `json:"missing_evidence,omitempty"`
}

func (s SessionInspection) Clone() SessionInspection {
	c := s
	c.Application = s.Application.Clone()
	c.Sources = append([]string(nil), s.Sources...)
	c.MissingEvidence = append([]string(nil), s.MissingEvidence...)
	if s.AppDeadline != nil {
		v := *s.AppDeadline
		c.AppDeadline = &v
	}
	if s.FirstObservedAt != nil {
		v := *s.FirstObservedAt
		c.FirstObservedAt = &v
	}
	if s.LastObservedAt != nil {
		v := *s.LastObservedAt
		c.LastObservedAt = &v
	}
	if s.Enforcement.ObservedAt != nil {
		v := *s.Enforcement.ObservedAt
		c.Enforcement.ObservedAt = &v
	}
	return c
}

func DefaultSessionInspection() SessionInspection {
	return SessionInspection{
		Mode: InspectionModeOff, State: InspectionStateNotRequested,
		Coverage: CoverageNone, Application: UnknownApplication(),
		AppPolicyState: AppPolicyNotApplicable, LatestVerdict: VerdictUnknown,
		MaxSeverity: SeverityUnknown,
		Enforcement: EnforcementResult{Mechanism: EnforcementNone, Scope: EnforcementScopePacket, Status: EnforcementNotRequested},
	}
}
