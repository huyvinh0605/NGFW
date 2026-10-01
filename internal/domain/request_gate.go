package domain

import "time"

// M4 request-gate contracts. Zero values remain unknown, never allowed.
type GateFailMode string

const (
	GateFailOpen  GateFailMode = "OPEN"
	GateFailClose GateFailMode = "CLOSE"
)

func (m GateFailMode) Valid() bool { return m == GateFailOpen || m == GateFailClose }

type TLSGateAction string

const (
	TLSGateBypass       TLSGateAction = "BYPASS"
	TLSGateMetadataOnly TLSGateAction = "METADATA_ONLY"
	TLSGateDecrypt      TLSGateAction = "DECRYPT"
	TLSGateInspectHTTP  TLSGateAction = "INSPECT_HTTP"
	TLSGateBlock        TLSGateAction = "BLOCK"
)

func (a TLSGateAction) Valid() bool {
	return a == TLSGateBypass || a == TLSGateMetadataOnly || a == TLSGateDecrypt || a == TLSGateInspectHTTP || a == TLSGateBlock
}

type RequestVerdict string

const (
	RequestAllow       RequestVerdict = "ALLOW"
	RequestBlock       RequestVerdict = "BLOCK"
	RequestUnavailable RequestVerdict = "UNAVAILABLE"
)

func (v RequestVerdict) Valid() bool {
	return v == RequestAllow || v == RequestBlock || v == RequestUnavailable
}

type RequestCoverage string

const (
	CoverageComplete           RequestCoverage = "COMPLETE"
	RequestCoveragePartial     RequestCoverage = "PARTIAL"
	RequestCoverageUnavailable RequestCoverage = "UNAVAILABLE"
	CoverageNotRequested       RequestCoverage = "NOT_REQUESTED"
)

func (c RequestCoverage) Valid() bool {
	return c == CoverageComplete || c == RequestCoveragePartial || c == RequestCoverageUnavailable || c == CoverageNotRequested
}

type ProxyConnectionOpen struct {
	ConnectionID string `json:"connection_id"`
	SourceIP     string `json:"source_ip"`
	SourcePort   int    `json:"source_port"`
	OriginalIP   string `json:"original_ip"`
	OriginalPort int    `json:"original_port"`
	Protocol     string `json:"protocol"`
	// TLSFailureCode is set only when a bounded ClientHello peek failed. The
	// engine, not the proxy, chooses BYPASS or BLOCK from the active profile.
	TLSFailureCode string `json:"tls_failure_code,omitempty"`
	// IsTLS is required, including an explicit false for plain HTTP. A missing
	// value must never cause a TLS connection to be treated as HTTP by default.
	IsTLS *bool      `json:"is_tls"`
	TLS   TLSContext `json:"tls"`
}

type ProxyConnectionDecision struct {
	DecisionID       string        `json:"decision_id"`
	ConfigGeneration uint64        `json:"config_generation"`
	SessionID        string        `json:"session_id,omitempty"`
	PolicyID         string        `json:"policy_id,omitempty"`
	ProfileID        string        `json:"profile_id,omitempty"`
	Action           TLSGateAction `json:"action"`
	FailMode         GateFailMode  `json:"fail_mode"`
	ReasonCode       string        `json:"reason_code"`
	UpstreamHost     string        `json:"upstream_host,omitempty"`
	UpstreamIP       string        `json:"upstream_ip"`
	UpstreamPort     int           `json:"upstream_port"`
}

type RequestContext struct {
	RequestID        string  `json:"request_id"`
	ConnectionID     string  `json:"connection_id"`
	SessionID        string  `json:"session_id,omitempty"`
	RequestOrdinal   uint64  `json:"request_ordinal"`
	StreamID         *uint32 `json:"stream_id,omitempty"`
	HTTPVersion      string  `json:"http_version"`
	Method           string  `json:"method"`
	Scheme           string  `json:"scheme"`
	Host             string  `json:"host"`
	Path             string  `json:"path"`
	QueryPresent     bool    `json:"query_present"`
	ContentType      string  `json:"content_type,omitempty"`
	ContentEncoding  string  `json:"content_encoding,omitempty"`
	HeaderBytes      int     `json:"header_bytes"`
	BodyBytes        int     `json:"body_bytes"`
	DecodedBodyBytes int     `json:"decoded_body_bytes"`
	BodySHA256       string  `json:"body_sha256,omitempty"`
	Truncated        bool    `json:"truncated"`
}

func (c RequestContext) Clone() RequestContext {
	if c.StreamID != nil {
		value := *c.StreamID
		c.StreamID = &value
	}
	return c
}

type RequestAlert struct {
	Detector    string `json:"detector"`
	SignatureID string `json:"signature_id,omitempty"`
	Category    string `json:"category"`
	Message     string `json:"message,omitempty"`
	Action      string `json:"action,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

type RequestInspectionResult struct {
	RequestID   string          `json:"request_id"`
	Coverage    RequestCoverage `json:"coverage"`
	Completed   bool            `json:"completed"`
	Alerts      []RequestAlert  `json:"alerts,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	DurationMS  int64           `json:"duration_ms"`
	RulesetID   string          `json:"ruleset_id,omitempty"`
	RulesetHash string          `json:"ruleset_hash,omitempty"`
}

// ProxyRequestEvaluation is the bounded evaluate_request IPC payload. Raw
// request headers, query and body never cross this boundary.
type ProxyRequestEvaluation struct {
	Context    RequestContext          `json:"context"`
	Inspection RequestInspectionResult `json:"inspection"`
}

func (r RequestInspectionResult) Clone() RequestInspectionResult {
	r.Alerts = append([]RequestAlert(nil), r.Alerts...)
	return r
}

type RequestDecision struct {
	DecisionID       string          `json:"decision_id"`
	RequestID        string          `json:"request_id"`
	ConfigGeneration uint64          `json:"config_generation"`
	SessionID        string          `json:"session_id,omitempty"`
	PolicyID         string          `json:"policy_id,omitempty"`
	ProfileID        string          `json:"profile_id,omitempty"`
	Verdict          RequestVerdict  `json:"verdict"`
	Coverage         RequestCoverage `json:"coverage"`
	HTTPStatus       int             `json:"http_status"`
	ReasonCode       string          `json:"reason_code"`
	Reason           string          `json:"reason"`
}

// RequestGateEvidence is the engine-owned, bounded management record. The
// request DTO already excludes raw query, headers and body; the store also
// truncates path and alert details before retaining a copy.
type RequestGateEvidence struct {
	EventID         string                  `json:"event_id"`
	Sequence        uint64                  `json:"sequence"`
	ObservedAt      time.Time               `json:"observed_at"`
	Context         RequestContext          `json:"context"`
	PathTruncated   bool                    `json:"path_truncated"`
	Inspection      RequestInspectionResult `json:"inspection"`
	AlertCount      int                     `json:"alert_count"`
	AlertsTruncated bool                    `json:"alerts_truncated"`
	Decision        RequestDecision         `json:"decision"`
}

func (e RequestGateEvidence) Clone() RequestGateEvidence {
	e.Context = e.Context.Clone()
	e.Inspection = e.Inspection.Clone()
	return e
}

type RequestGateEvidencePage struct {
	Items        []RequestGateEvidence `json:"items"`
	NextSequence uint64                `json:"next_sequence"`
	HasMore      bool                  `json:"has_more"`
}

type RequestGateHealth struct {
	Enabled            bool              `json:"enabled"`
	Status             string            `json:"status"`
	Generation         uint64            `json:"generation"`
	ProxyReachable     bool              `json:"proxy_reachable"`
	HTTPListenerReady  bool              `json:"http_listener_ready"`
	HTTPSListenerReady bool              `json:"https_listener_ready"`
	CALoaded           bool              `json:"ca_loaded"`
	WorkersReady       int               `json:"workers_ready"`
	WorkersTotal       int               `json:"workers_total"`
	QueueDepth         int               `json:"queue_depth"`
	ActiveConnections  int               `json:"active_connections"`
	ActiveRequests     int               `json:"active_requests"`
	Counters           map[string]uint64 `json:"counters"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// RequestGateCapabilities distinguishes implemented request-gate code from
// verified Linux interception. Supported alone is never a readiness signal.
type RequestGateCapabilities struct {
	Supported         bool              `json:"supported"`
	ProductionReady   bool              `json:"production_ready"`
	HTTPVersions      []string          `json:"http_versions"`
	ConnectionActions []TLSGateAction   `json:"connection_actions"`
	FailModes         []GateFailMode    `json:"fail_modes"`
	Limits            RequestGateConfig `json:"limits"`
	RuntimeIPCVersion uint16            `json:"runtime_ipc_version"`
	BuildVersion      string            `json:"build_version"`
	Limitations       []string          `json:"limitations"`
}

func (h RequestGateHealth) Clone() RequestGateHealth {
	if h.Counters != nil {
		copied := make(map[string]uint64, len(h.Counters))
		for name, count := range h.Counters {
			copied[name] = count
		}
		h.Counters = copied
	}
	return h
}
