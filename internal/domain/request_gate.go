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
