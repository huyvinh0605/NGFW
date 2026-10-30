package domain

// RequestGateRuntime is an immutable operational descriptor from the engine.
// It carries limits, never a second copy of firewall policies or CA keys.
// InterceptionReady can only be set by verified engine dataplane activation.
type RequestGateRuntime struct {
	EngineInstanceID  string            `json:"engine_instance_id"`
	ConfigGeneration  uint64            `json:"config_generation"`
	Config            RequestGateConfig `json:"config"`
	RequiresCA        bool              `json:"requires_ca"`
	InterceptionReady bool              `json:"interception_ready"`
	// PreparationID permits resource preflight, never traffic authorization.
	PreparationID     string               `json:"preparation_id,omitempty"`
	ExpectedArtifacts RequestGateArtifacts `json:"expected_artifacts"`
}

// Public artifact identities bind activation to the actual loaded detector
// rules and CA certificate. Private-key hashes are deliberately absent.
type RequestGateArtifacts struct {
	RulesetID        string `json:"ruleset_id"`
	RulesetHash      string `json:"ruleset_hash"`
	WorkerConfigHash string `json:"worker_config_hash"`
	CAFingerprint    string `json:"ca_fingerprint,omitempty"`
}

// RequestGateHeartbeat reports observations for exactly one engine generation.
// The engine timestamps receipt and validates sizes and resource bounds.
type RequestGateHeartbeat struct {
	ProxyInstanceID    string               `json:"proxy_instance_id"`
	EngineInstanceID   string               `json:"engine_instance_id,omitempty"`
	Generation         uint64               `json:"generation"`
	Sequence           uint64               `json:"sequence"`
	HTTPListenerReady  bool                 `json:"http_listener_ready"`
	HTTPSListenerReady bool                 `json:"https_listener_ready"`
	CALoaded           bool                 `json:"ca_loaded"`
	WorkersReady       int                  `json:"workers_ready"`
	QueueDepth         int                  `json:"queue_depth"`
	ActiveConnections  int                  `json:"active_connections"`
	ActiveRequests     int                  `json:"active_requests"`
	Counters           map[string]uint64    `json:"counters,omitempty"`
	FailureCode        string               `json:"failure_code,omitempty"`
	PreparationID      string               `json:"preparation_id,omitempty"`
	Artifacts          RequestGateArtifacts `json:"artifacts"`
}

// IDs are opaque random 128-bit values, not filenames or client identifiers.
func ValidGateInstanceID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidGateFailureCode(code string) bool {
	switch code {
	case "", "GATE_ENGINE_UNAVAILABLE", "GATE_INTERCEPTION_UNAVAILABLE", "GATE_RUNTIME_INVALID", "GATE_CA_UNAVAILABLE", "GATE_SENSOR_UNAVAILABLE", "GATE_LISTENER_UNAVAILABLE", "GATE_RULESET_UNAVAILABLE", "PROXY_ORIGINAL_DST_UNAVAILABLE":
		return true
	default:
		return false
	}
}

func ValidGateCounter(name string) bool {
	switch name {
	case "intercepted", "bypassed", "decrypted", "request_allowed", "request_blocked", "fail_open", "fail_close", "inspection_timeout", "queue_rejected", "tls_handshake_fail", "upstream_verify_fail", "body_limit", "decompression_limit", "client_hello_timeout", "client_hello_invalid", "upstream_connect_fail", "upstream_mtls_unsupported", "upstream_handshake_fail", "result_report_fail", "capacity_rejected", "resolve_failed", "handler_failed", "engine_unavailable":
		return true
	default:
		return false
	}
}
