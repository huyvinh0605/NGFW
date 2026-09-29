package domain

// RequestGateConfig is the policy-visible M4 configuration. Artifact paths,
// CA keys and Suricata control sockets remain deployment settings.
type RequestGateConfig struct {
	Enabled                  bool   `json:"enabled"`
	ListenHTTPPort           int    `json:"listen_http_port"`
	ListenHTTPSPort          int    `json:"listen_https_port"`
	RulesetID                string `json:"ruleset_id"`
	WorkerCount              int    `json:"worker_count"`
	QueueItems               int    `json:"queue_items"`
	QueueBytes               int    `json:"queue_bytes"`
	MaxConcurrentRequests    int    `json:"max_concurrent_requests"`
	MaxPerClientRequests     int    `json:"max_per_client_requests"`
	MaxHTTP2Streams          int    `json:"max_http2_streams"`
	MaxHeaderBytes           int    `json:"max_header_bytes"`
	MaxHeaderCount           int    `json:"max_header_count"`
	MaxURLBytes              int    `json:"max_url_bytes"`
	MaxRawBodyBytes          int    `json:"max_raw_body_bytes"`
	MaxDecompressedBodyBytes int    `json:"max_decompressed_body_bytes"`
	MaxDecompressionRatio    int    `json:"max_decompression_ratio"`
	RequestTimeoutMillis     int    `json:"request_timeout_ms"`
	ClientHelloBytes         int    `json:"client_hello_bytes"`
	ClientHelloTimeoutMillis int    `json:"client_hello_timeout_ms"`
	LeafCacheEntries         int    `json:"leaf_cache_entries"`
	LeafCacheTTLSeconds      int    `json:"leaf_cache_ttl_seconds"`
}

type RequestGateProfile struct {
	Enabled                   bool         `json:"enabled"`
	FailMode                  GateFailMode `json:"fail_mode"`
	OversizeAction            string       `json:"oversize_action"`
	UnsupportedEncodingAction string       `json:"unsupported_encoding_action"`
	BlockQUIC                 bool         `json:"block_quic"`
}

type TLSExclusion struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Domains          []string `json:"domains,omitempty"`
	DestinationCIDRs []string `json:"destination_cidrs,omitempty"`
	Ports            []int    `json:"ports,omitempty"`
	Enabled          bool     `json:"enabled"`
	Reason           string   `json:"reason"`
}

func DefaultRequestGateConfig() RequestGateConfig {
	return RequestGateConfig{
		ListenHTTPPort: 18080, ListenHTTPSPort: 18443, RulesetID: "m4-builtin-v1",
		WorkerCount: 2, QueueItems: 256, QueueBytes: 4 << 20,
		MaxConcurrentRequests: 128, MaxPerClientRequests: 32, MaxHTTP2Streams: 64,
		MaxHeaderBytes: 32 << 10, MaxHeaderCount: 64, MaxURLBytes: 8 << 10,
		MaxRawBodyBytes: 64 << 10, MaxDecompressedBodyBytes: 256 << 10,
		MaxDecompressionRatio: 20, RequestTimeoutMillis: 2000,
		ClientHelloBytes: 64 << 10, ClientHelloTimeoutMillis: 2000,
		LeafCacheEntries: 1024, LeafCacheTTLSeconds: 24 * 60 * 60,
	}
}

// WithDefaults fills omitted numeric settings without mutating the candidate.
// Negative values remain invalid and are rejected by config validation.
func (g RequestGateConfig) WithDefaults() RequestGateConfig {
	d := DefaultRequestGateConfig()
	if g.ListenHTTPPort == 0 {
		g.ListenHTTPPort = d.ListenHTTPPort
	}
	if g.ListenHTTPSPort == 0 {
		g.ListenHTTPSPort = d.ListenHTTPSPort
	}
	if g.RulesetID == "" {
		g.RulesetID = d.RulesetID
	}
	if g.WorkerCount == 0 {
		g.WorkerCount = d.WorkerCount
	}
	if g.QueueItems == 0 {
		g.QueueItems = d.QueueItems
	}
	if g.QueueBytes == 0 {
		g.QueueBytes = d.QueueBytes
	}
	if g.MaxConcurrentRequests == 0 {
		g.MaxConcurrentRequests = d.MaxConcurrentRequests
	}
	if g.MaxPerClientRequests == 0 {
		g.MaxPerClientRequests = d.MaxPerClientRequests
	}
	if g.MaxHTTP2Streams == 0 {
		g.MaxHTTP2Streams = d.MaxHTTP2Streams
	}
	if g.MaxHeaderBytes == 0 {
		g.MaxHeaderBytes = d.MaxHeaderBytes
	}
	if g.MaxHeaderCount == 0 {
		g.MaxHeaderCount = d.MaxHeaderCount
	}
	if g.MaxURLBytes == 0 {
		g.MaxURLBytes = d.MaxURLBytes
	}
	if g.MaxRawBodyBytes == 0 {
		g.MaxRawBodyBytes = d.MaxRawBodyBytes
	}
	if g.MaxDecompressedBodyBytes == 0 {
		g.MaxDecompressedBodyBytes = d.MaxDecompressedBodyBytes
	}
	if g.MaxDecompressionRatio == 0 {
		g.MaxDecompressionRatio = d.MaxDecompressionRatio
	}
	if g.RequestTimeoutMillis == 0 {
		g.RequestTimeoutMillis = d.RequestTimeoutMillis
	}
	if g.ClientHelloBytes == 0 {
		g.ClientHelloBytes = d.ClientHelloBytes
	}
	if g.ClientHelloTimeoutMillis == 0 {
		g.ClientHelloTimeoutMillis = d.ClientHelloTimeoutMillis
	}
	if g.LeafCacheEntries == 0 {
		g.LeafCacheEntries = d.LeafCacheEntries
	}
	if g.LeafCacheTTLSeconds == 0 {
		g.LeafCacheTTLSeconds = d.LeafCacheTTLSeconds
	}
	return g
}

func EffectiveRequestGateConfig(c Config) RequestGateConfig {
	if c.RequestGate == nil {
		return DefaultRequestGateConfig()
	}
	return c.RequestGate.WithDefaults()
}

func UsesM4(c Config) bool { return c.RequestGate != nil && c.RequestGate.Enabled }
