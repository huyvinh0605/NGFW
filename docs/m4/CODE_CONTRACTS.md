# M4 — Code Contracts

This document freezes the required semantics so that implementation agents do not silently change architectural boundaries.

## 1. Enums

```go
type GateFailMode string
const (
    GateFailOpen  GateFailMode = "OPEN"
    GateFailClose GateFailMode = "CLOSE"
)

type TLSGateAction string
const (
    TLSGateBypass       TLSGateAction = "BYPASS"
    TLSGateMetadataOnly TLSGateAction = "METADATA_ONLY"
    TLSGateDecrypt      TLSGateAction = "DECRYPT"
    TLSGateInspectHTTP  TLSGateAction = "INSPECT_HTTP"
    TLSGateBlock        TLSGateAction = "BLOCK"
)

type RequestVerdict string
const (
    RequestAllow       RequestVerdict = "ALLOW"
    RequestBlock       RequestVerdict = "BLOCK"
    RequestUnavailable RequestVerdict = "UNAVAILABLE"
)

type RequestCoverage string
const (
    CoverageComplete     RequestCoverage = "COMPLETE"
    RequestCoveragePartial     RequestCoverage = "PARTIAL"
    RequestCoverageUnavailable RequestCoverage = "UNAVAILABLE"
    CoverageNotRequested RequestCoverage = "NOT_REQUESTED"
)
```

Zero/unknown values must never be normalized into ALLOW/CLEAN.
The two prefixed Go identifiers avoid collision with the existing M3
`CoverageState` constants in `internal/domain/inspection.go`; wire values stay
`PARTIAL` and `UNAVAILABLE`.

## 2. Connection contract

```go
type ProxyConnectionOpen struct {
    ConnectionID string     `json:"connection_id"`
    SourceIP     string     `json:"source_ip"`
    SourcePort   int        `json:"source_port"`
    OriginalIP   string     `json:"original_ip"`
    OriginalPort int        `json:"original_port"`
    Protocol     string     `json:"protocol"`
    IsTLS        *bool      `json:"is_tls"`
    TLS          TLSContext `json:"tls"`
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
```

An empty `SessionID` means correlation is unavailable. The engine must still decide using authoritative policy data or return an explicit unavailable result. The proxy must never infer policy locally.

`IsTLS` is required even for plain HTTP (`false`); absent/null is invalid, so
the engine never infers transport from port or a zero-value TLS context.
For a selected non-TLS HTTP connection, the engine returns `INSPECT_HTTP`:
the proxy parses HTTP without TLS termination, holds every request, runs
synchronous inspection, and obtains the final request verdict from the engine
before forwarding any application request upstream. `ALLOW` may forward;
`BLOCK` may not. `INSPECT_HTTP` is neither `BYPASS` nor `METADATA_ONLY` nor
`DECRYPT`. The four existing actions retain their TLS meaning.

## 3. Request contract

```go
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
```

Do not send the raw request body through engine IPC. The request-worker boundary runs the detector and returns normalized evidence only.

## 4. Detector contract

```go
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
```

Contract:
- Only `Completed=true + Coverage=COMPLETE + no blocking alert` is a clean inspection.
- Timeout/socket/queue/parser errors imply `Completed=false` and unavailable/partial coverage.
- `alert.action` and the proxy request verdict are separate fields and must not be conflated.

## 5. Final request decision

```go
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
```

Default M4 decision table:

| Detector result | Fail mode | Verdict | HTTP | Coverage |
|---|---|---|---:|---|
| complete, no blocking alert | any | ALLOW | 0 | COMPLETE |
| blocking alert | any | BLOCK | 403 | COMPLETE |
| timeout/unavailable | OPEN | ALLOW | 0 | UNAVAILABLE/PARTIAL |
| timeout/unavailable | CLOSE | BLOCK | 503 | UNAVAILABLE |
| oversize | OPEN + ALLOW_PARTIAL | ALLOW | 0 | PARTIAL |
| oversize | CLOSE/BLOCK | BLOCK | 413 | PARTIAL |
| malformed request | any | BLOCK | 400 | UNAVAILABLE |

## 6. Stable error/reason codes

Minimum stable set:

- `GATE_POLICY_NOT_ALLOWED`
- `GATE_NOT_REQUESTED`
- `GATE_INSPECTION_REQUIRED`
- `GATE_ENGINE_UNAVAILABLE`
- `GATE_IPC_VERSION_MISMATCH`
- `GATE_REQUEST_TOO_LARGE`
- `GATE_HEADERS_TOO_LARGE`
- `GATE_URL_TOO_LONG`
- `GATE_UNSUPPORTED_ENCODING`
- `GATE_DECOMPRESSION_LIMIT`
- `GATE_QUEUE_FULL`
- `GATE_INSPECTION_TIMEOUT`
- `GATE_SENSOR_UNAVAILABLE`
- `GATE_SIGNATURE_BLOCK`
- `TLS_CLIENTHELLO_TIMEOUT`
- `TLS_CLIENTHELLO_INVALID`
- `TLS_SNI_UNAVAILABLE`
- `TLS_ECH_UNSUPPORTED`
- `TLS_CA_UNAVAILABLE`
- `TLS_CLIENT_HANDSHAKE_FAILED`
- `TLS_UPSTREAM_CONNECT_FAILED`
- `TLS_UPSTREAM_VERIFY_FAILED`
- `TLS_UPSTREAM_MTLS_UNSUPPORTED`
- `TLS_PINNING_SUSPECTED`
- `TLS_EXCLUSION`
- `PROXY_ORIGINAL_DST_UNAVAILABLE`
- `PROXY_CAPACITY_EXCEEDED`

Never use free-form error strings as branch logic.

## 7. Health contract

```go
type RequestGateHealth struct {
    Enabled            bool              `json:"enabled"`
    Status             string            `json:"status"` // disabled|healthy|degraded|down
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
```

Minimum counters: `intercepted`, `bypassed`, `decrypted`, `request_allowed`, `request_blocked`, `fail_open`, `fail_close`, `inspection_timeout`, `queue_rejected`, `tls_handshake_fail`, `upstream_verify_fail`, `body_limit`, `decompression_limit`.

## 8. TLS exclusion matching

- Canonicalize domains to lower case and trim a trailing dot. IDNA handling must be explicit. If an IDNA dependency is not introduced, reject non-ASCII domains rather than normalizing them incorrectly.
- `*.example.com` matches subdomains but not `example.com` itself.
- CIDRs match the original destination IP using the connection's post-DNAT semantics.
- If an exclusion contains both domain and CIDR criteria, both criterion groups must match.
- An empty port list means any port in the TLS path. M4 defaults to 443 unless a policy service explicitly selects another TLS port.
- If multiple exclusions are allowed, first-match priority should be explicit. If no priority exists, reject exact duplicate/shadow rules.

## 9. HTTP/2 correctness

Correctness is defined by request isolation, not by the availability of an exact wire StreamID.

- `http.Server`/HTTP2 handlers create a distinct request for each stream.
- `ConnContext` attaches the `ConnectionID`.
- `RequestOrdinal` is atomic per connection and is only a local ordinal.
- Body buffers, detector results, deadlines, and decision pointers must not be shared across requests.
- Test one H2 connection with at least two concurrent requests, one malicious and one clean; only the clean request may appear upstream.

## 10. Sensitive metadata redaction

At minimum, drop/redact values for: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, and token/secret/password-like patterns. Do not persist raw query strings. Persist only `query_present` or a redacted key set when required for debugging.

## 11. Synthetic request PCAP (T19)

`requestpcap.Build(normalizedRequest, flowID)` produces deterministic Ethernet/IPv4/TCP PCAP bytes from one already-bounded request. The worker owns `flowID`: each job on a Suricata process uses a distinct 32-bit ID, and the worker must stop/restart before wrap. The ID maps injectively to a synthetic 198.18.0.0/15 client IP and source port 1024–33791; the synthetic server is 192.168.0.10:80. Neither address is a real traffic identity.

The finite capture contains SYN, SYN/ACK, ACK, 1200-byte-or-smaller request segments, an empty HTTP response, and both TCP FINs. IPv4 and TCP checksums are valid. HTTP/2 application semantics are serialized as HTTP/1.1 for signature matching only; HTTP/2 framing is not represented. Original Content-Length, Content-Encoding and hop-by-hop headers are replaced or omitted for the decoded detector body. Secret-bearing headers are omitted. The capture is capped at 6 MiB and must never be logged. The builder does not create paths; T21 writes each job in a unique 0700 directory and removes it after inspection. Suricata acceptance of the generated packets remains an Ubuntu VM test, not a local unit-test claim.

## 12. Suricata command socket (T20)

`suricata_socket.Dial` negotiates JSON protocol version `0.1` and requires `pcap-file`, `pcap-current`, `pcap-file-list`, and `pcap-file-number` from `command-list`. Each connection serializes commands and parses a complete JSON response even when Suricata splits it across writes. Every operation has a bounded deadline and 64 KiB response cap; a timeout, malformed response or transport error closes the connection so a later command cannot consume a stale reply. `NOK` remains a rejection. Missing/null queue depth or list fields are protocol errors, never an empty/clean queue. The socket client only submits worker-owned absolute paths and does not determine request verdicts. The protocol shape follows the [Suricata 8.0 Unix socket documentation](https://docs.suricata.io/en/suricata-8.0.0/unix-socket.html).
