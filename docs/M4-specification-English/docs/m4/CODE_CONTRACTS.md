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

The `evaluate_request` operation wraps these two existing DTOs without adding raw traffic fields:

```go
type ProxyRequestEvaluation struct {
    Context    RequestContext          `json:"context"`
    Inspection RequestInspectionResult `json:"inspection"`
}
```

## 4. Detector contract

```go
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

The `ProxyConnectionOpen` DTO also carries optional `tls_failure_code` (`TLS_CLIENTHELLO_TIMEOUT` or `TLS_CLIENTHELLO_INVALID`) when the bounded ClientHello peek cannot produce metadata. The proxy sends the consumed bytes and failure identity to the engine without opening upstream. For a selected DECRYPT profile, the engine chooses BYPASS on explicit `OPEN` or BLOCK on `CLOSE`; missing SNI uses `TLS_SNI_UNAVAILABLE` with the same profile choice. A later downstream TLS handshake failure is always closed because tunneling after presenting a substitute certificate would be an unsafe downgrade.

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
- `GATE_INSPECTION_COMPLETE`
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
- `GATE_EVE_MALFORMED`
- `GATE_EVE_INCOMPLETE`
- `GATE_EVE_MISMATCH`
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

T29 exposes read-only `GET /api/v1/request-gate/health`, `/capabilities` and
authenticated, bounded `/evidence` through `ngfw-engine` runtime IPC. A missing
live proxy heartbeat must report `down` (or `disabled` when M4 is off), never
`healthy`; zero counters while unreachable are not proof of zero traffic.
Capabilities distinguish `supported` code paths from `production_ready` on the
target Linux appliance. The initial T29 response keeps `production_ready=false`
until T01/T06/T07/T28 activation and a generation-bound proxy heartbeat are
implemented and verified. The evidence page accepts `after_sequence` and a
limit of 1–128; it must not include raw query, headers or body.

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

## 13. Request worker and EVE correlation (T21–T22)

The pool admits at most `queue_items + worker_count` requests and at most `queue_bytes` of accepted PCAP data; at most `worker_count` builders allocate PCAPs concurrently. Each worker owns one persistent Suricata process/socket and runs one job at a time. The job's random directory has mode 0700, its PCAP mode 0600, and its output is deleted after use. Request timeout covers queue wait. `flowID` increments without wrap and maps injectively to the synthetic TCP tuple in section 11. Workers stop/restart before exhaustion.

After Suricata acknowledges `pcap-file`, the worker polls structured current/list/count state under the request deadline. It never uses a fixed sleep as completion. Only after the submitted path is absent from all three states does it read at most 1 MiB of job-local `eve.json`; missing or empty output is unavailable. `NormalizeEVE` requires bounded, newline-terminated JSON records, the current PCAP path when provided, matching synthetic forward/reply tuple, consistent Suricata flow ID when provided, and a terminal `flow.state=closed` event. Only then does it set `Completed=true` and `Coverage=COMPLETE`. Malformed, incomplete or cross-job output remains unavailable with stable `GATE_EVE_MALFORMED`, `GATE_EVE_INCOMPLETE` or `GATE_EVE_MISMATCH`; earlier parsed alerts are discarded on failure. Unsupported valid EVE event types are ignored. Alert SID, category, signature message, action, severity and timestamp are preserved without raw payloads. This terminal-flow requirement is a conservative local contract; actual Suricata 8 EVE/PCAP behavior must be verified on Ubuntu before acceptance. [Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html).

## 14. Authoritative request decision (T23)

`ngfw-engine` keeps a bounded, expiring map from random `ConnectionID` to the exact `open_connection` tuple; a different tuple may not reuse a live ID. `evaluate_request` reopens the current connectivity gate for that tuple on every request, so a new policy generation, source block or session revocation supersedes an earlier connection ALLOW. The map and a bounded request-decision record store belong to the engine, not the proxy. Unknown/expired connection identity fails closed. Each final verdict has a new DecisionID, current config generation, linked session/policy/profile when available, coverage and stable reason code. The engine checks that `Inspection.RequestID` matches `Context.RequestID`; it never accepts raw bodies through this operation. Fail-open/close and oversize decisions follow section 5. A blocking Suricata action (`blocked`/`drop`/`reject`/`deny`) produces request-scope 403; an `allowed`/`pass` alert alone does not become a proxy BLOCK. M4 does not introduce M5 risk scoring or a second policy evaluator. The existing action field is authoritative for blocking in the current profile schema; an optional blocking SID list is not yet configured.

## 15. HTTP/1.1 request forwarder (T24)

`HTTP1RequestGate` accepts `INSPECT_HTTP` for plaintext or `DECRYPT` for an already-terminated TLS/HTTP1.1 connection. The Go HTTP server parser holds each request. It reads at most `max_raw_body_bytes + 1`, normalizes and optionally decompresses detector input under the configured limit, asks the bounded Suricata worker for evidence, and sends only bounded metadata/evidence through `evaluate_request` IPC. A worker error or incomplete EVE is UNAVAILABLE, never CLEAN. The proxy only creates a new upstream HTTP request after a matching, non-stale engine `ALLOW`; BLOCK, malformed IPC, absent engine, or a connection policy mismatch has no upstream application write. The engine alone chooses fail-open/close and ALLOW_PARTIAL.

The upstream target is the engine-authorized original IP/port, never an untrusted Host address. HTTPS upstream uses certificate/hostname verification with HTTP/1.1 ALPN; verification failure returns 502 without plaintext fallback. Hop-by-hop request/response fields and Connection-nominated fields are removed, while method, path/query, virtual Host and raw application body are replayed after ALLOW. HTTP/1.1 keep-alive requests each receive a separate inspection and verdict. CONNECT/Upgrade and an upstream 101 are unsupported and fail closed. HTTP/2 is handled by T25. Request/response streaming and upstream timeouts are bounded; a truncated upstream response aborts downstream reuse. Live interception and TLS trust remain Ubuntu VM ACCEPTANCE PENDING.

## 16. HTTP/2 stream isolation (T25)

Only an already-decrypted TLS connection with negotiated `h2` enters `http2.Server.ServeConn`. The server limits concurrent streams to the lesser of configured per-connection and per-client counts, advertises bounded 16 KiB frames, 4 KiB HPACK tables and 64 KiB/256 KiB stream/connection receive windows. Each stream has a distinct `RequestID`, atomic connection-local ordinal, body, inspection deadline and engine verdict. A blocked stream returns its own response without adding `Connection: close` to the HTTP/2 connection; no wire StreamID is invented. On ALLOW, the verified upstream TLS transport may negotiate h2 and uses a bounded header list/frame/table configuration. The exact upstream IP/port remains the engine-authorized destination. A local concurrent-stream test proves that a blocked stream never reaches an HTTP/2 upstream while a clean stream on the same downstream connection does. Linux interception and browser trust remain VM ACCEPTANCE PENDING.

## 17. Failure/overload mapping (T26)

The profile's `unsupported_encoding_action` had no explicit verdict row. The minimal compatible rule is: `GATE_UNSUPPORTED_ENCODING` has UNAVAILABLE coverage; only `FailMode=OPEN` together with `ALLOW_PARTIAL` may ALLOW the original raw body. Every other combination BLOCKs with 503. Invalid compressed data is `GATE_REQUEST_MALFORMED` and BLOCK 400 even under OPEN; it is not a clean detector outage. Oversize raw bodies retain PARTIAL coverage and follow the existing 413/ALLOW_PARTIAL table. A detector timeout, queue rejection or missing EVE reaches the engine as unavailable evidence. If the engine itself cannot return a valid verdict, the proxy returns 503 and never forwards upstream.

An incomplete HTTP/1.1 body gets a connection read deadline; an incomplete HTTP/2 body is canceled at its stream/request deadline. Neither may hold a request slot indefinitely. The proxy counts intercepted, allowed, blocked, fail-open, fail-close, inspection timeout, queue/capacity rejection, body/decompression limit and upstream TLS/connect failure with atomic counters. Connection dispatch also counts ClientHello timeout/invalid and TLS handshake failure. `RequestGateHealth` aggregation/exposure belongs to T29. Local tests cover 400/413/414/431/502/503, capacity rejection, slow HTTP/1.1 body and a slow HTTP/2 stream that leaves the shared connection usable.

## 18. Request evidence and session detail (T27)

`ngfw-engine` owns a separate bounded M4 request-evidence store keyed by RequestID, with a 10,000-record/16 MiB default, ten-minute TTL and monotonic sequence. A new record replaces the same RequestID, and oldest records are evicted under count or byte pressure. Its `RequestGateEvidence` contains the request metadata DTO, normalized inspection summary, engine decision and timestamp; it never receives raw query, headers or body. Stored path is truncated to 256 bytes with a flag, and at most four alert messages of 128 bytes each are retained with original `AlertCount`/truncation flag. Session detail includes at most the newest 32 related request records, while the existing M2 session state and PACKET/SESSION enforcement remain unchanged. A separate bounded evidence page can be queried by sequence. Each final verdict publishes a `RequestGateDecision` event on the existing bounded runtime event ring; the event contains only ID, session link, generation and reason. Production management IPC attachment and endpoint exposure belong to T28/T29.
