# M4 Detailed Implementation Specification
## Synchronous HTTP/TLS Request Gate for the NGFW Project

**Status:** Implementation handoff specification  
**Language:** English  
**Target milestone:** M4  
**Baseline:** M1/M2 implementation exists; M3 production source exists. Ubuntu VM acceptance for earlier milestones remains independent and must not be inferred from M4 local tests.  
**Primary purpose of this document:** Define *what M4 must implement, why it exists, how the major runtime logic must behave, what invariants must never be violated, and what evidence must prove completion*. A later code-planning agent is expected to map this specification to exact repository files, symbols, functions, tests, and patch order after reading the current source tree.

---

# 1. Why M4 Exists

M1 provides Linux network configuration, routing, stateful firewalling, NAT, transactional activation, rollback, and startup reconciliation.

M2 adds authoritative runtime session identity, conntrack lifecycle handling, NAT-safe tuple correlation, policy generation, fast-path marking, bounded session/event stores, and runtime guards.

M3 adds asynchronous network inspection around the authoritative M2 session model, including Suricata IDS/IPS integration, application evidence, event correlation, sensor health, and packet/session-oriented enforcement.

M4 must add a different security property:

> For a policy-selected HTTP or HTTPS request that requires request inspection, the application request must not reach the upstream server until inspection has completed and the authoritative engine has returned an ALLOW verdict.

M4 therefore introduces a **synchronous request gate**.

The critical difference from M3 is timing.

M3 may observe or act on packet/session evidence while a connection exists. M4 must hold the HTTP request before the upstream application receives it.

M4 is not a general WAF milestone, not an ML milestone, and not a risk-scoring milestone. It is the milestone that establishes the architectural ability to synchronously inspect and block HTTP semantics before upstream delivery.

---

# 2. M4 Completion Claim

M4 may be described as implemented only when the source contains all required components and the local contract tests pass.

M4 may be described as accepted only when the required Linux appliance tests prove the behavior with real networking components.

These are separate states:

- `IMPLEMENTED`
- `UNIT_TESTED`
- `LOCAL_INTEGRATION_TESTED`
- `VM_ACCEPTANCE_PENDING`
- `VM_ACCEPTED`

Local tests must never be used to claim Ubuntu appliance acceptance.

---

# 3. Scope

## 3.1 Included

M4 must implement:

1. Transparent interception of selected TCP HTTP/HTTPS traffic.
2. Authoritative gate selection derived from the same running policy program used by the engine.
3. Plain HTTP request gating.
4. TLS ClientHello metadata collection.
5. TLS modes:
   - `BYPASS`
   - `METADATA_ONLY`
   - `DECRYPT`
6. Lab MITM CA provisioning and bounded leaf-certificate generation/cache.
7. HTTPS interception for:
   - HTTP/1.1
   - HTTP/2
8. Request-level identity and isolation.
9. Bounded buffering and concurrency.
10. Safe decompression for supported content encodings.
11. A synchronous Suricata request inspection adapter.
12. Deterministic request verdict semantics.
13. Explicit fail-open/fail-close behavior.
14. TLS exclusions.
15. Explicit HTTP/3/QUIC limitation behavior.
16. Request-gate health, counters, events, and bounded evidence metadata.
17. Commit/rollback/startup integration.
18. Linux acceptance tooling and evidence requirements.

## 3.2 Excluded

M4 must not expand into:

- ML classification or model lifecycle.
- M5 risk scoring.
- threat-intelligence feed ingestion.
- behavioral/scan/DoS correlation engines.
- full WAF rule management.
- response-body antivirus/DLP inspection.
- HTTP/3 or QUIC decryption.
- ECH decryption.
- upstream mutual-TLS client impersonation.
- WebSocket frame inspection after upgrade.
- enterprise explicit-proxy authentication.
- HA/load balancing.
- session-wide escalation from a malicious request unless a later milestone explicitly defines it.

If a future capability is useful but not necessary for the M4 contract, record it as follow-up work rather than implementing it inside M4.

---

# 4. Architectural Non-Negotiables

## 4.1 One authoritative firewall brain

`ngfw-engine` must remain the only authoritative owner of:

- running configuration;
- configuration generation;
- canonical policy ordering;
- matched policy/profile;
- M2 runtime session identity;
- NAT/session correlation;
- request interception decision;
- request security verdict;
- request event state;
- commit/rollback state.

Production M4 must remove the architectural pattern where `ngfw-proxy` creates its own independent engine and evaluates firewall policy locally.

The current prototype behavior equivalent to:

```go
engine.New(manager, enforcement.NewMemory())
```

inside the proxy path must not remain the production M4 decision path.

## 4.2 Proxy is a dataplane helper

The proxy may:

- accept an intercepted TCP connection;
- recover the original destination;
- read bounded protocol metadata;
- terminate TLS when instructed;
- parse HTTP using the standard HTTP stack;
- hold a request;
- call the engine through the request-gate protocol;
- run or invoke the request inspection adapter where the agreed architecture places it;
- forward after ALLOW;
- generate a local block/error response after BLOCK or gate failure.

The proxy must not independently decide:

- whether a denied L3/L4 flow is allowed;
- which security profile applies;
- whether fail-open/fail-close is configured;
- whether an M4 request block should become a session block;
- whether stale config-generation data is still authoritative.

## 4.3 M4 must never create a new allow path

The request gate operates only on traffic already permitted by the authoritative base firewall policy.

If the canonical policy result is `DROP` or `REJECT`, M4 must not redirect that traffic to the proxy and must not allow it through a proxy path.

A simplified rule is:

```text
Base policy DENY -> M4 cannot override.
Base policy ALLOW + no gate -> normal forwarding.
Base policy ALLOW + gate -> request-gate path.
```

## 4.4 No-forward-before-verdict

For a gated request, application-layer forwarding must not begin until the final authoritative request verdict is ALLOW.

This means that a blocked request cannot have already been sent to the upstream application.

The implementation must prove this property in tests by observing the upstream server, not only by checking a local block response.

---

# 5. Authoritative Policy and Gate Selection Logic

M4 must derive gate selection from the same compiled policy semantics used by the existing connectivity runtime.

The policy evaluation order remains the existing first-match behavior.

For a flow candidate:

1. Evaluate the canonical L3/L4 connectivity program.
2. If no policy matches, preserve the existing default behavior.
3. If the matched policy is not ALLOW, gate selection is OFF.
4. If the matched ALLOW policy has no request-gate profile, gate selection is OFF.
5. If a gate profile exists:
   - resolve the security profile;
   - resolve TLS mode;
   - resolve fail mode;
   - resolve body/encoding policy;
   - resolve exclusions;
   - produce an immutable gate selection object.
6. Bind the result to the current configuration generation.

Conceptual output:

```go
type RequestGateSelection struct {
    Enabled          bool
    PolicyID         string
    ProfileID        string
    Generation       uint64

    TLSMode          TLSMode
    FailMode         RequestFailMode
    OversizeAction   OversizeAction
    EncodingAction   UnsupportedEncodingAction
    BlockQUIC        bool

    RulesetID        string
}
```

The exact repository type names may differ, but the semantic contract must remain equivalent.

The gate selection must be immutable after compilation.

---

# 6. Configuration Model

M4 requires a global request-gate runtime configuration, a per-security-profile gate configuration, and TLS exclusions.

A code-planning agent may adapt names to existing project conventions but must preserve these concepts.

## 6.1 Global request-gate configuration

Conceptual fields:

```go
type RequestGateConfig struct {
    Enabled bool

    ListenHTTPPort  int
    ListenHTTPSPort int

    RulesetID string

    WorkerCount  int
    QueueItems   int
    QueueBytes   int

    MaxConcurrentRequests int
    MaxPerClientRequests  int
    MaxHTTP2Streams       int

    MaxHeaderBytes           int
    MaxHeaderCount           int
    MaxURLBytes              int
    MaxRawBodyBytes          int
    MaxDecompressedBodyBytes int
    MaxDecompressionRatio    int

    RequestTimeoutMillis     int
    ClientHelloBytes         int
    ClientHelloTimeoutMillis int

    LeafCacheEntries int
    LeafCacheTTL     time.Duration
}
```

Recommended lab defaults:

| Limit | Default |
|---|---:|
| Header bytes | 32 KiB |
| Header count | 64 |
| URL | 8 KiB |
| Raw body | 64 KiB |
| Decompressed body | 256 KiB |
| Decompression ratio | 20x |
| Request inspection deadline | 2 s |
| ClientHello peek | 64 KiB |
| ClientHello deadline | 2 s |
| Concurrent requests | 128 |
| Per-client concurrent requests | 32 |
| HTTP/2 concurrent streams | 64 |
| Suricata request workers | 2 |
| Maximum default lab workers | 4 |
| Queue items | 256 |
| Leaf certificate cache | 1024 |
| Leaf cache TTL | <= 24 h |
| Leaf certificate validity | approximately 7 d |

Every configured limit must itself be validated against a safe allowed range.

## 6.2 Per-profile gate configuration

Conceptual form:

```go
type RequestGateProfile struct {
    Enabled bool

    FailMode RequestFailMode // OPEN | CLOSE

    OversizeAction OversizeAction
    UnsupportedEncodingAction UnsupportedEncodingAction

    BlockQUIC bool
}
```

The existing profile TLS mode remains authoritative for TLS behavior.

## 6.3 TLS exclusions

A TLS exclusion can match:

- canonical domain;
- wildcard domain;
- destination CIDR;
- destination port.

Conceptual form:

```go
type TLSExclusion struct {
    ID      string
    Name    string
    Enabled bool
    Reason  string

    Domains          []string
    DestinationCIDRs []string
    Ports            []int
}
```

Rules:

- Domain matching is case-insensitive after canonicalization.
- A trailing dot is removed.
- `*.example.com` matches a subdomain such as `api.example.com`, but not the apex `example.com`.
- If IDNA support is not implemented explicitly, reject non-ASCII domain rules instead of normalizing them incorrectly.
- CIDR matching uses the effective original destination semantics defined by the transparent interception path.
- If both domain criteria and CIDR criteria exist in one exclusion, both groups must match.
- Empty port list means any port relevant to the TLS path.
- Duplicate and shadowed exclusions must be detected or have explicit deterministic priority semantics.

---

# 7. Transparent Interception

M4 must introduce a dedicated NGFW-owned transparent interception ruleset.

It must not flush foreign nftables state.

A dedicated namespace/table is preferred, conceptually:

```text
inet ngfw_proxy
```

The exact schema name may follow repository conventions.

## 7.1 Selection

Only traffic that matches all of the following is eligible:

1. Base firewall result is ALLOW.
2. Effective profile enables M4 gating.
3. Transport/protocol/port is supported by M4.
4. No higher-priority contract says to bypass.

For M4 OFF, the compiled selector must not change M1/M2/M3 forwarding semantics.

## 7.2 Redirect versus TPROXY

The implementation must capability-probe the target Linux environment before committing to the transparent interception mechanism.

Preferred MVP is redirect-based interception if all required original-destination and DNAT semantics are reliable.

The capability probe must prove:

- TCP/80 interception.
- TCP/443 interception.
- original destination recovery.
- DNAT + interception ordering.
- no recursive interception of upstream connections created by the proxy.
- behavior after restart.
- supported IPv4 path.

If original destination cannot be recovered reliably in required NAT scenarios, the architecture must switch to TPROXY + policy routing before dependent implementation proceeds.

The code-planning agent must not guess this based only on documentation.

## 7.3 Local upstream recursion

Connections created by `ngfw-proxy` toward the upstream server must never be intercepted again by the same transparent gate.

The solution must be explicit and testable.

Possible mechanisms depend on the chosen interception design and may include:

- chain placement;
- socket marks;
- process/user ownership criteria;
- policy routing/marking;
- local-output exclusion.

The exact mechanism must be selected by the code-planning agent after the Linux capability probe.

---

# 8. Connection Identity and Open-Connection Decision

Each accepted downstream TCP connection receives a random collision-resistant `ConnectionID`.

A connection context must minimally contain:

```go
type ProxyConnectionContext struct {
    ConnectionID string

    ClientAddress netip.AddrPort
    OriginalDestination netip.AddrPort

    SessionID string // when authoritative correlation succeeds

    SNI   string
    ALPN  []string
    TLSVersionHints []uint16

    AcceptedAt time.Time
    Generation uint64
}
```

When the proxy receives a connection:

1. Recover original destination.
2. Collect bounded metadata required for the decision.
3. Send `open_connection` to `ngfw-engine`.
4. Engine resolves:
   - M2 session identity if available;
   - matched policy;
   - effective profile;
   - TLS exclusion;
   - current config generation.
5. Engine returns one of:

```text
INSPECT_HTTP (selected non-TLS HTTP only)
BYPASS
METADATA_ONLY
DECRYPT
BLOCK
UNAVAILABLE
```

The proxy explicitly reports whether the accepted connection is TLS. For
non-TLS HTTP selected by the M4 gate, `INSPECT_HTTP` parses HTTP without TLS
termination, holds each request before upstream forwarding, performs
synchronous inspection, and uses the engine's final request verdict. It is
never a raw tunnel or a synonym for `DECRYPT`.

The response must include a stable decision ID and configuration generation.

A stale decision cannot be reused across a generation transition that invalidates it.

---

# 9. Connection State Machine

A conceptual connection state machine:

```text
ACCEPTED
  -> DESTINATION_RESOLVED
  -> METADATA_PEEKED
  -> ENGINE_DECIDED

ENGINE_DECIDED:
  INSPECT_HTTP   -> HTTP_SERVING -> per-request verdict -> CLOSED
  BYPASS         -> RAW_TUNNEL -> CLOSED
  METADATA_ONLY  -> RAW_TUNNEL -> CLOSED
  DECRYPT        -> TLS_TERMINATED -> HTTP_SERVING -> CLOSED
  BLOCK          -> LOCALLY_TERMINATED -> CLOSED
  UNAVAILABLE    -> FAILURE_POLICY -> CLOSED or RAW_TUNNEL
```

Illegal transitions must fail closed with respect to local state correctness; they must not silently create an allow path.

Connection state must not be shared globally in a way that lets one connection overwrite another connection's decision or metadata.

---

# 10. TLS ClientHello Handling

For intercepted TLS:

1. Read only up to the configured ClientHello byte limit.
2. Enforce a deadline.
3. Support fragmented TLS records.
4. Parse observable metadata such as:
   - SNI;
   - ALPN offers;
   - version information available in ClientHello.
5. Preserve all bytes consumed during the peek operation.
6. If decision is BYPASS or METADATA_ONLY, forward the exact buffered bytes before tunneling remaining traffic.
7. Never silently change a TLS parsing failure into a DECRYPT decision.
8. Record partial metadata honestly.

Important cases:

- no SNI;
- malformed ClientHello;
- fragmented record;
- TLS 1.2;
- TLS 1.3;
- ALPN containing h2;
- ALPN containing http/1.1;
- unknown extensions;
- ClientHello exceeding configured limit.

---

# 11. TLS Modes

## 11.1 BYPASS

The proxy must not decrypt application traffic.

It forwards the connection as raw TCP after the authoritative engine allows bypass.

Any ClientHello bytes already read must be replayed byte-for-byte to the upstream connection.

Request-level HTTP inspection coverage must not be claimed.

## 11.2 METADATA_ONLY

Same transport behavior as BYPASS, but TLS metadata may be recorded as coverage/evidence.

No request body/header semantic inspection is claimed.

## 11.3 DECRYPT

The proxy:

1. receives authoritative permission to decrypt;
2. selects or generates the appropriate leaf certificate;
3. terminates downstream TLS;
4. negotiates HTTP/1.1 or HTTP/2;
5. opens verified TLS to the real upstream;
6. gates each application request before forwarding.

There must be no silent downgrade from DECRYPT to BYPASS after a handshake, CA, or upstream verification failure.

The failure must be represented by a stable reason and handled according to the configured contract.

---

# 12. CA and Leaf Certificate Management

Runtime CA auto-generation due to missing files is forbidden.

M4 must provide an explicit provisioning workflow.

Example conceptual operation:

```text
ngfw-proxy ca init
```

or an installation script with equivalent behavior.

Security requirements:

- CA private key file mode: 0600.
- CA certificate may be 0644.
- private key parent directory should be 0700.
- API/UI must never return private key data.
- startup must fail health checks if required CA artifacts are missing or invalid.
- no emergency self-signed fallback CA.
- CA fingerprint may be exposed read-only for lab trust installation.

Leaf certificate generation requirements:

- random serial number;
- correct DNS or IP SAN;
- short validity;
- bounded cache;
- cache TTL;
- concurrent generation deduplication for the same target;
- no unbounded hostname map.

The planning agent should determine whether an existing cache utility can be reused or whether a small bounded LRU must be introduced.

---

# 13. Upstream TLS Verification

When connecting to an HTTPS upstream after decryption:

- verify the certificate chain;
- verify the expected hostname when a hostname is known;
- use the correct SNI;
- support configured/system trust roots;
- negotiate `h2` or `http/1.1`;
- never use production `InsecureSkipVerify=true`.

Failure maps to an explicit upstream TLS verification error.

Recommended HTTP response toward the client:

```text
502 Bad Gateway
```

The event must distinguish this from:

- malicious request block;
- detector unavailable;
- local overload;
- downstream handshake failure.

---

# 14. Honest TLS Limitations

M4 must explicitly represent cases it cannot securely inspect.

## 14.1 ECH / unavailable SNI

If required routing/decryption identity cannot be observed, record partial TLS metadata.

A strict decrypt profile must not silently bypass and pretend complete coverage.

## 14.2 Certificate pinning

If the client rejects the generated MITM certificate:

- record handshake failure;
- do not silently switch to bypass.

## 14.3 Upstream mTLS

If upstream requires a client certificate that M4 cannot supply:

- return an explicit unsupported/failure reason;
- recommend an exclusion if appropriate;
- do not impersonate a client identity.

## 14.4 HTTP/3 / QUIC

M4 does not decrypt HTTP/3.

A strict profile may explicitly block UDP/443 to encourage TCP fallback.

If UDP/443 is blocked for this purpose:

- it must be configuration-driven;
- observable in counters/events;
- not described as HTTP/3 inspection.

---

# 15. Dedicated Request-Gate IPC

High-rate request gating must not be tunneled through a management-oriented IPC path if that path is not designed for low-latency bounded request traffic.

Use a dedicated Unix socket, conceptually:

```text
/run/ngfw/request-gate.sock
```

Protocol version:

```text
1
```

Required operations:

```text
open_connection
evaluate_request
report_request_result   // optional but idempotent
gate_health_ping
```

## 15.1 Framing

Use explicit bounded framing.

Acceptable examples:

- length-prefixed JSON;
- another fixed/bounded binary framing scheme.

Do not use unbounded newline-delimited messages.

Every frame must enforce:

- protocol version;
- maximum message bytes;
- read deadline;
- write deadline;
- malformed-frame rejection.

## 15.2 Generation and decision identity

Every engine response must include:

```text
config_generation
decision_id
```

The proxy must not apply a response to the wrong request/connection.

A response that is stale relative to a connection/request state transition must be rejected rather than reused.

## 15.3 Error classes

Stable protocol errors should distinguish at least:

- malformed request;
- unsupported protocol version;
- oversized frame;
- deadline exceeded;
- engine unavailable;
- session/policy correlation unavailable;
- stale generation;
- internal engine error.

Transport errors must not become CLEAN inspection results.

---

# 16. HTTP Request Identity

Each request must have:

```go
type RequestContext struct {
    RequestID      string
    ConnectionID   string
    SessionID      string

    RequestOrdinal uint64

    Protocol string // HTTP/1.1 or HTTP/2
    StreamID *uint64 // only if reliably available

    Method string
    Scheme string
    Host   string

    StartedAt time.Time

    Generation uint64
}
```

Requirements:

- `RequestID` must be collision-resistant.
- `RequestOrdinal` is per connection and monotonically increasing.
- An ordinal must never be falsely called the HTTP/2 wire stream ID.
- Request-local buffers, verdicts, deadlines, detector output, and errors must not be stored as shared mutable connection state.

---

# 17. HTTP Parsing Rules

Use the standard Go HTTP stack for protocol parsing.

Do not implement a custom HTTP/2 frame parser for M4.

The standard parser must remain authoritative for:

- HTTP/1.1 framing;
- chunked decoding;
- HTTP/2 stream-to-request parsing.

Malformed or ambiguous framing must be rejected.

The proxy must not forward a request that the standard parser rejected.

Request inspection normalization must not rewrite the actual forwarded payload, except for normal reverse-proxy hop-by-hop header handling.

---

# 18. Request Resource Limits

Before inspection, enforce:

- maximum URL length;
- maximum total header bytes;
- maximum header count;
- maximum raw request body;
- maximum decompressed body;
- maximum decompression ratio;
- request deadline;
- concurrency limit;
- per-client concurrency limit;
- queue capacity.

Recommended mappings:

| Condition | Result |
|---|---|
| malformed HTTP | 400 |
| URL too long | 414 |
| body too large under strict policy | 413 |
| headers too large | 431 |
| local concurrency/queue overload | 429 or stable 503 |
| inspection unavailable + fail-close | 503 |
| malicious request | 403 |
| upstream connection/TLS failure | 502 |

The exact code/status contract should be made stable in the code-level planning document.

---

# 19. Body Processing

## 19.1 Raw body

A gated request body is read into a bounded buffer before upstream forwarding.

If the raw body exceeds the configured inspection cap:

- strict `BLOCK` behavior must block with a coverage/limit reason;
- `ALLOW_PARTIAL` behavior may allow according to explicit profile semantics, but must mark coverage PARTIAL;
- never claim complete inspection.

## 19.2 Compression

M4 should support bounded decoding of at least:

- gzip;
- deflate.

Use:

- decoded byte cap;
- decompression ratio cap;
- deadline/cancellation.

A decompression bomb must terminate inspection without exhausting memory.

Unsupported encoding must map to an explicit state.

It must not become CLEAN.

## 19.3 Detector representation versus forwarded representation

Normalization is for detector input.

The actual application request forwarded upstream must preserve client semantics.

Do not forward the normalized detector representation as though it were the original request.

---

# 20. Normalized HTTP Request

M4 should create a bounded detector representation similar to:

```go
type NormalizedHTTPRequest struct {
    RequestID string

    Method string
    Scheme string
    Host   string
    Path   string
    QueryMetadata QueryMetadata

    Headers map[string]string

    ContentType string

    InspectionBody []byte

    RawBodyBytes        int
    DecodedBodyBytes    int

    Truncated             bool
    UnsupportedEncoding   bool
    DecompressionLimited  bool

    Protocol string
}
```

Sensitive header values must be removed before detector/event persistence.

At minimum redact:

- Authorization;
- Proxy-Authorization;
- Cookie;
- Set-Cookie;
- X-API-Key;
- token/secret/password-like fields.

Avoid persisting raw query strings.

Use redacted keys or a simple `query_present` flag where sufficient.

---

# 21. Synchronous Suricata Request Inspector

M4 must not use the current toy in-process SQLi/XSS string matcher as the production request verdict source.

The production request inspector must expose a bounded synchronous interface conceptually equivalent to:

```go
type RequestInspector interface {
    Inspect(ctx context.Context, req NormalizedHTTPRequest) RequestInspectionResult
}
```

The result must explicitly distinguish:

```text
CLEAN
MALICIOUS
UNAVAILABLE
PARTIAL
ERROR
```

Exact enum organization may vary, but unavailable/partial/error states must never collapse to CLEAN.

---

# 22. Suricata Request Representation

M4 may inspect normalized requests by building a finite synthetic TCP conversation in PCAP form and submitting it to a dedicated Suricata Unix-socket PCAP worker.

The representation is semantic HTTP inspection, not HTTP/2 frame inspection.

For HTTP/2 requests:

- translate the parsed HTTP semantics into a finite HTTP/1.1-equivalent request representation for Suricata signature inspection;
- do not claim HTTP/2 frame-level parser coverage.

The synthetic PCAP builder must have golden tests proving deterministic output.

The test fixture must prove Suricata accepts the generated capture and produces expected EVE output for representative rules.

---

# 23. Synthetic PCAP Safety

Each job must use:

- unique random work directory;
- restrictive permissions;
- generated filenames unrelated to user-controlled host/path;
- bounded capture size;
- deterministic packet construction.

If a packet-building dependency is introduced, pin it explicitly.

The generated flow must contain enough TCP semantics for Suricata to process the request reliably.

The exact packet sequence, sequence numbers, link type, and checksum strategy should be decided in the code-level plan and then locked with golden tests.

---

# 24. Suricata Worker Pool

Use a bounded pool.

Recommended default:

```text
2 workers
```

Recommended maximum for the lab default configuration:

```text
4 workers
```

Each worker may process only one active request job at a time.

A conceptual worker job lifecycle:

```text
QUEUED
 -> WORKDIR_CREATED
 -> PCAP_WRITTEN
 -> SUBMITTED
 -> RUNNING
 -> COMPLETED
 -> EVE_CONSUMED
 -> CLEANUP
 -> DONE
```

Failure can transition to:

```text
UNAVAILABLE
TIMEOUT
MALFORMED_OUTPUT
CANCELLED
```

The worker must always release:

- queue slot;
- semaphore token;
- temporary resources.

Cancellation must not leak a permanently occupied worker.

---

# 25. Suricata Completion Contract

A fixed sleep such as:

```text
sleep 500ms
```

must never be the definition of completion.

Completion must be based on the Unix-socket protocol and job state.

The adapter should use the available socket operations such as:

- submit PCAP;
- query current PCAP;
- inspect queue/list state;
- inspect queue count.

The exact polling strategy must:

- obey context cancellation;
- obey deadline;
- use bounded polling interval/backoff;
- finish only when the submitted job is no longer active/queued;
- then consume the bounded job-local output.

If the adapter cannot prove completion, the result is UNAVAILABLE or ERROR, not CLEAN.

---

# 26. EVE Request Result Correlation

The request worker output must be isolated per job.

A detector result from an old request must not be attached to another request.

Required correlation attributes should include:

- request job ID;
- request ID;
- worker identity;
- time bounds;
- job-local output location or event identity.

Normalize only supported relevant event types.

Preserve useful alert metadata:

```text
signature ID
signature message
category
severity
Suricata action
timestamp
```

Malformed or oversized EVE output maps to an explicit unavailable/error state.

---

# 27. Request Inspection Result

Conceptual contract:

```go
type RequestInspectionResult struct {
    RequestID string

    Status RequestInspectionStatus
    Coverage RequestCoverage

    Alerts []RequestAlert

    Detector string
    DetectorVersion string

    StartedAt  time.Time
    CompletedAt time.Time

    FailureReason GateFailureReason
}
```

`RequestCoverage` should distinguish at least:

```text
NOT_REQUESTED
COMPLETE
PARTIAL
UNAVAILABLE
```

This allows the system to represent:

- clean and fully inspected;
- allowed under fail-open without full inspection;
- body truncation/unsupported encoding;
- detector outage.

---

# 28. Deterministic Request Decision Table

M4 does not use the future M5 risk engine.

Request decision must be deterministic.

Apply this order:

1. Base connectivity policy must already be ALLOW.
2. If gate not requested:
   - `NOT_REQUESTED`
   - do not claim inspection.
3. If detector reports a configured blocking alert:
   - `BLOCK`
   - scope `REQUEST`
   - reason `MALICIOUS_REQUEST`.
4. If inspection completes and no blocking alert exists:
   - `ALLOW`
   - coverage `COMPLETE`.
5. If inspection is unavailable:
   - fail mode `CLOSE` -> `BLOCK`, reason `INSPECTION_UNAVAILABLE`;
   - fail mode `OPEN` -> `ALLOW`, coverage `UNAVAILABLE`, increment fail-open counter.
6. If inspection is partial due to a configured coverage limitation:
   - apply the profile's explicit partial/oversize/encoding rule;
   - never rewrite the result as complete.
7. A request block does not automatically revoke the M2 session.

The engine owns this final decision.

---

# 29. Request Decision Contract

Conceptual output:

```go
type RequestDecision struct {
    DecisionID string

    RequestID    string
    ConnectionID string
    SessionID    string

    Generation uint64

    Action RequestAction // ALLOW | BLOCK

    Scope EnforcementScope // REQUEST

    Coverage RequestCoverage
    Reason   GateFailureReason

    PolicyID  string
    ProfileID string

    Alerts []RequestAlert
}
```

The proxy executes this result.

It does not reinterpret it.

---

# 30. HTTP/1.1 Forwarding

For a clean allowed request:

1. Complete request inspection.
2. Receive authoritative ALLOW.
3. Construct the upstream request.
4. Remove required hop-by-hop headers.
5. Preserve:
   - method;
   - path;
   - query semantics;
   - allowed headers;
   - body semantics.
6. Forward using a reusable bounded transport.
7. Bound upstream connect/header timeouts.
8. Return upstream response.

Do not instantiate an entirely new heavyweight reverse proxy transport object for every request if the standard transport can be safely reused.

Blocked requests must not create/send the application request upstream.

---

# 31. HTTP/2 Request Isolation

HTTP/2 correctness is defined by request isolation.

One downstream TLS connection may contain multiple concurrent request streams.

Example:

```text
Request A: clean
Request B: SQL injection
Request C: clean
```

Required result:

```text
A -> upstream
B -> blocked locally
C -> upstream
```

M4 must not automatically close the entire connection simply because B is malicious.

Per-request mutable state includes:

- body buffer;
- inspection state;
- detector alerts;
- deadline;
- final decision;
- upstream forwarding state.

Connection-level state may include:

- ConnectionID;
- authoritative open-connection decision;
- generation;
- atomic request ordinal;
- safe shared transport/context.

The implementation must pass race tests for concurrent HTTP/2 requests.

---

# 32. Concurrency Model

All M4 concurrency must be bounded.

A reasonable design has distinct limits for:

- accepted proxy connections;
- active request gates;
- requests per client;
- HTTP/2 concurrent streams;
- Suricata inspection queue;
- Suricata workers;
- IPC frame processing;
- certificate generation.

Avoid:

```go
go inspect(request)
```

with no controlling semaphore/worker pool.

Any goroutine started by M4 must have:

- owner;
- cancellation path;
- bounded lifetime;
- cleanup path.

---

# 33. Failure Semantics

M4 must represent failure origin precisely.

Do not reduce all failures to a generic 500.

At minimum distinguish:

## Client/input failures

- invalid HTTP framing;
- URL too long;
- headers too large;
- body too large;
- decompression limit;
- unsupported content encoding.

## Gate infrastructure failures

- engine unavailable;
- IPC timeout;
- stale generation;
- request queue full;
- Suricata unavailable;
- Suricata timeout;
- malformed detector output.

## TLS failures

- downstream TLS handshake failure;
- missing/invalid CA;
- client pinning failure;
- upstream verification failure;
- unsupported upstream mTLS;
- insufficient metadata for strict decrypt.

## Upstream failures

- connect failure;
- connection timeout;
- TLS verification failure;
- upstream protocol error.

Every failure must map to:

- stable reason code;
- appropriate HTTP behavior;
- bounded security/health event;
- counter.

---

# 34. Fail-Open and Fail-Close

Fail mode is an authoritative policy/profile property.

The proxy must not use a local environment flag as the source of truth for production M4.

## Fail-open

When inspection infrastructure is unavailable:

- allow the request only if engine policy says OPEN;
- mark coverage UNAVAILABLE or PARTIAL;
- emit an event;
- increment fail-open counter.

## Fail-close

When inspection infrastructure is unavailable:

- block the request;
- use an availability failure response, normally 503;
- reason must say inspection unavailable, not malicious;
- increment fail-close counter.

Malicious block and fail-close block are not the same event.

---

# 35. Security Events and Privacy

M4 security events should include bounded metadata such as:

- RequestID;
- ConnectionID;
- SessionID;
- policy/profile ID;
- config generation;
- method;
- host;
- redacted/truncated path;
- protocol;
- content type;
- body size;
- optional safe body hash;
- detector SID/category;
- final decision;
- coverage;
- reason;
- timestamps.

Never store by default:

- raw Authorization value;
- cookies;
- raw bearer tokens;
- CA private key;
- full raw request body;
- unredacted token-bearing query string.

M4 request enforcement scope must remain distinct from M3 packet/session enforcement scope.

---

# 36. Health Model

M4 health must distinguish configuration from actual readiness.

Conceptual health:

```go
type RequestGateHealth struct {
    Configured bool

    ProxyReachable bool

    HTTPListenerReady  bool
    HTTPSListenerReady bool

    CALoaded bool

    WorkersReady int
    WorkersTotal int

    QueueDepth int
    QueueDrops uint64

    ActiveConnections int
    ActiveRequests    int

    Counters map[string]uint64

    UpdatedAt time.Time
}
```

Minimum counters:

```text
intercepted
bypassed
metadata_only
decrypted
request_allowed
request_blocked
fail_open
fail_close
inspection_timeout
inspection_unavailable
queue_rejected
tls_handshake_fail
upstream_verify_fail
body_limit
header_limit
decompression_limit
unsupported_encoding
stale_decision
```

`configured=true` must never imply `healthy=true`.

---

# 37. Capability Reporting

The capability endpoint must state honestly what M4 does and does not support.

Examples:

- HTTP/1.1 synchronous request gate: supported/unsupported.
- HTTP/2 semantic request gate: supported/unsupported.
- TLS decryption: supported when CA ready.
- HTTP/3 decryption: unsupported.
- ECH decryption: unsupported.
- upstream mTLS impersonation: unsupported.
- response-body malware scanning: unsupported.
- ML request verdict: unsupported in M4.

Do not advertise future M5 capability as present.

---

# 38. Activation, Commit, Rollback, and Restart

M4 must integrate into the existing activation model instead of applying nftables/proxy state ad hoc.

The M4 activation artifact should bind enough information to detect stale/corrupt state.

Conceptually include:

- compiled proxy selector plan;
- selector/ruleset hash;
- request-gate configuration version/hash;
- CA certificate fingerprint;
- required listener ports;
- request ruleset ID/hash.

Do not persist or expose a private-key hash as sensitive telemetry merely for convenience.

## 38.1 Preflight before kernel mutation

Before mutating dataplane state, validate:

- configuration;
- gate plan compilation;
- proxy binary/runtime availability as required;
- listen-port conflicts;
- CA artifacts when DECRYPT is required;
- request ruleset/Suricata worker prerequisites;
- IPC path configuration.

If preflight fails, do not partially apply kernel interception.

## 38.2 Commit

Conceptual ordering:

1. Validate candidate.
2. Compile canonical connectivity program.
3. Compile M3 selection if enabled.
4. Compile M4 gate selection.
5. Preflight M4 artifacts.
6. Prepare activation snapshot/journal.
7. Safely reconfigure/pause gate as needed.
8. Apply nftables/network activation.
9. Verify expected objects.
10. Publish new running generation.
11. Resume/confirm request gate readiness.
12. Clear activation journal only after success.

The exact ordering must preserve existing M1/M2/M3 rollback invariants.

## 38.3 Rollback

Rollback must restore the previous M4 selector/profile state.

The configuration generation remains monotonic.

Do not reuse stale request decisions after rollback.

## 38.4 Restart

On engine/proxy restart:

- rebuild selection from running state;
- reopen the dedicated gate IPC;
- discard stale in-memory request decisions;
- preserve authoritative persisted configuration;
- do not create a new CA automatically;
- health remains degraded until required workers/listeners are actually ready.

---

# 39. Backward Compatibility

With M4 globally disabled:

- M1 behavior must remain unchanged.
- M2 session behavior must remain unchanged.
- M3 OFF/IDS/IPS behavior must remain unchanged.
- no transparent interception selector may unexpectedly capture traffic.
- no CA requirement may prevent engine startup.
- no Suricata request-worker requirement may prevent non-M4 operation.

M4 must be an opt-in capability.

---

# 40. Prototype Debt That M4 Must Resolve

The current codebase contains useful prototypes, but M4 must not simply promote all prototype behavior to production.

Known architectural debt to resolve includes:

1. Proxy-local configuration manager.
2. Proxy-local legacy `engine.Engine`.
3. `enforcement.NewMemory()` as a second firewall authority.
4. Local fail-close environment flag as policy source.
5. Fixed upstream URL instead of transparent original destination.
6. Toy in-process SQLi/XSS signature matcher as production verdict source.
7. Runtime MITM CA auto-generation.
8. Request identity based only on simple monotonic process counter.
9. Lack of dedicated bounded request-gate IPC.
10. Lack of true HTTP/2 request isolation contract.
11. Lack of synchronous detector completion semantics.
12. Potentially unbounded/insufficiently bounded runtime structures.

The code-level planning agent must map each debt item to exact current files and symbols.

---

# 41. Implementation Workstreams

The following workstreams define the required M4 implementation shape.

They are intentionally more detailed than a milestone list but intentionally less specific than an exact patch plan.

## Workstream A — Baseline and discovery

Goals:

- record current commit and dirty tree;
- run local baseline tests that are available;
- identify exact current proxy/engine/dataplane/config/domain integration points;
- run Linux capability probes where possible;
- do not change M1/M2/M3 acceptance status.

Exit condition:

- capability assumptions are known;
- code-level planner can map M4 to real symbols.

## Workstream B — Domain and configuration contracts

Goals:

- add M4 enums/types;
- add clone/JSON behavior;
- add defaults;
- add validation;
- add TLS exclusion matching semantics;
- add duplicate/shadow checks.

Exit condition:

- invalid M4 configurations are rejected before activation.

## Workstream C — Canonical gate selection

Goals:

- compile immutable M4 gate plan from canonical connectivity program;
- preserve first-match reachability semantics;
- bind to generation.

Exit condition:

- M4 cannot create a new allow path.

## Workstream D — Transparent interception dataplane

Goals:

- compile NGFW-owned proxy interception table/chains;
- recover original destination;
- prove DNAT interaction;
- avoid recursive proxy interception.

Exit condition:

- selected ALLOW traffic reaches proxy with correct destination;
- unselected traffic follows old path.

## Workstream E — Dedicated request-gate IPC

Goals:

- bounded protocol;
- versioning;
- deadlines;
- open-connection operation;
- evaluate-request operation;
- health ping;
- stable error classes.

Exit condition:

- proxy and engine communicate without duplicating policy state.

## Workstream F — Proxy connection lifecycle and TLS

Goals:

- random connection IDs;
- bounded ClientHello peek;
- BYPASS/METADATA/DECRYPT;
- CA management;
- upstream TLS verification;
- honest limitation handling.

Exit condition:

- clean TLS path behaves correctly without silent security downgrade.

## Workstream G — HTTP request gate

Goals:

- request IDs;
- body/header limits;
- decompression;
- no-forward-before-verdict;
- HTTP/1.1 forwarding;
- HTTP/2 isolation.

Exit condition:

- clean requests pass;
- gated blocked requests never reach upstream.

## Workstream H — Synchronous Suricata adapter

Goals:

- normalized request;
- synthetic PCAP;
- Unix-socket worker;
- bounded pool;
- EVE result normalization;
- reliable completion.

Exit condition:

- representative SQLi/XSS detection returns deterministic request result.

## Workstream I — Engine final request decision

Goals:

- deterministic M4 decision table;
- generation checks;
- session link;
- request-scope event.

Exit condition:

- final verdict comes only from authoritative engine state.

## Workstream J — Health, observability, activation, deployment

Goals:

- health/capabilities;
- counters;
- bounded events;
- activation snapshot;
- rollback/restart;
- systemd/deploy;
- acceptance runner.

Exit condition:

- M4 is operable and testable as a system.

---

# 42. Core Algorithms

This section defines intended logic that the code-level planner must preserve.

## 42.1 Connection-open algorithm

Pseudo-logic:

```text
accept TCP connection
  |
  +-> enforce connection capacity
  |
  +-> generate ConnectionID
  |
  +-> recover original destination
  |      failure -> stable gate failure
  |
  +-> if TLS:
  |      bounded ClientHello peek
  |      collect SNI/ALPN metadata
  |
  +-> send open_connection to engine
         |
         +-> engine resolves session/policy/profile/generation
         +-> engine evaluates TLS exclusion
         +-> engine returns INSPECT_HTTP (non-TLS) / BYPASS / METADATA_ONLY / DECRYPT / BLOCK
  |
  +-> reject stale/malformed response
  |
  +-> execute returned mode
```

## 42.2 Request-gate algorithm

```text
HTTP parser creates request
  |
  +-> generate RequestID
  +-> increment per-connection RequestOrdinal
  +-> enforce per-client/global concurrency
  +-> validate URL/header limits
  +-> read bounded raw body
  +-> decode supported compression with limits
  +-> build normalized detector request
  +-> invoke synchronous detector with deadline
  +-> send detector result + request context to authoritative engine
  +-> engine creates final RequestDecision
  |
  +-> if BLOCK:
  |      return local response
  |      DO NOT create/send upstream application request
  |
  +-> if ALLOW:
         construct upstream request
         send upstream
         relay response
```

## 42.3 Detector failure algorithm

```text
detector invocation
  |
  +-> success, blocking alert -> MALICIOUS
  |
  +-> success, no blocking alert -> CLEAN
  |
  +-> timeout/socket/worker failure -> UNAVAILABLE
  |
  +-> truncated/unsupported/limit -> PARTIAL or explicit limit state
```

Then engine applies profile failure semantics.

## 42.4 HTTP/2 isolation algorithm

```text
connection context:
    immutable/open-decision state
    atomic ordinal
    shared safe transport

stream/request A:
    independent buffer/result/decision

stream/request B:
    independent buffer/result/decision

stream/request C:
    independent buffer/result/decision
```

No request may reuse another request's mutable decision object.

---

# 43. Test Strategy

Testing must follow a pyramid.

## 43.1 Unit tests

Required areas:

- config validation;
- enum zero/unknown values;
- TLS exclusions;
- gate selection;
- IPC framing;
- stale generation handling;
- ClientHello fragmentation;
- request limits;
- decompression bombs;
- redaction;
- request decision table;
- certificate cache bounds;
- synthetic PCAP golden output;
- EVE normalization;
- queue/worker cancellation.

## 43.2 Fuzz tests

High-value fuzz targets:

- request-gate IPC decoder;
- ClientHello parser/peek wrapper;
- TLS exclusion canonicalizer;
- compressed body decoder;
- EVE request parser;
- normalized request conversion.

## 43.3 Race tests

At minimum cover packages responsible for:

- proxy;
- engine;
- inspection;
- gate IPC;
- session interaction.

Special race scenario:

- one HTTP/2 connection;
- multiple concurrent requests;
- one malicious;
- one clean;
- concurrent cancellation/timeouts.

## 43.4 Local integration tests

Use fake or controlled components for:

- engine/proxy IPC;
- request detector adapter;
- upstream server;
- TLS CA;
- HTTP/2 server.

Prove no-forward-before-verdict with an upstream nonce/access log.

## 43.5 Linux integration tests

Must cover actual:

- nftables interception;
- original destination;
- DNAT interaction;
- restart;
- real Suricata Unix socket;
- real EVE result;
- real TLS interception.

## 43.6 Full regression

At major checkpoints run:

- Go tests;
- vet;
- race-targeted suite;
- frontend tests/build if changed.

Do not run full repository tests after every small edit.

---

# 44. Mandatory Linux Acceptance Scenarios

The detailed acceptance matrix remains the authoritative list, but the following scenarios are core completion evidence.

## HTTP

- clean HTTP/1.1 request reaches upstream;
- HTTP/1.1 SQLi is blocked before upstream;
- HTTP/1.1 XSS is blocked before upstream;
- chunked request is inspected correctly;
- body/header/URL limits behave according to profile;
- gzip/deflate behavior is bounded.

## HTTPS

- trusted lab CA allows clean decrypted HTTPS;
- SQLi over HTTPS is blocked before upstream;
- XSS over HTTPS is blocked before upstream;
- TLS bypass exclusion tunnels correctly;
- upstream invalid certificate causes explicit verification failure;
- client pinning failure is not silently bypassed;
- upstream mTLS limitation is explicit.

## HTTP/2

On one connection:

- clean request succeeds;
- malicious request is blocked;
- another clean request still succeeds;
- no cross-request state contamination.

## Failure behavior

- Suricata timeout + fail-open;
- Suricata timeout + fail-close;
- request queue full;
- proxy restart;
- engine restart;
- stale generation response;
- malformed detector output.

## NAT

- DNAT public HTTPS target is intercepted;
- proxy dials correct post-DNAT/original effective destination;
- request remains linked to authoritative M2 session.

## Regression

- M4 OFF preserves M1/M2/M3 behavior.

---

# 45. Evidence Requirements

An acceptance PASS requires real evidence, not only a test script return code.

Recommended evidence per case:

```text
test metadata
running config snapshot
nftables relevant chains/counters
conntrack entry where relevant
proxy logs
engine logs
Suricata socket/EVE evidence
client output
upstream access log
packet capture where useful
result.json
```

For a blocked request, the strongest evidence is:

1. client sent the request;
2. proxy received it;
3. detector/engine produced BLOCK;
4. upstream access log does not contain the request nonce;
5. packet/application capture supports the same conclusion.

---

# 46. Required Output From the Future Code-Planning Agent

This specification is intentionally not the final file/function patch plan.

Before coding, the high-capability planning agent must read:

- this document;
- the other M4 specification documents;
- the current repository source;
- current tests;
- current deployment scripts.

It must then create a **code-level implementation plan**.

Recommended output file:

```text
docs/m4/CODE_LEVEL_IMPLEMENTATION_PLAN.md
```

That plan must contain, for every implementation task:

1. Exact current files to modify.
2. Exact new files to create.
3. Existing functions/types to reuse.
4. Existing functions/types to refactor or retire.
5. New functions/types and intended signatures.
6. Call flow before and after the change.
7. Concurrency ownership.
8. Data ownership.
9. Error propagation.
10. Configuration-generation handling.
11. Unit tests to add or update.
12. Integration tests to add or update.
13. Commands to run at the smallest useful scope.
14. Definition of Done.
15. Dependencies on prior tasks.
16. Expected diff boundaries.
17. Risks and rollback strategy.

The planning agent must also map all known prototype debt from Section 40 to exact symbols.

It must not start implementation until the code-level map for the current dependency layer is internally consistent.

It does not need to pre-plan every implementation line for all future tasks if the current source makes later details uncertain.

---

# 47. Required Planning-Agent Questions to Resolve From Source

The code-planning agent must answer these using the actual repository rather than guessing:

1. What exact canonical M2/M3 policy compilation function should M4 reuse?
2. What exact generation object is authoritative for gate decisions?
3. How should M4 extend the existing `ActivationSnapshot` without breaking old snapshots?
4. What exact runtime service owns request decisions?
5. Should the dedicated gate IPC reuse any transport/framing utility from existing engine IPC?
6. What is the correct package boundary for request-gate domain types?
7. Which current proxy prototype types can be salvaged safely?
8. Which current `inspection.HTTPRequest` fields/logic should be reused versus replaced?
9. What current MITM helper behavior must be hardened?
10. How should original-destination recovery integrate with the selected interception method?
11. How are proxy-created upstream sockets excluded from interception?
12. How is DNAT destination represented at the point the proxy receives the socket?
13. Where should Suricata request workers live operationally?
14. How is job-local EVE output isolated?
15. How should engine request events connect to the current security event store?
16. What API handler pattern should health/capabilities follow?
17. Which systemd sandbox settings must change for the proxy?
18. Which existing tests can be extended instead of creating duplicate test frameworks?
19. What package boundaries minimize cyclic imports?
20. What legacy proxy code becomes unreachable and should be deleted after migration?

---

# 48. Code-Planning Quality Rules

The future planning agent should optimize for execution efficiency.

It must not:

- repeatedly rescan the repository;
- rewrite this specification;
- create a second competing architecture;
- refactor unrelated code;
- plan exact implementation for components whose required capability probe has not yet succeeded.

It should:

- build a one-time repository integration map;
- use symbol search and call-site search;
- attach each planned patch to a requirement;
- identify smallest relevant tests;
- use checkpoint-based broader regression;
- keep future coding tasks small and deterministic.

---

# 49. Definition of M4 Implementation Complete

M4 source implementation is complete when:

1. Production proxy no longer runs an independent firewall engine.
2. Canonical gate selection is compiled from authoritative policy state.
3. Transparent interception is integrated without creating an allow bypass.
4. Original destination behavior is proven in the supported Linux design.
5. Dedicated bounded gate IPC exists.
6. TLS BYPASS/METADATA/DECRYPT behavior exists.
7. Runtime CA auto-generation is removed.
8. Upstream TLS verification is strict.
9. HTTP/1.1 request gating is synchronous.
10. HTTP/2 request isolation is race-tested.
11. Request limits and decompression limits are bounded.
12. Synchronous Suricata request inspection exists.
13. Detector completion is protocol-driven, not sleep-driven.
14. Engine owns final request verdict.
15. Fail-open/fail-close semantics are explicit and observable.
16. Request events are bounded and redacted.
17. Activation/rollback/restart include M4 state.
18. Health/capabilities are honest.
19. M4 OFF preserves M1/M2/M3 behavior.
20. Local tests and checkpoint regressions pass.

This status is still not VM acceptance.

---

# 50. Definition of M4 VM Accepted

M4 may be marked VM accepted only when:

- required baseline M1/M2/M3 scenarios on the same topology are usable;
- M4 acceptance scenarios pass on Ubuntu;
- real nftables interception is used;
- real conntrack/NAT behavior is observed where applicable;
- real Suricata request workers are used;
- real HTTP/1.1 and HTTP/2 traffic is exercised;
- HTTPS decryption uses the provisioned lab CA;
- blocked request non-delivery is proven at the upstream server;
- failure modes are exercised;
- restart/rollback behavior is exercised;
- evidence artifacts are stored.

No local mock/unit result can substitute for this state.

---

# 51. Handoff Summary

M4 is the milestone that turns the existing proxy/inspection prototypes into an authoritative, synchronous request-security path.

The architectural target is:

```text
Linux dataplane selects an already-allowed gated flow
    ->
transparent proxy accepts it
    ->
proxy obtains authoritative connection policy from ngfw-engine
    ->
TLS is bypassed, observed, or decrypted according to policy
    ->
HTTP request is bounded and held
    ->
request inspector returns explicit evidence/coverage
    ->
ngfw-engine produces final request verdict
    ->
ALLOW: request is forwarded upstream
BLOCK: upstream never receives the application request
```

The central safety properties are:

- one authoritative engine;
- no policy duplication;
- no new allow path;
- no-forward-before-verdict;
- no detector failure becoming CLEAN;
- no unbounded request-processing resource;
- no silent TLS security downgrade;
- no cross-request contamination on HTTP/2;
- no false claim of VM acceptance.

The next high-capability agent should use this document as the behavioral and architectural contract, then produce a source-aware code-level implementation plan with exact files, functions, signatures, call flows, and tests. A lower-cost coding agent can then execute that plan task by task with minimal rediscovery and minimal token waste.
