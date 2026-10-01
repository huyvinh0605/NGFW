# M4 — HTTP/TLS Request Gate Implementation Specification

Specification date: 2026-09-28  
Baseline: M1/M2 are implemented and M3 production source is implemented. Ubuntu acceptance for M1/M2/M3 remains independent and must not be treated as PASS merely because M4 builds or tests pass.

Read together with:
- `docs/m4/CODE_CONTRACTS.md`
- `docs/m4/CODING_TASKS.md`
- `docs/m4-acceptance-matrix.md`
- `docs/adr/0004-m4-http-tls-request-gate.md`

## 1. M4 objective

M4 adds a synchronous HTTP/TLS request gate for selected policies. For any request whose profile requires the gate, no request header/body byte may be forwarded upstream before the gate returns a final verdict.

M4 must prove four core properties:

1. HTTP/1.1 and HTTP/2 requests are isolated by request context; a malicious stream/request must not leak its verdict into another clean request.
2. HTTPS selected by a `DECRYPT` policy is intercepted with a managed lab CA while the upstream TLS certificate is still verified.
3. Representative SQLi/XSS requests are blocked before they reach the server by the synchronous Suricata request adapter; clean requests are forwarded.
4. Detector timeout, proxy outage, oversize bodies, non-decryptable TLS, and unsupported encoding must have explicit status/failure behavior. They must never be silently converted into `CLEAN` or silently bypassed.

M4 also resolves the current architectural debt: `ngfw-proxy` must no longer create a separate `engine.Engine` and must not use `enforcement.NewMemory()` in production. `ngfw-engine` is the only authoritative owner of running configuration, matched policy/profile, session identity, and request decisions.

## 2. Mandatory scope

### 2.1. Included in M4

- Transparent interception for policy/profile-selected TCP HTTP/HTTPS traffic.
- Plain HTTP/1.1 request gate.
- A selected plain HTTP connection uses the explicit `INSPECT_HTTP` action: no TLS termination, and no upstream application request before synchronous inspection and the engine's final request verdict.
- TLS ClientHello peek to collect metadata observable before decryption.
- Per-profile TLS modes: `BYPASS`, `METADATA_ONLY`, `DECRYPT`.
- Lab CA, leaf certificate generation, and bounded certificate cache.
- HTTPS interception for HTTP/1.1 and HTTP/2 via ALPN.
- Per-request context: `RequestID`, `ConnectionID`, `SessionID`, protocol, request ordinal; an exact HTTP/2 wire stream ID may only be recorded when the public API/library exposes it reliably. It must never be fabricated.
- Bounded header/body/URL/decompression/concurrency/deadline behavior.
- Synchronous Suricata request adapter using persistent Unix-socket PCAP workers.
- Request-level ALLOW/BLOCK/UNAVAILABLE/PARTIAL semantics.
- Explicit fail-open/fail-close behavior for the request gate.
- TLS exclusions with validation and auditability.
- Explicit QUIC/HTTP3 limitation; optional UDP/443 blocking for strict profiles so clients can fall back to TCP.
- M4 health/capabilities, counters, security events, and request evidence metadata without raw secret payloads.
- Commit/rollback/restart must add or remove transparent interception atomically within NGFW-owned tables.
- Linux acceptance runner and evidence layout.

### 2.2. Explicitly excluded from M4

- ML classification/model lifecycle/correlation: M5.
- Risk Engine 0–100 and multi-detector scoring: M5.
- Threat-intelligence feeds and behavior/scan/DoS detectors.
- nDPI as an M4 completion requirement.
- Response-body malware/DLP inspection.
- A full WAF feature set; M4 may only claim the request gate and Suricata signatures actually tested.
- HTTP/3/QUIC decryption.
- ECH decryption.
- Upstream mTLS client-certificate impersonation.
- WebSocket frame inspection after `101 Switching Protocols`.
- Enterprise explicit-proxy authentication/PAC.
- HA/load balancing.

## 3. Ownership and process boundaries

### `ngfw-engine`

The engine is the only owner of:
- running config/generation;
- M2 session identity and NAT aliases;
- matched L3/L4 policy/profile;
- the decision to intercept/decrypt/gate;
- final request security verdicts;
- request/security event store and counters;
- commit/rollback snapshots.

### `ngfw-proxy`

The proxy is only a dataplane helper. It may:
- accept transparently intercepted TCP connections;
- recover the original destination;
- peek ClientHello;
- terminate TLS when the engine requires `DECRYPT`;
- parse HTTP through the standard Go HTTP stack;
- buffer requests within configured bounds;
- send request observations to the engine;
- forward upstream only after `ALLOW`;
- return block/error responses according to the engine verdict.

The proxy must not:
- load candidate/running configuration through `config.NewManager`;
- locally evaluate policy through the legacy `engine.Engine`;
- write nftables state;
- decide fail-open/fail-close outside the engine contract.

### Suricata request workers

M4 uses a dedicated Suricata pool in Unix-socket PCAP mode. It must not reuse the M3 live NFLOG/NFQUEUE process as though it were a synchronous API. Each worker handles at most one request job at a time. The pool must be bounded.

The Suricata Unix socket supports enqueueing `pcap-file` and querying `pcap-current`, `pcap-file-list`, and `pcap-file-number`. The adapter may report completion only after the job is no longer current/queued and all relevant output has been consumed. A fixed `sleep` is forbidden as a completion contract.

## 4. Packet path and transparent interception

### 4.1. Safety principle

The transparent proxy must never create a new allow path that bypasses M1/M2 policy.

The M4 compiler must derive interception selection from the same canonical connectivity program and first-match policy ordering already used by M2/M3. L3/L4 first-match behavior remains authoritative:
- matched `DROP/REJECT`: do not redirect; M1/M2 continues to drop/reject;
- matched `ALLOW` without a gate: do not redirect;
- matched `ALLOW` with an M4 gate: redirect/TPROXY to the M4 listener;
- no match: do not redirect; M1/M2 default policy decides.

Do not implement a second free-form string policy matcher inside the proxy.

### 4.2. Linux mechanism

T01 must capability-probe both candidate approaches. The ADR may promote a production path only after the probe.

Preferred lab MVP: nftables `redirect` in prerouting for selected TCP/80 and TCP/443 traffic, after the required DNAT semantics, combined with `SO_ORIGINAL_DST` or an equivalent mechanism so the proxy can recover the original destination. If the target kernel/nftables combination cannot reliably preserve/recover the destination for the required DNAT/NAT scenarios, the task becomes BLOCKED and the architecture must be updated to TPROXY + policy routing before continuing past T05.

Do not add interception rules to the `output` chain. Upstream connections created by the proxy must not recursively redirect back into the proxy.

M4 must own a dedicated table/chain namespace, for example `inet ngfw_proxy`, with an explicit schema version. Never `flush ruleset`.

### 4.3. Destination zone and NAT

Interception selection must preserve post-DNAT semantics. A public DNAT destination that resolves to a DMZ server must still expose the real server destination to the proxy so it dials the correct upstream. DNAT + HTTPS gate is a mandatory acceptance scenario.

## 5. TLS connection flow

When TCP/443 is intercepted:

1. The proxy accepts the connection and recovers the original destination.
2. It reads ClientHello with a bounded peek buffer and deadline without losing/consuming bytes required by later forwarding.
3. It parses observable SNI/ALPN/version metadata.
4. It sends `OpenConnection` to the engine with source, original destination, and ClientHello metadata.
5. The engine resolves the M2 session plus matched policy/profile and returns one of:
   - `BYPASS`: raw TCP tunnel; the buffered ClientHello must be forwarded byte-for-byte.
   - `METADATA_ONLY`: raw tunnel like BYPASS, while session/request coverage records metadata-only inspection.
   - `DECRYPT`: the proxy uses the configured CA to mint a leaf certificate and terminates client TLS.
   - `BLOCK`: terminate/respond according to the reason without dialing upstream.
   - `UNAVAILABLE`: apply the failure policy returned by the engine.
6. For `DECRYPT`, the proxy establishes verified TLS to the original upstream destination, uses the correct hostname/SNI when available, and verifies the certificate chain and hostname. `InsecureSkipVerify` is forbidden in production M4.
7. Downstream and upstream ALPN must support `h2` and `http/1.1`.

### Mandatory honest TLS limitations

- ECH or unavailable SNI: record `TLS_METADATA_PARTIAL`; a strict decrypt profile must not silently bypass.
- Client certificate pinning rejecting the MITM leaf: record handshake failure; never silently downgrade to bypass.
- Upstream mTLS requiring a client certificate: return `TLS_UPSTREAM_MTLS_UNSUPPORTED` unless the endpoint is explicitly excluded.
- HTTP/3/QUIC: no decryption. A profile may explicitly `BLOCK_UDP_443` to encourage TCP fallback, but this behavior must be visible and explicit.

## 6. CA and certificate lifecycle

`LoadMITMCA(..., create=true)` is a prototype behavior and must be replaced for production M4:

- Runtime must never generate a new CA simply because files are missing.
- Provide an explicit provisioning command/install step such as `ngfw-proxy ca init` or an equivalent script.
- CA certificate: 0644. CA private key: 0600. Parent directory: 0700. Ownership follows the deployment contract for the proxy account/root.
- API/UI must never read the private key.
- Leaf certificate cache must be bounded LRU, default 1024 entries, max TTL 24h. No unbounded map.
- Leaf validity must be short, default 7 days, with random serial numbers and correct DNS/IP SANs.
- Key/certificate parsing errors must make health degraded/down. Never generate a fallback CA/certificate at runtime.
- Provide a read-only CA fingerprint endpoint/command for lab client trust installation.

## 7. HTTP request gate

### 7.1. Request identity

Every request has:
- a collision-resistant random `RequestID`;
- a random `ConnectionID` per accepted downstream TCP connection;
- the authoritative `SessionID` from the engine when correlation succeeds;
- `Protocol`: HTTP/1.1 or HTTP/2;
- a monotonically increasing `RequestOrdinal` within the connection;
- nullable `StreamID`. Do not rename an ordinal to a fake HTTP/2 wire StreamID.

An HTTP/2 connection can carry multiple concurrent requests. All mutable state must belong to the individual request object/context. Body buffers, verdicts, deadlines, or detector results must never be shared as mutable connection-level fields.

### 7.2. No-forward-before-verdict

For a request requiring the gate:
- read and validate headers;
- read/buffer body within limits;
- build the normalized inspection representation;
- run the synchronous detector;
- ask the engine for the final request decision;
- only after `ALLOW` create/send the upstream request.

Tests must use upstream nonces/access logs to prove that blocked SQLi/XSS requests never reached the upstream server.

### 7.3. Limits

Recommended defaults:
- header bytes: 32 KiB;
- URL: 8 KiB;
- header count: 64;
- raw request body: 64 KiB;
- decompressed body: 256 KiB;
- decompression ratio: 20x;
- request inspection deadline: 2 s;
- ClientHello peek: 64 KiB, 2 s;
- max concurrent gate jobs: 128;
- per-client concurrent requests: 32;
- HTTP/2 max concurrent streams: 64;
- request Suricata workers: 2, maximum 4 in lab configuration;
- queued request jobs: 256.

Both item counts and byte capacity must be bounded, and reject/drop conditions must increment explicit counters.

### 7.4. Body and framing

- Go `net/http` is the wire parser for HTTP/1.1 and HTTP/2. Do not write a custom HTTP/2 frame parser for the proxy.
- Reject malformed or ambiguous framing; never forward a request that the parser considers invalid.
- Chunked HTTP/1.1 bodies are dechunked by the server stack before inspection.
- Inspect `gzip`/`deflate` with both a post-decompression byte cap and decompression-ratio cap.
- Unsupported content encoding returns `UNSUPPORTED_ENCODING`; behavior is determined by the profile.
- The forwarded raw body must preserve application semantics. Normalization is detector input only and must not rewrite client payload except for standard proxy hop-by-hop header handling.

## 8. Synchronous Suricata request adapter

M4 must not use the toy `DefaultSignatures` implementation as the production verdict source.

### 8.1. Request normalization

Create a bounded `NormalizedHTTPRequest` containing method, scheme, host, path/query, selected headers, content type, decoded inspection body, and metadata/truncation flags.

HTTP/2 requests are converted to a finite HTTP/1.1-equivalent semantic request for signature inspection. M4 may claim HTTP semantic signature coverage only; it must not claim HTTP/2 frame-level attack detection.

### 8.2. Synthetic PCAP

The adapter builds a finite PCAP representing a TCP conversation with enough handshake/request bytes for Suricata inspection. A pinned `gopacket/pcapgo` dependency may be used, but it must be version-locked and backed by golden tests. Sequence numbers, checksums, and link type must be accepted by the Suricata test fixture.

Each job uses a unique 0700 work directory. File names must not contain user-controlled host/path data.

### 8.3. Worker protocol

`RequestInspector.Inspect(ctx, request) -> RequestInspectionResult`.

Each worker:
1. acquires a bounded semaphore;
2. writes the PCAP;
3. enqueuees `pcap-file` through the Unix socket;
4. polls structured socket commands until completion or deadline;
5. reads bounded job-local EVE output and requires a matching terminal flow event before reporting complete coverage;
6. normalizes alerts;
7. removes temporary files according to retention policy;
8. releases the worker.

Timeout, socket error, or queue-full conditions mean `UNAVAILABLE`, never `CLEAN`.

## 9. M4 request decision semantics

M5 Risk Engine is not enabled in M4. Request decisions follow a deterministic table:

1. The base M2/M3 matched policy must be ALLOW. If it is not ALLOW, the gate must not create an allow path.
2. If the profile does not request the request gate: `NOT_REQUESTED`.
3. If the detector reports a blocking signature action or matching blocking SID: `BLOCK`, scope REQUEST.
4. If inspection completes with no blocking alert: `ALLOW`, coverage COMPLETE.
5. If inspection is unavailable, times out, is unsupported, or hits a coverage limit:
   - profile `CLOSE`: block the request with an availability/coverage failure reason; do not label it malicious;
   - profile `OPEN`: allow the request with `PARTIAL/UNAVAILABLE` coverage plus a security event/audit counter.
6. M4 must not automatically escalate a request block into a session block. In particular, a malicious HTTP/2 request must not kill unrelated clean requests on the same connection. Session escalation belongs to a later correlation/risk milestone if required.

Proxy HTTP responses:
- malicious block: 403;
- strict body/header limit: 413/431;
- inspection unavailable + fail-close: 503;
- invalid framing: 400;
- upstream connect/TLS verification failure: 502;
- local rate/concurrency overload: stable 503 or 429 behavior.

## 10. M4 configuration schema

Add the following semantics to the domain. Exact names may be adjusted, but the contract must remain equivalent:

```go
type RequestGateConfig struct {
    Enabled                    bool   `json:"enabled"`
    ListenHTTPPort             int    `json:"listen_http_port"`
    ListenHTTPSPort            int    `json:"listen_https_port"`
    RulesetID                  string `json:"ruleset_id"`
    WorkerCount                int    `json:"worker_count"`
    QueueItems                 int    `json:"queue_items"`
    MaxConcurrentRequests      int    `json:"max_concurrent_requests"`
    MaxPerClientRequests       int    `json:"max_per_client_requests"`
    MaxHTTP2Streams            int    `json:"max_http2_streams"`
    MaxDecompressedBodyBytes   int    `json:"max_decompressed_body_bytes"`
    MaxDecompressionRatio      int    `json:"max_decompression_ratio"`
    ClientHelloBytes           int    `json:"client_hello_bytes"`
    ClientHelloTimeoutMillis   int    `json:"client_hello_timeout_ms"`
}

type RequestGateProfile struct {
    Enabled                   bool   `json:"enabled"`
    FailMode                  string `json:"fail_mode"` // OPEN|CLOSE
    OversizeAction            string `json:"oversize_action"` // BLOCK|ALLOW_PARTIAL
    UnsupportedEncodingAction string `json:"unsupported_encoding_action"`
    BlockQUIC                 bool   `json:"block_quic"`
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
```

`Config` adds `RequestGate *RequestGateConfig` and `TLSExclusions []TLSExclusion`. `SecurityProfile` adds `RequestGate *RequestGateProfile`. Reuse the existing `SecurityProfile.TLSMode`.

Mandatory validation:
- M4 fields are active only when `request_gate.enabled` is true.
- A gate profile may only apply to an enabled ALLOW session policy; it must not open denied traffic.
- HTTPS request inspection requires `TLSMode=DECRYPT`.
- `BYPASS/METADATA_ONLY` must not claim request inspection coverage.
- `DECRYPT` requires CA artifact preflight before any kernel mutation.
- fail mode is only OPEN or CLOSE.
- listen ports and resource limits must be bounded; worker count <=4 under the default spec.
- TLS exclusions require canonical domains, CIDRs, and ports plus duplicate/shadow detection.
- `block_quic=true` is meaningful only with gate enabled + DECRYPT.
- M3 fail-open semantics remain unchanged for live IDS/IPS. M4 request fail-close must not turn the M3 NFQUEUE path into fail-close.

## 11. M4 IPC

Do not push high-rate request-gate traffic through management runtime IPC v3. Create a dedicated Unix socket `/run/ngfw/request-gate.sock` with a separate bounded, low-latency protocol.

Protocol version: `1`.

Operations:
- `open_connection`
- `evaluate_request`
- `report_request_result` (optional final telemetry; idempotent)
- `gate_health_ping`

Request/response framing must use length-prefixed JSON or another explicitly bounded frame. Newline-delimited unbounded framing is not allowed.

Every engine response carries `config_generation` and `decision_id`. The proxy must reject stale responses when the connection has already transitioned to a newer generation that invalidates the old policy contract.

## 12. Core domain contracts

See `CODE_CONTRACTS.md`. At minimum M4 must define:
- `ProxyConnectionContext`
- `ProxyConnectionDecision`
- `RequestContext`
- `RequestInspectionResult`
- `RequestDecision`
- `RequestCoverage`
- `GateFailureReason`
- `RequestGateHealth`

Do not reuse legacy `domain.Session`/`SecurityContext` as a second database. M4 links back to `RuntimeSession.SessionID`.

## 13. Commit, rollback, and startup

M4 extends `ActivationSnapshot` with request-gate plan/artifact hashes:
- proxy nft selector plan;
- request ruleset hash;
- CA certificate fingerprint. Do not expose/hash private-key material into API logs; key readability is a separate preflight check;
- gate config version.

Commit flow:
1. validate candidate;
2. compile M2/M3 + M4 selector;
3. preflight installed proxy/ruleset/CA/socket ports;
4. safely pause/reconfigure the gate;
5. apply nftables transaction/snapshot;
6. verify expected tables/chains/rules;
7. publish running config;
8. resume the gate.

Rollback must restore the previous M4 selection/profile with a monotonically increasing generation. Startup rebuilds proxy selection from the running snapshot. Stale request decisions must not survive restart.

## 14. Health and capabilities

Minimum API:
- `GET /api/v1/request-gate/health`
- `GET /api/v1/request-gate/capabilities`
- request verdicts appear in security event/session detail or a separate bounded endpoint.

Health must distinguish:
- configured;
- proxy process reachable;
- HTTP listener ready;
- HTTPS listener ready;
- CA loaded;
- Suricata workers ready/total;
- queue depth/drops;
- active connections/requests;
- timeouts;
- fail-open count;
- fail-close count;
- decrypt handshake failures;
- upstream TLS verification failures.

Never infer `healthy=true` from `configured=true`.

## 15. Security logging and privacy

Do not log:
- Authorization/Cookie/Set-Cookie values;
- raw POST bodies;
- CA private key material;
- full query strings when token-like keys are present;
- bearer tokens.

Events retain bounded metadata only: method, host, truncated/redacted path, content type, body length/hash where acceptable in the lab, detector SID/category, verdict/reason, request/session IDs.

## 16. Test gates

### Unit/fuzz

- TLS ClientHello partial/malformed input.
- Domain wildcard/canonicalization exclusions.
- Request bounds/decompression bombs.
- HTTP framing/smuggling edge cases visible to the parser.
- Request isolation for concurrent H2 handlers.
- Suricata socket fragmented response reads.
- PCAP builder golden tests + Suricata fixture when available.
- IPC oversize/version/deadline behavior.
- CA cache bounds/concurrency.

### Race

```bash
go test -race -count=1 ./internal/proxy/... ./internal/engine/... \
  ./internal/inspection/... ./internal/engineipc/... ./internal/session/...
```

### Regression

Run `go test ./...`, `go vet ./...`, and web tests/build. With M4 OFF, M1/M2/M3 behavior/output must remain equivalent.

## 17. Linux acceptance gate

M4 acceptance may only run after the same topology demonstrates a usable M1/M2 baseline and the required M3 OFF/IDS/IPS baseline. A failed baseline must never be recorded as an M4 PASS.

See `m4-acceptance-matrix.md` for the detailed matrix. Core scenarios include:
- clean HTTP/1 request passes;
- HTTP/1 SQLi/XSS blocked before upstream;
- clean HTTPS decrypt passes;
- HTTPS SQLi/XSS blocked before upstream;
- two HTTP/2 requests on one connection: clean passes, malicious blocks, no cross-stream contamination;
- TLS bypass/exclusion;
- honest certificate verification/pinning/mTLS/ECH limitations;
- body/chunked/gzip/oversize handling;
- detector timeout under fail-open/fail-close;
- Suricata request-worker crash/queue full;
- proxy restart/API down/engine restart;
- DNAT + gate original destination correctness;
- rollback/reboot journal recovery;
- performance comparison for OFF vs M3 vs M4.

## 18. Definition of Done

Call the milestone **M4 CODE COMPLETE / VM ACCEPTANCE PENDING** only when:
- T00–T29 local gates are complete;
- the legacy proxy second-engine production path is removed;
- M4 OFF regression passes;
- dedicated IPC, compiler, proxy, TLS, request adapter, and deployment scripts are tested;
- mandatory race/fuzz gates are satisfied according to the implementation status document;
- no acceptance row is changed to PASS without evidence.

Call the milestone **M4 ACCEPTED** only when all mandatory Ubuntu rows PASS with real evidence.
