# M4 — Sequential Coding Tasks

Do not implement all of M4 in one pass. Each task must have behavioral tests before opening the next dependency layer.

## T00 — Baseline and status ledger
**Files:** create `docs/m4/IMPLEMENTATION_STATUS.md`, ADR 0004.  
Record commit hash, dirty files, and tool versions; run full Go/web baseline. Preserve M1/M2/M3 VM status exactly as-is; do not mark it PASS.

## T01 — Linux capability probe for transparent gate
**Create:** `tests/integration/m4/probe-capabilities.sh`.  
Probe nftables redirect inside netns, original-destination recovery, DNAT+redirect ordering, protection against local upstream redirect loops, IPv4 TCP 80/443. Probe CA/TLS1.2/TLS1.3 ALPN for h2/http1.1. Probe Suricata Unix-socket commands `pcap-file`, `pcap-current`, `pcap-file-list`, `pcap-file-number`.  
If original destination recovery is unreliable, mark BLOCKED and update the ADR to TPROXY before T05.

## T02 — M4 domain enums/types/clone
**Modify:** `internal/domain/*`.  
Add the types in CODE_CONTRACTS; support JSON round-trip, safe zero/unknown behavior, and deep clone.

## T03 — Config schema/defaults/validation
**Modify:** `domain/types.go`, config load/clone/manager. **Create:** `internal/config/request_gate.go`.  
Add RequestGateConfig/Profile/TLSExclusion; bounded defaults; validate policy/profile/TLS-mode/limit dependencies.

## T04 — Duplicate/shadow semantics for gate/exclusions
The canonical key must include the effective gate profile, TLS mode, and exclusion behavior. L3 first-match policy remains authoritative for reachability; the gate must never turn a deny into an allow.

## T05 — Compile authoritative M4 selection
**Create:** `internal/connectivity/request_gate.go`.  
`CompileM4` and `SelectRequestGate` must reuse M2/M3 selectors. Output an immutable `RequestGatePlan{PolicyID,ProfileID,TLSMode,FailMode,...}`.

## T06 — Dataplane proxy schema/compiler
**Create:** `internal/dataplane/compiler_m4.go`, `proxy_schema.go`.  
Use a dedicated `inet ngfw_proxy` table; render interception only for matched ALLOW + gate policies. M4 OFF must produce an empty/absent selector according to snapshot contract. Never flush foreign tables.

## T07 — Original-destination adapter
**Create:** `internal/proxy/originaldst_linux.go`, unsupported stub.  
Use the probed `getsockopt`/equivalent mechanism. Bound errors; unit-test through a fake syscall wrapper; Linux integration must verify DNAT targets.

## T08 — Proxy connection server and IDs
Refactor `cmd/ngfw-proxy`: remove config manager + legacy engine. Listener manages random ConnectionID, ConnContext, capacity semaphore, and graceful shutdown.

## T09 — Dedicated gate IPC v1
**Create:** `internal/gateipc/*`.  
Bounded framed JSON, versioning, deadlines, maximum message bytes, client/server, stable error codes. Fuzz the decoder and test fragmented reads/writes.

## T10 — Engine gate service: open connection
Engine resolves source/original destination against M2 runtime/session + running policy/profile and returns INSPECT_HTTP for selected non-TLS HTTP, or BYPASS/METADATA_ONLY/DECRYPT/BLOCK as appropriate. Do not use the legacy `engine.Engine`.

## T11 — Bounded ClientHello peek
Refactor TLS helper for incremental bounded peek while preserving exact buffered bytes for tunnel mode. Test split TLS records, malformed input, missing SNI, ALPN, and TLS1.3 metadata.

## T12 — TLS exclusion matcher
Implement exact/wildcard domain + CIDR + port matching; canonicalization; duplicate/shadow tests. Matching may only affect the decrypt path and must never override an L3 deny.

## T13 — CA hardening and bounded leaf cache
Remove runtime auto-create behavior. Add explicit CA-init command/script, permissions, and fingerprint. Use bounded LRU/TTL cache and singleflight or equivalent for concurrent generation.

## T14 — Connection dispatch: INSPECT_HTTP/BYPASS/METADATA/DECRYPT
INSPECT_HTTP hands plain HTTP to the request gate without TLS termination. BYPASS performs a raw tunnel and forwards the buffered ClientHello exactly. DECRYPT terminates downstream TLS. No silent downgrade. Map handshake errors to stable reason codes.

## T15 — Upstream TLS transport verification
Dial the original destination with the correct SNI hostname, system/configured roots, hostname verification, and ALPN h2/http1.1. Return explicit 502 on verification failure. Production must not use `InsecureSkipVerify=true`.

## T16 — HTTP request model and request isolation
Refactor `inspection.HTTPRequest` into a bounded normalization helper. Use random RequestID, per-connection ordinal, nullable stream ID. Concurrent H2 tests must prove no shared mutable state.

## T17 — Request header/body limits
Enforce header/URL/count/body raw caps; map errors to 413/431/414/400. No upstream dial before the final gate decision. Telemetry stores body hash/length only.

## T18 — Decompression guard
Support gzip/deflate with decoded-byte cap + ratio cap and explicit unsupported-encoding behavior. Fuzz compression bombs and truncated streams.

## T19 — Synthetic PCAP builder
**Create:** `internal/inspection/requestpcap/*`.  
Build deterministic finite TCP conversations from normalized requests with golden tests. Pin `gopacket` if used. Never derive file paths from user-controlled input.

## T20 — Suricata Unix-socket client
**Create:** `internal/inspection/suricata_socket/*`.  
Implement socket handshake/commands with fragmented response handling. Fixed sleeps must not be used as protocol semantics.

## T21 — Bounded request-inspector worker pool
Each worker owns one Suricata Unix-socket process/endpoint and one active job. Bound queue by item count and bytes, enforce deadline, use unique work directories, and clean up. Completion is based on current/list/number plus fully consumed output.

## T22 — EVE request result normalization
Parse bounded job-local EVE into RequestAlert. Preserve signature ID/category/action; ignore unsupported event types; malformed output becomes unavailable, never clean.

## T23 — Engine final request decision
Implement `evaluate_request` using the deterministic M4 decision table only; no M5 risk engine. Base matched policy must be ALLOW. Store decision ID, generation, session link, and coverage.

## T24 — HTTP/1.1 forwarder
Create the upstream request only after ALLOW. Strip hop-by-hop headers, preserve method/path/body semantics, bound upstream errors, and keep keep-alive safe.

## T25 — HTTP/2 downstream/upstream
Enable H2 on decrypted TLS using the standard Go HTTP stack. Set MaxConcurrentStreams and receive-buffer bounds. Test one connection with concurrent clean + malicious requests; only clean requests may hit upstream.

## T26 — Failure policy and overload semantics
Fail OPEN/CLOSE is engine-owned. Sensor timeout, queue full, body limit, unsupported encoding, and proxy capacity must map to stable reason/status codes and counters. No component error may become CLEAN.

## T27 — M4 security events and session context
Add request-gate evidence to engine event store and session detail without raw body data. Request scope remains distinct from M3 PACKET/SESSION enforcement.

## T28 — Activation snapshot/rollback/restart
Add M4 plan/artifact hashes; preflight proxy/ruleset/CA before kernel mutation; preserve monotonic generation across commit/rollback; restart must clear stale decisions and rebuild selectors.

## T29 — API/health/capabilities/deploy/acceptance runner
Add health/capabilities handlers + OpenAPI. Harden proxy systemd so the CA key path is read-only and CAP_NET_ADMIN is absent unless the capability probe proves it unavoidable. Add Suricata request-worker units/config/rules. Add `verify-m4-linux.sh`, acceptance README/evidence template. Run full Go/vet/race/web gates.
