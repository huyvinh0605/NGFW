# M4 implementation status

Baseline date: 2026-09-28. This ledger tracks implementation separately from Ubuntu appliance acceptance.

## Source and worktree

- Baseline HEAD: `fb41212e92ef0d15f100bba52ac33f63b102b000`
- Specification source: `docs/M4-specification-English/docs/`. The five canonical documents under `docs/` were copied at T00; the T02 Go identifier collision was corrected in both contract copies with unchanged wire values.
- Existing worktree changes before T00 (preserved):

```text
 D GiaiThich/~$AT&DNAT.docx
 M README.md
 M USE.md
 M docs/architecture.md
 M docs/m3-acceptance-matrix.md
 M docs/m3/START_HERE.md
 M docs/openapi.yaml
 M internal/deploy/scripts_test.go
 M internal/domain/inspection_api.go
 M internal/domain/runtime_events.go
 M internal/domain/runtime_ipc.go
 M internal/domain/security_event_m3.go
 M internal/engine/inspection_runtime.go
 M internal/engine/inspection_runtime_test.go
 M internal/engine/runtime_events.go
 M internal/engine/runtime_events_test.go
 M internal/engine/runtime_service.go
 M internal/engine/runtime_service_test.go
 M internal/engine/security_events.go
 M internal/engine/security_events_test.go
 M internal/engineipc/runtime.go
 M internal/inspection/eve/reader.go
 M internal/inspection/sensor/health.go
 M internal/inspection/sensor/monitor.go
 M internal/inspection/source.go
 M internal/management/api.go
 M internal/management/inspection_api.go
 M internal/management/runtime_api_regression_test.go
 M scripts/install-linux.sh
 M scripts/verify-m3-linux.sh
 M tests/integration/m3/README.md
 M tests/integration/m3/probe-capabilities.sh
 M web/src/App.tsx
 M web/src/inspectionComponents.tsx
 M web/src/inspectionData.ts
 M web/src/types.ts
 M web/tests/configuration-workflow.test.tsx
 M web/tests/inspection-data.test.tsx
?? docs/M4-specification-English/
?? docs/M4_DETAILED_IMPLEMENTATION_SPEC.md
?? docs/adr/0003-m3-inspection-pipeline.md
?? docs/m3/IMPLEMENTATION_STATUS.md
?? tests/integration/m3/marker_http.py
```

## Local baseline

| Command | Result |
|---|---|
| `go test -count=1 ./...` | PASS (exit 0) |
| `go vet ./...` | PASS (exit 0) |
| `cd web && npm test` | PASS (38/38; exit 0) |
| `cd web && npm run build` | PASS (exit 0) |

Go `1.27.0 windows/amd64`; Node `22.19.0`; npm `10.9.3`; Windows NT `10.0.26200.0`. Baseline is local only; it does not establish Linux packet-path acceptance.

## T00–T05 dependency map

- T00: baseline and canonical document placement; no dependency.
- T01: Linux capability probe requires T00 and Ubuntu with nftables, conntrack and Suricata. The physical interception choice remains pending until observed.
- T02: domain contracts require T00 and the copied CODE_CONTRACTS; it can proceed while T01 waits for Ubuntu.
- T03: config/defaults/validation require T02; can proceed while T01 waits.
- T04: duplicate/shadow semantics require T03; can proceed while T01 waits.
- T05: authoritative policy selection requires T03–T04 and is independent of REDIRECT versus TPROXY; T01 must resolve the kernel interception mechanism before T06.

## Task ledger

| Task | Status | Evidence / blocker |
|---|---|---|
| T00 | DONE | Baseline recorded; contracts copied without edits. |
| T01 | PARTIAL / VM_PENDING | Probe script authored and syntax-checked locally; Ubuntu netns/nft/Suricata execution pending. |
| T02 | DONE | M4 domain contracts and deep clones; `go test -count=1 ./internal/domain` PASS. |
| T03 | DONE | Config schema/defaults/validation and clone isolation; `go test -count=1 ./internal/config ./internal/domain ./internal/management` PASS. |
| T04 | DONE | Effective gate/exclusion key, exclusion duplicate/shadow checks, first-match deny invariant; `go test -count=1 ./internal/config ./internal/connectivity ./internal/engine ./internal/management` PASS. |
| T05 | DONE / LOCAL_TESTED | Shared first-match M2/M3 matcher derives immutable M4 plans; dependent Go package tests PASS. No Linux interception claim. |
| T06 | PARTIAL / LOCAL_TESTED | Mechanism-neutral first-match proxy selector plan + validation implemented. nft REDIRECT/TPROXY render/apply awaits T01 Ubuntu result. |
| T07 | PARTIAL / LOCAL_TESTED | Resolver boundary and explicit unavailable fallback implemented; Linux getsockopt/TPROXY adapter awaits T01 capability result. |
| T08 | PARTIAL / LOCAL_TESTED | Bounded dual-listener connection lifecycle, random IDs, ConnContext and graceful shutdown implemented; command migration awaits authoritative engine gate path. |
| T09 | DONE / LOCAL_TESTED | Bounded versioned Unix IPC transport, worker queue, deadline/correlation/generation checks, fragmented I/O and fuzz-seed tests; engine operation binding belongs to T10/T23. |
| T10 | DONE / LOCAL_TESTED | User-approved `INSPECT_HTTP` contract; authoritative Runtime gate service and Unix IPC round trip tested locally. Production command activation belongs to T28. |
| T11 | DONE / LOCAL_TESTED | Bounded incremental ClientHello record peek, exact consumed-byte replay buffer, deadline and fragmentation/malformed/TLS1.3 tests. |
| T12 | DONE / LOCAL_TESTED | Existing canonical exclusion matcher/duplicate-shadow validation now wired into engine decrypt selection; first-match deny override tested. |
| T13 | DONE / LOCAL_TESTED | Explicit CA init/fingerprint command, runtime load-only validation, private key permissions, bounded LRU/TTL leaf cache and concurrent dedup tested. |
| T14 | DONE / LOCAL_TESTED | Verdict-based transport dispatcher implements INSPECT_HTTP callback, exact raw tunnel replay, and downstream TLS termination without silent downgrade. |
| T15 | DONE / LOCAL_TESTED | Verified upstream TLS dial uses original IP, expected DNS/IP identity, trusted roots and ALPN; mismatch/connect errors are explicit. |
| T16 | DONE / LOCAL_TESTED | Detached in-memory HTTP normalization plus random RequestID, atomic per-connection ordinal and nullable StreamID; concurrent real HTTP/2 test. |
| T17 | PARTIAL / LOCAL_TESTED | Bounded max+1 body read, truncated flag, exact replay only after matching ALLOW verdict and header/URL/count validation; HTTP server limits/status mapping await T24/T26. |
| T18 | DONE / LOCAL_TESTED | gzip/zlib-deflate decoder with decoded-byte/ratio caps, cancellation and explicit partial/unsupported/malformed errors; request pipeline binding awaits T23/T24. |
| T19 | DONE / LOCAL_TESTED | Deterministic bounded Ethernet/IPv4/TCP request PCAP builder, distinct per-job flowID mapping, valid checksums/sequence, secret-header stripping and golden test; Suricata fixture awaits Ubuntu. |
| T20 | DONE / LOCAL_TESTED | Versioned JSON Unix socket client, required-command handshake, fragmented response parsing, bounded deadline/response, typed PCAP queue methods and stale-reply-safe closure; live Suricata awaits Ubuntu. |
| T21 | DONE / LOCAL_TESTED | Bounded pool, unique 0700 job dirs/0600 PCAP, per-worker Suricata process factory, deadline/cancel/queue byte caps, structured queue drain and bounded EVE read; live process acceptance pending. |
| T22 | DONE / LOCAL_TESTED | Job-local EVE parser correlates synthetic tuple/PCAP/flow ID, requires closed-flow completion, preserves bounded alert metadata, and treats malformed/stale/incomplete output as unavailable. |
| T23 | DONE / LOCAL_TESTED | Engine-owned bounded connection/request records, `evaluate_request` IPC, per-request current L3/L4 policy recheck, deterministic verdict/failure table and generation/block revocation tests. |
| T24 | DONE / LOCAL_TESTED | HTTP/1.1 forwarder holds requests until engine ALLOW; local tests pass. Ubuntu traffic acceptance pending. |
| T25 | DONE / LOCAL_TESTED | HTTP/2 request isolation and bounded streams tested locally; Ubuntu traffic acceptance pending. |
| T26 | DONE / LOCAL_TESTED | Failure/overload statuses, deadlines and counters tested locally. |
| T27 | DONE / LOCAL_TESTED | Engine-owned bounded request evidence and session context tested locally. |
| T28 | PARTIAL / VM_CAPABILITY_PENDING | Engine gate IPC attached; production proxy/selector and activation await T01 Ubuntu capability evidence. |
| T29 | PARTIAL / LOCAL_TESTED | Engine IPC + API health/capabilities/evidence, OpenAPI, hardened units and offline assets/collector added; live readiness, Suricata config validation and acceptance await Ubuntu/T28. |

## Acceptance

M1/M2/M3 acceptance records remain unchanged. M4 VM acceptance: NOT_RUN. The Windows host cannot run the Linux netns/nft/Suricata probe; that is an environment blocker, not a failing code test. Later task checkpoints must record the smallest test command, exit status, contract covered, limitations and next task.

## Contract note

The T02 Go identifier collision was resolved by prefixing the two M4 RequestCoverage constants in both contract copies while preserving their wire values.

## Task checkpoints

TASK: T00
STATUS: DONE
FILES CHANGED: canonical M4 specifications, ADR 0004, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./...` PASS; `go vet ./...` PASS; `npm test` 38/38 PASS; `npm run build` PASS; SHA-256 comparison of five copied specifications PASS.
CONTRACTS SATISFIED: baseline hash, dirty tree, tool versions and independent acceptance status recorded.
KNOWN LIMITATIONS: Windows baseline does not prove Ubuntu packet behavior.
NEXT TASK: T01 capability probe on Ubuntu; T02 may proceed independently.

TASK: T01
STATUS: PARTIAL / VM_PENDING
FILES CHANGED: `tests/integration/m4/probe-capabilities.sh`, `tests/integration/m4/README.md`.
TESTS: Git Bash syntax check PASS; four embedded Python blocks parsed PASS; Ubuntu netns/nft/Suricata probe NOT_RUN.
CONTRACTS SATISFIED: isolated probe covers TCP/80/443, post-DNAT original destination, local upstream recursion, proxy restart, temporary CA/TLS1.2/TLS1.3 ALPN and Suricata PCAP socket commands.
KNOWN LIMITATIONS: mechanism selection remains unverified until execution on the target Ubuntu VM.
NEXT TASK: run `sudo bash tests/integration/m4/probe-capabilities.sh --evidence-dir /tmp/ngfw-m4-probe` on Ubuntu before T05/T06.

TASK: T02
STATUS: DONE
FILES CHANGED: `docs/m4/CODE_CONTRACTS.md`, original M4 CODE_CONTRACTS, `internal/domain/request_gate.go`, `internal/domain/request_gate_test.go`.
TESTS: `go test -count=1 ./internal/domain` PASS.
CONTRACTS SATISFIED: M4 enums/connection/request/inspection/decision/health DTOs, exact JSON wire values, zero-value rejection and clone isolation.
KNOWN LIMITATIONS: these are domain contracts only; no M4 runtime path is wired yet. Two Go constant identifiers are prefixed to coexist with M3.
NEXT TASK: T03.

TASK: T03
STATUS: DONE
FILES CHANGED: `internal/domain/types.go`, `internal/domain/request_gate_config.go`, `internal/config/manager.go`, `internal/config/inspection.go`, `internal/config/request_gate.go`, `internal/config/request_gate_test.go`.
TESTS: `go test -count=1 ./internal/config ./internal/domain` PASS; `go test -count=1 ./internal/management` PASS.
CONTRACTS SATISFIED: M4 config remains inert while disabled; enabled gate limits have defaults and hard bounds; only enabled ALLOW SESSION policy may use a gate profile; explicit fail/oversize/encoding actions; TLS exclusion syntax; deep candidate clone; M3 IPS remains fail-open.
KNOWN LIMITATIONS: CA artifact and Linux capability preflight belong to activation and T01/T28; exclusion duplicate/shadow checks are T04.
NEXT TASK: T04.

TASK: T04
STATUS: DONE
FILES CHANGED: `internal/config/request_gate.go`, `internal/config/policy_canonical.go`, `internal/config/tls_exclusion.go`, `internal/config/tls_exclusion_test.go`.
TESTS: `go test -count=1 ./internal/config` PASS; `go test -count=1 ./internal/connectivity ./internal/engine ./internal/management` PASS.
CONTRACTS SATISFIED: effective M4 policy key includes gate/fail/TLS/exclusions; disabled gate remains inert; exclusion selectors canonicalize domains/CIDRs/ports, reject duplicate IDs and fully shadowed later rules; first-match deny still shadows a later gate ALLOW.
KNOWN LIMITATIONS: exclusion matching is not wired into engine until T05/T10; T01 Linux interception capability remains unverified.
NEXT TASK: T05 pure policy selection; T01 VM probe remains required before T06.

TASK: T05
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/connectivity/request_gate.go`, `internal/connectivity/request_gate_test.go`, `internal/connectivity/program.go`, `internal/connectivity/inspection.go`, `internal/config/request_gate.go`, `internal/config/tls_exclusion.go`.
TESTS: `go test -count=1 ./internal/connectivity` PASS; `go test -count=1 ./internal/domain ./internal/config ./internal/connectivity ./internal/dataplane ./internal/engine ./internal/management` PASS.
CONTRACTS SATISFIED: `CompileM4` and `SelectRequestGate` reuse the first-match M2/M3 program; only matched ALLOW gets a gate; default ALLOW, deny, UDP and unselected ports do not; plans carry generation and resolved profile/exclusion settings; compiled plans share one private immutable exclusion snapshot instead of copying it per flow; diagnostic copies and cloned programs do not alias candidate data; M4 OFF preserves the L3 policy without activating a gate.
KNOWN LIMITATIONS: no nft selector or proxy is wired yet. T01 capability probe must choose REDIRECT or TPROXY before T06; Ubuntu acceptance is NOT_RUN.
NEXT TASK: execute T01 on Ubuntu, then T06 dataplane selector.

CHECKPOINT CP1 (domain + config + pure policy contracts)
STATUS: LOCAL_TESTED
TESTS: final `go test -count=1 ./...` PASS after immutable exclusion snapshot fix; `go vet ./...` PASS before that fix and `go vet ./internal/connectivity ./internal/config` PASS after it.
KNOWN LIMITATIONS: this checkpoint does not establish Linux kernel or Suricata behavior; T01 remains VM_PENDING.

TASK: T06 (mechanism-neutral part)
STATUS: PARTIAL / LOCAL_TESTED
FILES CHANGED: `internal/dataplane/proxy_schema.go`, `internal/dataplane/compiler_m4.go`, `internal/dataplane/compiler_m4_test.go`, `internal/connectivity/request_gate.go`, `internal/config/request_gate.go`, `internal/config/request_gate_test.go`.
TESTS: `go test -count=1 ./internal/config ./internal/connectivity ./internal/dataplane` PASS; `go test -count=1 ./internal/engine ./internal/management` PASS; `go vet ./internal/config ./internal/connectivity ./internal/dataplane` PASS.
CONTRACTS SATISFIED: M4 OFF yields no selector; enabled selector preserves every compiled first-match policy in priority order and annotates only matched ALLOW rules with a gate; unsafe or malformed plans are rejected; UDP-only gate policies are invalid and mixed TCP/UDP policies gate only TCP; candidate/plan clone isolation and JSON snapshot round-trip are tested. An inert, owned `inet ngfw_proxy` schema is defined but never applied before T01.
KNOWN LIMITATIONS: the inert schema has no hook; the nft interception renderer/apply and rollback are intentionally not implemented until T01 proves REDIRECT or forces TPROXY on the Ubuntu VM. T06 is not DONE and no M4 traffic is intercepted.
NEXT TASK: execute T01 on Ubuntu, then finish T06 renderer and activation integration.

TASK: T06 (gate-port parity refinement)
STATUS: PARTIAL / LOCAL_TESTED
FILES CHANGED: `internal/connectivity/request_gate.go`, `internal/connectivity/request_gate_test.go`, `internal/connectivity/inspection.go`, `internal/dataplane/compiler_m4.go`, `internal/dataplane/proxy_schema.go`, `internal/dataplane/compiler_m4_test.go`.
TESTS: `go test -count=1 ./internal/connectivity ./internal/dataplane ./internal/gateipc` PASS; `go test -count=1 ./internal/engine ./internal/management` PASS; `go test -race -count=1 ./internal/connectivity` PASS; `go vet ./internal/connectivity ./internal/dataplane` PASS.
CONTRACTS SATISFIED: wildcard policies gate only TCP/80 and TCP/443; explicit TCP services preserve OR/range semantics; UDP is never gated. Runtime selection and the persisted dataplane plan use the same compiled port ranges, and plan validation rejects broadened or missing ranges.
KNOWN LIMITATIONS: no REDIRECT/TPROXY rule is rendered or applied before the T01 Ubuntu capability result.
NEXT TASK: complete T01/T06 when VM evidence is available; T09 transport can be implemented independently.

TASK: T09
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/gateipc/frame.go`, `internal/gateipc/protocol.go`, `internal/gateipc/client.go`, `internal/gateipc/server.go`, `internal/gateipc/unix.go`, `internal/gateipc/frame_test.go`, `internal/gateipc/ipc_test.go`, `docs/m4/GATE_IPC_V1.md`.
TESTS: `go test -count=1 ./internal/gateipc` PASS; `go test -race -count=1 ./internal/gateipc` PASS; `go vet ./internal/gateipc ./internal/connectivity ./internal/dataplane` PASS. Tests cover a real local Unix-socket round trip, permissions where supported, fragmented I/O, malformed/oversized frames, version/correlation/generation errors, timeout and fuzz seeds.
CONTRACTS SATISFIED: length-prefixed JSON protocol v1, maximum frame bytes, read/write deadlines, correlation and stale-generation rejection, stable transport errors, fixed worker count and bounded pending queue, Unix socket ownership safeguards. No engine handler or proxy client is wired yet; these belong to T10/T23.
KNOWN LIMITATIONS: full queue maps to engine-unavailable until T26 adds failure-policy telemetry. Unix socket permissions and behavior still need Ubuntu VM acceptance. T07/T08 and the nft interception renderer remain blocked by the T01 capability probe.
NEXT TASK: T01 Ubuntu probe, then T06/T07/T08; connect T09 in T10/T23.

TASK: T07 (mechanism-neutral boundary)
STATUS: PARTIAL / LOCAL_TESTED
FILES CHANGED: `internal/proxy/originaldst.go`, `internal/proxy/connection_server_test.go`.
TESTS: `go test -count=1 ./internal/proxy` PASS; `go test -race -count=1 ./internal/proxy` PASS; `go vet ./internal/proxy` PASS.
CONTRACTS SATISFIED: original destination is supplied only by a resolver and is checked before any handler runs; an unavailable/invalid/self-targeted destination closes the connection. No listener address is substituted as an upstream target.
KNOWN LIMITATIONS: no Linux syscall adapter has been selected or written because T01 has not established REDIRECT versus TPROXY or post-DNAT recovery behavior. T07 is not DONE.
NEXT TASK: run T01 on Ubuntu, then implement and integration-test the selected Linux resolver.

TASK: T08 (connection lifecycle layer)
STATUS: PARTIAL / LOCAL_TESTED
FILES CHANGED: `internal/proxy/connection_server.go`, `internal/proxy/connection_server_test.go`.
TESTS: `go test -count=1 ./cmd/ngfw-proxy ./internal/proxy` PASS; `go test -race -count=1 ./internal/proxy` PASS; `go vet ./internal/proxy` PASS; `GOOS=linux GOARCH=amd64 go build ./internal/proxy ./internal/gateipc ./internal/connectivity ./internal/dataplane` PASS (cross-build only).
CONTRACTS SATISFIED: HTTP/HTTPS listeners share a bounded active-connection limit; new connections receive collision-resistant IDs and an immutable `ConnContext`; capacity rejection and resolver failures close only the affected connection; cancellation closes listeners and active connections without holding locks around network I/O. No local policy evaluation or firewall engine was added.
KNOWN LIMITATIONS: `cmd/ngfw-proxy/main.go` still uses the legacy prototype and has not been switched to this server. That migration requires a verified original-destination adapter and an authoritative engine gate handler; the prototype must not be treated as production M4. No VM acceptance has been run.
NEXT TASK: T01/T06/T07, then complete the command migration in T08 and connect the engine through T09/T10.

TASK: T10 contract review before coding
STATUS: RESOLVED / MINOR_RESOLVABLE_GAP
CONFLICT: `docs/m4/CODE_CONTRACTS.md:14-20` defines only BYPASS, METADATA_ONLY, DECRYPT and BLOCK for `TLSGateAction`; `docs/m4/CODE_CONTRACTS.md:56-63` requires this action in every `ProxyConnectionDecision`. `docs/M4_IMPLEMENTATION_PLAN.md:30` requires a plain HTTP/1.1 request gate, while lines 136-138 define BYPASS/METADATA_ONLY as raw tunnels and DECRYPT as TLS termination. `docs/M4_DETAILED_IMPLEMENTATION_SPEC.md:1747-1769` sends every accepted connection to `open_connection` but lists no plain HTTP inspect action. Mapping port 80 to an existing action would either bypass request inspection or claim TLS decryption that did not occur.
RESOLUTION: the user explicitly selected `INSPECT_HTTP` for selected plaintext HTTP. Added a required `is_tls` field to distinguish TLS from non-TLS without port inference; absent/null fails validation. Updated contracts, plan, ADR, detailed spec, domain enum and tests. The four existing TLS actions retain their meaning.

TASK: T10 engine open-connection service
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/engine/gate_service.go`, `internal/engine/gate_service_test.go`, `internal/domain/request_gate.go`, `internal/domain/request_gate_test.go`, M4 contract/plan/ADR/status documents.
TESTS: `go test -count=1 ./internal/domain ./internal/connectivity` PASS; `go test -count=1 ./internal/engine -run TestM4OpenConnection` PASS; `go test -count=1 ./internal/engine ./internal/gateipc` PASS; `go test -race -count=1 ./internal/engine -run TestM4OpenConnection` PASS; `go vet ./internal/engine ./internal/domain ./internal/gateipc` PASS.
CONTRACTS SATISFIED: engine Runtime is the sole session/policy authority; plain selected HTTP receives INSPECT_HTTP, never a TLS or bypass action; first-match deny, source block, NAT post-DNAT upstream, session link, generation and TLS exclusion are checked; malformed/ambiguous input fails closed. A real local Unix IPC round trip exercises `open_connection`.
KNOWN LIMITATIONS: `cmd/ngfw-engine` and `cmd/ngfw-proxy` are not yet switched to the M4 service, because production interception/activation still depends on T01/T06/T07/T28. This is local implementation, not Ubuntu packet-path acceptance. T23 still owns final per-request verdict.
NEXT TASK: T11 bounded ClientHello peek.

TASK: T11 bounded ClientHello peek
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/tls.go`, `internal/proxy/clienthello.go`, `internal/proxy/clienthello_test.go`.
TESTS: `go test -count=1 ./internal/proxy -run TestPeek` PASS; `go test -count=1 ./internal/inspection` PASS; `go test -count=1 ./internal/proxy` PASS; `go test -race -count=1 ./internal/proxy -run TestPeek` PASS; `go vet ./internal/proxy ./internal/inspection` PASS.
CONTRACTS SATISFIED: 64 KiB/5 s hard bounds, exact consumed bytes retained for a future raw tunnel, fragmented TLS records, malformed/truncated input, missing SNI, first ALPN offer, TLS 1.3 supported-version hint and a real Go TLS ClientHello. Errors never mark metadata available.
KNOWN LIMITATIONS: proxy production command does not yet invoke the peek or tunnel; T14 owns dispatch. `TLSContext.ALPN` stores the first offered protocol under the existing M3 field contract; downstream TLS negotiation still uses Go's TLS stack.
NEXT TASK: T12 TLS exclusion matcher.

TASK: T12 TLS exclusion matcher
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/engine/gate_service.go`, `internal/engine/gate_service_test.go`; existing `internal/config/tls_exclusion.go`, `internal/connectivity/request_gate.go` and their tests already provided canonical matching and shadow detection from T04/T05.
TESTS: `go test -count=1 ./internal/config ./internal/connectivity ./internal/engine -run 'TestTLSExclusion|TestM4Exclusion|TestM4GateCannotRescue|TestM4OpenConnectionTLSModesAndExclusion'` PASS.
CONTRACTS SATISFIED: exact/wildcard/CIDR/port matching uses the effective post-DNAT destination and first-match exclusion order; only a selected DECRYPT path may become an explicit `TLS_EXCLUSION` BYPASS; an earlier L3 deny still BLOCKs.
KNOWN LIMITATIONS: no real TLS tunnel has been exercised on Ubuntu; that belongs to T14 and VM acceptance.
NEXT TASK: T13 CA hardening and bounded leaf cache.

TASK: T13 CA hardening and bounded leaf cache
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/mitm.go`, `internal/inspection/mitm_test.go`, `cmd/ngfw-proxy/main.go`, `cmd/ngfw-proxy/main_test.go`, `docs/m4/CA_PROVISIONING.md`.
TESTS: `go test -count=1 ./internal/inspection ./internal/proxy ./internal/engine ./cmd/ngfw-proxy` PASS; `go test -race -count=1 ./internal/inspection -run TestMITMCA` PASS; `go vet ./internal/inspection ./cmd/ngfw-proxy` PASS; `GOOS=linux GOARCH=amd64 go build ./internal/inspection ./internal/proxy ./cmd/ngfw-proxy` PASS (cross-build only).
CONTRACTS SATISFIED: runtime never creates a missing CA; explicit init refuses replacement; cert/key pairing, validity and Linux private-key mode are checked; SHA-256 fingerprint is available through an explicit command; leaf DNS/IP SAN, random serial, seven-day lifetime, bounded LRU/TTL and concurrent same-host dedup are tested. Missing SNI does not receive a placeholder leaf.
KNOWN LIMITATIONS: CA CLI is ready, but the current M1/M3 installer does not deploy the production M4 proxy binary. Ubuntu ownership/permission behavior and browser trust still require VM acceptance; production TLS dispatch and systemd wiring belong to T14/T28/T29.
NEXT TASK: T14 TLS dispatch.

TASK: T14 connection dispatch
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/proxy/gate_connection.go`, `internal/proxy/gate_connection_test.go`, `docs/m4/CODING_TASKS.md`.
TESTS: `go test -count=1 ./internal/proxy -run TestGateConnection -timeout 30s` PASS; `go test -race -count=1 ./internal/proxy -run TestGateConnection -timeout 45s` PASS; `go vet ./internal/proxy` PASS.
CONTRACTS SATISFIED: proxy sends explicit `is_tls` and ClientHello metadata to the engine IPC authorizer, rejects malformed/contradictory decisions, replays buffered bytes before a raw BYPASS/METADATA_ONLY tunnel, terminates downstream TLS for DECRYPT, and routes INSPECT_HTTP without TLS termination. BLOCK/invalid/missing handler paths never dial upstream. TLS handshake failure is an explicit error, not a bypass fallback.
KNOWN LIMITATIONS: the injected HTTP request handler is implemented by T16–T24; until then it cannot forward application requests. T26 must map ClientHello parse/timeout failures through engine-owned profile failure policy. Production command and Linux selector activation still await T01/T06/T07/T28.
NEXT TASK: T15 verified upstream TLS dial.

TASK: T15 verified upstream TLS dial
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/proxy/upstream_tls.go`, `internal/proxy/upstream_tls_test.go`.
TESTS: `go test -count=1 ./internal/proxy -run TestDialVerifiedUpstream -timeout 30s` PASS; `go test -race -count=1 ./internal/proxy -run TestDialVerifiedUpstream -timeout 45s` PASS; `go vet ./internal/proxy` PASS; `GOOS=linux GOARCH=amd64 go build ./internal/proxy` PASS (cross-build only).
CONTRACTS SATISFIED: the authorized original IP/port is dialed directly; certificate chain and expected SNI hostname or IP SAN are verified using configured/system roots; h2/http1.1 ALPN is offered; verification and connect failures have stable errors and close the connection. No insecure verification or plaintext fallback exists.
KNOWN LIMITATIONS: the helper is not called by an HTTP forwarder until T24, and Ubuntu routing/NAT acceptance remains pending.
NEXT TASK: T16 bounded HTTP request model and isolation.

TASK: T16 bounded HTTP request model and isolation
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/http_gate.go`, `internal/inspection/http_gate_test.go`, `internal/proxy/request_model.go`, `internal/proxy/request_model_test.go`.
TESTS: `go test -count=1 ./internal/proxy -run TestNormalizeRequest -timeout 20s` PASS; `go test -count=1 ./internal/inspection -run TestNormalizeGateHTTPRequest` PASS; `go test -race -count=1 ./internal/proxy -run TestNormalizeRequest -timeout 30s` PASS; `go vet ./internal/inspection ./internal/proxy` PASS.
CONTRACTS SATISFIED: per-request random identity, atomic ordinal scoped to one connection, no fabricated HTTP/2 StreamID; detached body/header/query inspection view; only body length/hash and query presence enter engine metadata JSON. A real concurrent HTTP/2 connection test shows distinct request identity and body/header isolation.
KNOWN LIMITATIONS: T17 must still implement bounded streaming body reads and HTTP server parser limits; T18 owns decompression; T23 owns verdict. The legacy M3 HTTPRequest is left untouched because its JSON shape includes raw query/headers.
NEXT TASK: T17 request header/body limits.

TASK: T17 request header/body limits
STATUS: PARTIAL / LOCAL_TESTED
FILES CHANGED: `internal/proxy/request_body.go`, `internal/proxy/request_body_test.go`; `internal/inspection/http_gate.go`, `internal/inspection/http_gate_test.go` also enforce normalized header/URL/count/body bounds.
TESTS: `go test -count=1 ./internal/proxy -run TestReadGateRequestBody -timeout 20s` PASS; `go test -race -count=1 ./internal/proxy -run 'TestReadGateRequestBody|TestNormalizeRequest' -timeout 30s` PASS; `go vet ./internal/proxy ./internal/inspection` PASS.
CONTRACTS SATISFIED: body read is bounded to max+1 bytes, oversize coverage is explicit, and blocked/wrong-request decisions cannot acquire the body replay reader; ALLOW_PARTIAL can replay every original byte without rewriting it. Normalization checks header bytes/count and URL length.
KNOWN LIMITATIONS: an HTTP server with `MaxHeaderBytes` and stable 400/413/414/431 response mapping is not yet wired. T24/T26 must enforce these before forwarding and before claiming T17 done.
NEXT TASK: T18 decompression guard.

TASK: T18 decompression guard
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/decompress_gate.go`, `internal/inspection/decompress_gate_test.go`.
TESTS: `go test -count=1 ./internal/inspection -run 'TestDecodeGateBody|FuzzDecodeGateBodyNoPanic' -timeout 20s` PASS; `go test -race -count=1 ./internal/inspection -run 'TestDecodeGateBody|FuzzDecodeGateBodyNoPanic' -timeout 30s` PASS; `go vet ./internal/proxy ./internal/inspection` PASS.
CONTRACTS SATISFIED: gzip and zlib-wrapped deflate decode under a 4 MiB hard decoded cap and configurable ratio cap; truncated input, unsupported coding, malformed streams and cancellation produce explicit non-clean errors. Detector output is detached from raw forwarded bytes.
KNOWN LIMITATIONS: this decoder is not yet invoked by the future Suricata request pipeline; T21/T24 must bind it. Raw DEFLATE without the zlib wrapper is explicitly unsupported.
NEXT TASK: T19 finite synthetic PCAP builder.

TASK: T19 synthetic PCAP builder
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/requestpcap/builder.go`, `internal/inspection/requestpcap/builder_test.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/inspection/requestpcap -timeout 30s` PASS; `go test -race -count=1 ./internal/inspection/requestpcap -timeout 60s` PASS; `go vet ./internal/inspection/requestpcap` PASS.
CONTRACTS SATISFIED: bounded deterministic finite Ethernet/IPv4/TCP capture, valid checksums and sequence progression, injective per-worker flowID tuple mapping, 1200-byte segmentation, HTTP/2 semantic normalization, secret-header omission and golden hash.
KNOWN LIMITATIONS: Suricata packet ingestion and signature EVE output are VM ACCEPTANCE PENDING; job workdir creation/cleanup belongs to T21. The worker must allocate unique flowIDs and fail/restart before uint32 wrap.
NEXT TASK: T20 Suricata Unix-socket client.

TASK: T20 Suricata Unix-socket client
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/suricata_socket/client.go`, `internal/inspection/suricata_socket/client_test.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/inspection/suricata_socket -timeout 30s` PASS; `go test -race -count=1 ./internal/inspection/suricata_socket -timeout 60s` PASS; `go vet ./internal/inspection/suricata_socket` PASS; local Unix-socket fragmentation tests were not skipped.
CONTRACTS SATISFIED: protocol 0.1 handshake, required command discovery, byte-fragmented JSON responses, bounded operation timeout/64 KiB reply, typed submit/current/list/count, malformed/null queue state as protocol error, error/timeout connection closure.
KNOWN LIMITATIONS: no Suricata process was started locally; command compatibility and queue completion require Ubuntu T01/T21 acceptance. This client does not equate an empty queue with inspection success.
NEXT TASK: T21 bounded synchronous request-inspector pool.

TASK: T21 bounded synchronous request-inspector pool
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/requestworker/pool.go`, `internal/inspection/requestworker/suricata.go`, matching tests, `internal/inspection/requestpcap/builder.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/inspection/requestworker -timeout 30s` PASS; `go test -race -count=1 ./internal/inspection/requestworker -timeout 60s` PASS; `go vet ./internal/inspection/requestworker` PASS; Linux amd64 cross-build PASS.
CONTRACTS SATISFIED: fixed one-session-per-worker pool, bounded queued items/bytes and concurrent builders, deadline covering queue wait, no flowID reuse, 0700 job workdirs/0600 PCAP, structured Suricata queue drain, 1 MiB EVE cap, cancellation and cleanup.
KNOWN LIMITATIONS: local tests use fake command socket/session; the real Suricata process and terminal EVE behavior remain Ubuntu VM ACCEPTANCE PENDING. Missing/empty output is unavailable, never clean.
NEXT TASK: T22 EVE request normalization.

TASK: T22 EVE request normalization
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/inspection/requestworker/eve.go`, `internal/inspection/requestworker/eve_test.go`, `internal/domain/request_gate.go`, `internal/inspection/requestpcap/builder.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/M4_IMPLEMENTATION_PLAN.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/inspection/requestpcap ./internal/inspection/requestworker -timeout 30s` PASS; `go test -race -count=1 ./internal/inspection/requestworker -timeout 60s` PASS; `go vet ./internal/inspection/requestworker ./internal/domain` PASS; Linux amd64 cross-build PASS.
CONTRACTS SATISFIED: bounded JSONL parser, terminal flow proof, exact job PCAP/tuple/flow ID correlation, no stale alerts, explicit unavailable/error codes, alert SID/category/message/action/severity/timestamp preservation, unsupported event filtering.
KNOWN LIMITATIONS: fixture-based local tests cannot establish how a live Suricata build emits terminal `flow` records for the synthetic PCAP; Ubuntu acceptance remains pending. Final authoritative request decision belongs to T23.
NEXT TASK: T23 engine-owned request verdict and IPC operation.

TASK: T23 engine-owned request verdict and IPC operation
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/domain/request_gate.go`, `internal/engine/gate_service.go`, `internal/engine/gate_request.go`, `internal/engine/gate_request_test.go`, `internal/engine/gate_service_test.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/engine -run 'TestM4' -timeout 40s` PASS; `go test -race -count=1 ./internal/engine -run 'TestM4' -timeout 80s` PASS; `go vet ./internal/engine ./internal/domain` PASS. CP5 before T23: `go test -count=1 ./...` PASS, `go vet ./...` PASS.
CONTRACTS SATISFIED: only engine evaluates final request verdict; every request rechecks current connectivity generation, session link and source block; per-connection identity and request decisions are bounded; clean/blocked/unavailable/oversize tables produce explicit request-scope status and coverage; Unix IPC round trip uses request evidence without body bytes.
KNOWN LIMITATIONS: no production HTTP forwarder invokes this IPC yet (T24). The current profile has no configured blocking-SID list, so explicit Suricata blocking action is the blocking signal. Live Suricata/Ubuntu acceptance remains pending.
NEXT TASK: T24 HTTP/1.1 forwarder.

TASK: T24 HTTP/1.1 request forwarder
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/proxy/http1_gate.go`, `internal/proxy/http1_gate_test.go`, `internal/proxy/upstream_tls.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/proxy -run 'TestHTTP1RequestGate|TestDialVerifiedUpstream' -timeout 45s` PASS; `go test -race -count=1 ./internal/proxy -run 'TestHTTP1RequestGate|TestDialVerifiedUpstream' -timeout 60s` PASS; `go vet ./internal/proxy ./internal/engine ./internal/inspection/requestworker` PASS; Linux amd64 cross-build PASS.
CONTRACTS SATISFIED: Go HTTP/1.1 parser holds request through bounded body read, decoding, detector evidence and authoritative engine IPC; BLOCK/invalid reply never dials upstream; clean and engine-approved partial requests replay original bytes after ALLOW; hop headers are stripped; keep-alive re-evaluates each request; HTTPS HTTP/1.1 upstream verifies certificate and hostname with HTTP/1.1 ALPN and no plaintext downgrade. Local tests prove pre-upstream hold, malicious block, raw chunked body replay, oversize block/partial allow, timeout evidence, stale/malformed verdict rejection and TLS verification failure.
KNOWN LIMITATIONS: the production `cmd/ngfw-proxy` still needs T28 wiring to instantiate this gate; HTTP/2 dispatch/upstream belongs to T25. Live Suricata, transparent redirect and Ubuntu TLS interception acceptance remain pending. T17 parser status mapping and T26 overload/failure counters remain partial.
NEXT TASK: T25 HTTP/2 downstream/upstream isolation.

TASK: T25 HTTP/2 downstream/upstream isolation
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/proxy/http1_gate.go`, `internal/proxy/http1_gate_test.go`, `go.mod`, `go.sum`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/proxy -run '^TestHTTP2RequestGate' -timeout 25s` PASS; `go test -race -count=1 ./internal/proxy -run 'TestHTTP2RequestGate|TestHTTP1RequestGate' -timeout 60s` PASS; `go test -count=1 ./internal/proxy ./internal/inspection/requestworker ./internal/engine -timeout 60s` PASS; `go vet ./internal/proxy` PASS.
CONTRACTS SATISFIED: decrypted TLS ALPN h2 uses the pinned Go HTTP/2 server stack with per-connection stream, frame, HPACK and receive-window bounds. Request IDs, body buffers, inspection calls and engine decisions are isolated per stream. Engine BLOCK returns a stream-scoped response without closing other h2 streams. Authorized h2 requests use verified upstream TLS and can negotiate HTTP/2. A two-stream local test proves only the clean body reaches an HTTP/2 upstream; request IDs/ordinals differ and no fake StreamID is exposed.
KNOWN LIMITATIONS: package name `HTTP1RequestGate` predates its h2 support; production command wiring remains T28. Live browser/Suricata/TLS interception acceptance on Ubuntu remains pending. T26 still owns overload counters and failure mapping. The pinned x/net HTTP/2 import required x/text v0.18.0 and x/sync v0.8.0 checksums.
NEXT TASK: T26 failure policy and overload semantics.

TASK: T17 HTTP parser limit completion (T24/T26 dependency)
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/proxy/http1_gate.go`, `internal/proxy/http1_gate_test.go`.
TESTS: `go test -count=1 ./internal/proxy -run '^TestHTTPRequestGateRejectsOversizeHeadersURLAndMalformedFraming$' -timeout 15s` PASS; proxy race and vet checks listed with T26 PASS.
CONTRACTS SATISFIED: Go HTTP server enforces header read bound and the normalized request limit; tests prove 431 for excessive headers, 414 for URL limit, 400 for malformed framing, and no upstream request. Raw body max+1 and replay restrictions were tested earlier.
KNOWN LIMITATIONS: Ubuntu wire acceptance and actual browser behavior remain pending.
NEXT TASK: T26 failure policy and overload semantics.

TASK: T26 failure policy and overload semantics
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/domain/request_gate.go`, `internal/engine/gate_request.go`, `internal/engine/gate_request_test.go`, `internal/engine/gate_service.go`, `internal/engine/gate_service_test.go`, `internal/proxy/gate_connection.go`, `internal/proxy/gate_connection_test.go`, `internal/proxy/http1_gate.go`, `internal/proxy/http1_gate_test.go`, `internal/proxy/gate_stats.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: targeted engine/profile, proxy failure/overload/parser and HTTP/2 stalled-stream tests PASS; `go test -count=1 ./internal/proxy ./internal/engine ./internal/gateipc ./internal/domain -timeout 70s` PASS; `go test -race -count=1 ./internal/proxy -run 'TestHTTPRequestGate|TestHTTP1RequestGate|TestHTTP2RequestGate|TestGateConnectionInvalidClientHello' -timeout 80s` PASS; targeted engine race PASS; `go vet ./internal/proxy ./internal/engine ./internal/domain` PASS; Linux amd64 cross-build PASS.
CONTRACTS SATISFIED: engine now honors explicit unsupported-encoding action under fail mode and always blocks malformed compressed data with 400; ClientHello timeout/invalid and missing SNI route to engine-owned OPEN/BYPASS or CLOSE/BLOCK; local request-capacity overflow returns 503 without harming in-flight traffic; incomplete HTTP/1.1 or HTTP/2 body releases the slot at deadline; stable counters cover verdict and failure categories. HTTP/2 remains usable after one stalled stream; parser rejects 400/414/431 before upstream.
KNOWN LIMITATIONS: T29 still must aggregate/expose health counters and deploy a production proxy. Live Ubuntu transparent interception, real Suricata behavior, and configured CA ownership remain VM ACCEPTANCE PENDING. T26 does not claim that a downstream TLS handshake failure can safely fail-open after a substitute certificate is presented.
NEXT TASK: T27 request security events and session detail.

TASK: T27 request security events and session detail
STATUS: DONE / LOCAL_TESTED
FILES CHANGED: `internal/domain/request_gate.go`, `internal/domain/session_m2.go`, `internal/domain/runtime_events.go`, `internal/engine/gate_service.go`, `internal/engine/gate_request.go`, `internal/engine/gate_request_test.go`, `internal/engine/runtime_service.go`, `docs/m4/CODE_CONTRACTS.md`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./internal/engine -run '^TestM4RequestEvidence' -timeout 40s` PASS; `go test -race -count=1 ./internal/engine -run '^TestM4RequestEvidence' -timeout 60s` PASS; `go test -count=1 ./internal/domain ./internal/session ./internal/engine ./internal/engineipc -timeout 70s` PASS; `go vet ./internal/domain ./internal/session ./internal/engine` PASS; Linux amd64 cross-build PASS.
CONTRACTS SATISFIED: engine-owned request evidence has count/byte/TTL bounds and sequence pagination; path and alert details are truncated with explicit flags; raw body/query/headers are absent. Runtime events carry request decision IDs without request payloads. Session detail attaches the newest 32 request records through one authoritative GateService; local tests cover eviction, pagination, clone isolation, correlated session detail and concurrent reads/evaluations under race detector.
KNOWN LIMITATIONS: production engine command must construct GateService and attach it to RuntimeServiceAdapter in T28; T29 exposes evidence/health through management API. Ubuntu request-gate acceptance remains pending.
NEXT TASK: T28 activation snapshot/rollback/restart and production process wiring.

TASK: T28 engine-side request-gate IPC attachment
STATUS: PARTIAL / LOCAL_TESTED / VM_CAPABILITY_PENDING
FILES CHANGED: `cmd/ngfw-engine/main.go`, `internal/engine/runtime_service.go`, `docs/m4/IMPLEMENTATION_STATUS.md`.
TESTS: `go test -count=1 ./cmd/ngfw-engine ./internal/engine -timeout 45s` PASS; final local checkpoint `go test -count=1 ./... -timeout 120s` PASS and `go vet ./...` PASS; Linux amd64 cross-build of engine/proxy/requestworker packages PASS; a final targeted engine-command test after log hardening PASS.
CONTRACTS SATISFIED: privileged `ngfw-engine` now constructs the sole GateService from the existing authoritative Runtime, binds the dedicated bounded gate IPC server, and attaches the same GateService to management session detail. A gate-socket failure is logged as degraded without stopping M1/M2 forwarding. Engine restart constructs empty request/connection maps, so stale process-local M4 verdicts are not trusted.
ARCHITECTURAL GAP: T01 Ubuntu capability evidence has not established REDIRECT versus TPROXY, including correct original/post-DNAT destination recovery. T06 nft interception render/apply, T07 Linux resolver, M4 plan/hash preflight and rollback activation, and production `cmd/ngfw-proxy` migration cannot be truthfully completed before that decision. The current `cmd/ngfw-proxy` still contains the legacy memory-engine path; it is NOT a production M4 request-gate binary and must not be deployed as one. No Linux interception or acceptance claim is made.
NEXT TASK: on the Ubuntu appliance run `sudo bash tests/integration/m4/probe-capabilities.sh --evidence-dir /tmp/ngfw-m4-probe`; use its observed result to finish T06/T07/T28, then T29 and live acceptance.

TASK: T29 API, deploy assets and read-only acceptance collection
STATUS: PARTIAL / LOCAL_TESTED / VM_ACCEPTANCE_PENDING
FILES CHANGED: `internal/domain/request_gate.go`, `internal/engine/request_gate_runtime.go`, `internal/engineipc/runtime.go`, `internal/management/api.go`, `internal/management/request_gate_api.go`, matching tests, `docs/openapi.yaml`, `deploy/ngfw-proxy.service`, `deploy/ngfw-request-worker-preflight.service`, `deploy/ngfw-proxy.env.example`, `deploy/request-gate/*`, `scripts/install-m4-assets.sh`, `scripts/verify-m4-linux.sh`, `docs/m4/CA_PROVISIONING.md`, `tests/integration/m4/README.md`, `tests/integration/m4/EVIDENCE_TEMPLATE.md`.
CONTRACTS SATISFIED: management reads M4 health/capabilities and bounded evidence only from authoritative engine IPC; request evidence requires authentication. Implemented protocol support is separate from production readiness. With no verified proxy heartbeat, enabled M4 reports `down`, zero ready workers and `production_ready=false`, never a false healthy verdict. The proxy unit has a dedicated account, read-only CA path, no CAP_NET_ADMIN, bounded cgroup limits, and a separate request-worker config preflight. The asset installer does not start the legacy proxy or change nftables. The read-only collector explicitly records `acceptance_status: PENDING`.
KNOWN LIMITATIONS: no generation-bound live proxy heartbeat is wired; dynamic worker/queue counters remain unavailable until T28 production proxy wiring. Suricata config/rules syntax must be validated by `suricata -T` on Ubuntu. T01/T06/T07/T28 remain required before production activation; all M4 traffic acceptance rows remain NOT_RUN.
NEXT TASK: obtain T01 Ubuntu probe evidence, then finish T06/T07/T28 and live T29 health/acceptance.
