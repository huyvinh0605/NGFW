# ADR 0004: M4 HTTP/TLS Synchronous Request Gate

- Status: Proposed for implementation; Linux capability probe required
- Date: 2026-09-28
- Scope: M4

## Context

M3 is asynchronous for App-ID/IDS metadata and inline only at packet scope through Suricata NFQUEUE. It cannot guarantee that an HTTP request is held until inspection completes. The existing `ngfw-proxy` is a lab prototype that creates its own config manager/legacy engine and memory enforcer, which would create a second policy authority if promoted unchanged.

## Decision

`ngfw-engine` remains the only policy/session authority. `ngfw-proxy` becomes a bounded dataplane helper connected to the engine through a dedicated request-gate Unix IPC. The proxy cannot locally load or evaluate running policy.

Selected HTTP/HTTPS TCP flows are transparently intercepted by an engine-compiled nftables M4 selector derived from the same first-match connectivity-policy semantics. Interception is allowed only for matched L3/L4 ALLOW rules. M4 cannot open a flow denied by M1/M2.

For selected plain HTTP, the engine returns `INSPECT_HTTP`: the proxy parses and synchronously gates each request without TLS termination. For HTTPS, the proxy peeks ClientHello and asks the engine for BYPASS, METADATA_ONLY, DECRYPT, or BLOCK. DECRYPT uses a pre-provisioned lab CA; runtime never auto-creates a CA. Upstream TLS is verified normally. Pinning, ECH, and upstream mTLS limitations are explicit and never trigger silent bypass.

Each gated HTTP request is fully bounded and held before upstream forwarding. HTTP/2 correctness is defined by per-request isolation on one connection; exact wire stream ID is optional because the supported Go HTTP server API does not expose it as an application contract.

Synchronous signature inspection uses a dedicated bounded pool of persistent Suricata Unix-socket PCAP workers. HTTP/2 is normalized into finite HTTP semantics for signatures; M4 does not claim frame-level HTTP/2 attack detection. ML and risk correlation remain M5.

Request failures are not security-clean results. Fail-open may allow with `PARTIAL/UNAVAILABLE` coverage and evidence; fail-close blocks with an availability reason distinct from malicious detection.

## Consequences

M4 can prove that representative SQLi/XSS requests never reach upstream while clean HTTP/1.1 and HTTP/2 requests do. It adds latency and memory cost because request bodies are held and Suricata PCAP inspection is synchronous; performance must be measured rather than claimed.

M4 adds another Suricata workload for request inspection but does not change M3 NFLOG/NFQUEUE fail-open semantics. A future implementation may replace the PCAP adapter with a lower-latency detector as long as the `RequestInspector` contract and acceptance behavior remain unchanged.
