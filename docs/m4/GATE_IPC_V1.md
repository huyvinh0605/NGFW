# Request-gate IPC v1

T09 provides transport only. The authoritative handler runs in `ngfw-engine`; `ngfw-proxy` is a client. The default socket is `/run/ngfw/request-gate.sock` with mode `0660` and group `ngfw-proxy`. The engine's systemd drop-in grants the proxy search-only ACL access to `/run/ngfw` at every start; it cannot access the separate `root:ngfw` management `engine.sock`. One Unix connection carries one request and one response. Business payloads use the M4 types in `internal/domain/request_gate.go`; no raw HTTP body belongs in this IPC.

Each message is a four-byte unsigned big-endian JSON length followed by exactly that many bytes. The default maximum is 256 KiB and the hard maximum is 1 MiB. A zero or oversized length is rejected before payload allocation. The transport applies one deadline to dialing, reading, writing, and handling (two seconds by default, at most 30 seconds). The server uses a fixed worker count and a bounded pending queue.

Request envelope: `version`, random `correlation_id`, `operation`, `payload`. Version is `1`. Operations are `open_connection`, `evaluate_request`, optional idempotent `report_request_result`, and `gate_health_ping`. Response envelope: `version`, the same `correlation_id`, `ok`, `code` on failure, `config_generation`, `decision_id`, and `data` on success. Every successful response requires a nonempty decision ID. The client rejects a wrong correlation ID, protocol version, missing decision ID, or a generation older than the caller's minimum. The caller must still compare the returned generation to its current connection/request state before applying the decision.

Transport errors use stable codes: `GATE_IPC_MALFORMED`, `GATE_IPC_VERSION_MISMATCH`, `GATE_IPC_FRAME_TOO_LARGE`, `GATE_IPC_DEADLINE_EXCEEDED`, `GATE_ENGINE_UNAVAILABLE`, `GATE_IPC_CORRELATION_MISMATCH`, `GATE_IPC_STALE_GENERATION`, and `GATE_IPC_INTERNAL`. Raw handler errors and request payloads are not returned in error frames. A full server queue currently closes the new connection; the client reports engine unavailability. T26 will attach the configured failure policy and queue-specific health counters. No transport error is a clean inspection result.

T10/T23 bind typed engine operations to this transport. T28 uses
`gate_health_ping` for a two-phase resource handshake. The engine may return a
random `preparation_id` with limits and CA requirements, while
`interception_ready=false`. This permits listener/worker startup only; every
connection/request authorization remains blocked during preparation.

The proxy echoes that ID in its heartbeat together with ruleset ID/hash,
worker-config hash and public CA certificate fingerprint. No private-key hash
is exchanged. A heartbeat from another preparation cannot satisfy preflight.
After kernel verification and publication of Running/Runtime, the engine
clears the preparation ID and supplies the accepted `expected_artifacts`.
The proxy keeps matching prepared resources; changed identity/generation or
an aborted preparation retires the old runtime first. A process restart must
load artifacts matching the accepted identity. Stale IPC cannot authorize
traffic after a commit or rollback.

## Post-forward result reporting

`report_request_result` is implemented by the engine and used by the production
proxy after an allowed upstream attempt. Its bounded payload is
`ProxyRequestResult`: engine instance/generation, RequestID, ConnectionID,
DecisionID, HTTP status, a whitelisted reason code and the observed boolean
`client_certificate_requested`. It contains no raw TLS error, headers, body,
query, client certificate or private key.

The engine accepts a report only for its existing ALLOW with matching request,
connection, decision and current generation. It rejects stale/foreign reports,
unknown reason/status combinations, mTLS facts on plaintext, contradictory
replays, and a claimed mTLS rejection without an observed certificate request.
Exact repeats are idempotent. The response is a `RequestResultReceipt` bound to
the same request/decision/generation; the proxy validates the envelope and body.

The engine attaches a timestamped `forward` object to its bounded request
evidence, advances the evidence cursor, and emits `RequestGateResult`. It keeps
the original content decision and coverage unchanged. Reports do not extend
record TTLs, bypass the byte budget, or mutate M2 sessions. An inspection ALLOW
is therefore distinguishable from a later upstream 502.

Reporting runs synchronously with a separate one-second deadline, including
when the downstream has canceled. It starts no unbounded queue/goroutine and
cannot change the HTTP outcome or retry the request. A reporting failure
increments `result_report_fail`. Engine, proxy and API must be deployed from
the matching build so API decoding retains the new evidence field.
