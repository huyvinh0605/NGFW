# Request-gate IPC v1

T09 provides transport only. The authoritative handler runs in `ngfw-engine`; `ngfw-proxy` is a client. The default socket is `/run/ngfw/request-gate.sock` with mode `0660`. One Unix connection carries one request and one response. Business payloads use the M4 types in `internal/domain/request_gate.go`; no raw HTTP body belongs in this IPC.

Each message is a four-byte unsigned big-endian JSON length followed by exactly that many bytes. The default maximum is 256 KiB and the hard maximum is 1 MiB. A zero or oversized length is rejected before payload allocation. The transport applies one deadline to dialing, reading, writing, and handling (two seconds by default, at most 30 seconds). The server uses a fixed worker count and a bounded pending queue.

Request envelope: `version`, random `correlation_id`, `operation`, `payload`. Version is `1`. Operations are `open_connection`, `evaluate_request`, optional idempotent `report_request_result`, and `gate_health_ping`. Response envelope: `version`, the same `correlation_id`, `ok`, `code` on failure, `config_generation`, `decision_id`, and `data` on success. Every successful response requires a nonempty decision ID. The client rejects a wrong correlation ID, protocol version, missing decision ID, or a generation older than the caller's minimum. The caller must still compare the returned generation to its current connection/request state before applying the decision.

Transport errors use stable codes: `GATE_IPC_MALFORMED`, `GATE_IPC_VERSION_MISMATCH`, `GATE_IPC_FRAME_TOO_LARGE`, `GATE_IPC_DEADLINE_EXCEEDED`, `GATE_ENGINE_UNAVAILABLE`, `GATE_IPC_CORRELATION_MISMATCH`, `GATE_IPC_STALE_GENERATION`, and `GATE_IPC_INTERNAL`. Raw handler errors and request payloads are not returned in error frames. A full server queue currently closes the new connection; the client reports engine unavailability. T26 will attach the configured failure policy and queue-specific health counters. No transport error is a clean inspection result.

T10 and T23 will bind typed engine operations to this transport. T09 does not activate interception or change M1/M2/M3 packet forwarding.
