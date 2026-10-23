# M4 activation implementation

Code completion checkpoint: 2026-10-23. VM traffic acceptance remains pending.

1. `activation_snapshot.go`, `activation_m4.go`: schema-2 proxy selector,
   policy-route specification and public artifact identity; schema-1 reading.
2. `controller.go`, `tproxy_routing.go`, `ruleset_bundle.go`: prepare before
   mutation, ensure route before selector, remove route after selector,
   compensating rollback, durable journal recovery and readiness monitoring.
3. `compiler_m4_tproxy.go`: first-match TPROXY, post-DNAT zone guard, local and
   MGMT exclusions, no-listener drop, additional TLS ports and scoped QUIC block.
   M2/M3 dynamic guard chains run before interception without flushing their sets.
4. `gate_activation.go`, `gate_runtime.go`: nonce-bound proxy preflight,
   actual CA/rules/worker artifact identity and no request authorization before
   publication. The proxy uses the same engine for every final request verdict.
5. `runtime.go`, `runtime_factory.go` under proxy: prepare/start resources,
   promote without unnecessary restart, retire on changed generation or IPC
   failure, and reject changed accepted artifacts on proxy restart.
6. Engine command: start gate IPC before startup reconciliation, bind the
   routing manager and preparation callback, retain M4 in management program
   compilation, and finalize only after readiness checks.
7. Deploy: matching binaries; optional proxy install through
   `install-m4-assets.sh --proxy-binary`; explicit CA provisioning;
   supplementary engine group; proxy enablement before committing M4.

Behavioral checks cover the preparation authorization boundary, stale/replayed
heartbeats, artifact tampering, commit/update/monotonic rollback, injected nft
failure, prepared-journal restart recovery, downgrade cleanup and compatibility
with old snapshots. Native Linux execution of the complete new transaction and
full M4 traffic acceptance still require the Ubuntu VM.
