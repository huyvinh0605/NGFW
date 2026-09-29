# ADR 0003: M3 inspection pipeline

- Status: Accepted for implementation; Ubuntu acceptance pending
- Date: 2026-09-27
- Scope: M3 only

## Context

M1 owns Linux routing, nftables and NAT. M2 makes `ngfw-engine` the sole owner of
conntrack-backed sessions, policy generations and decision-cache state. M3 must
add application metadata and Suricata IDS/IPS signals without creating another
session engine, weakening M1 default deny, or treating asynchronous evidence as
a synchronous request gate.

## Decision

`ngfw-engine` owns the inspection coordinator, bounded EVE readers, correlation,
session inspection context, security-event store and application guard state.
The API only queries this state through runtime IPC v3. API/UI failure therefore
does not stop forwarding or the Suricata processes.

IDS traffic is selected to NFLOG group 100. IPS traffic is selected to NFQUEUE
100 with queue bypass and Suricata `nfq.fail-open: yes`. A three-second nftables
lease represents a live IPS capture path; the engine renews it once per second
only after liveness is established. The base M1 connectivity decision remains
authoritative. Hard blocks and revocations run after inspection selection and
still override cached/established allow.

Application policy uses `RESTRICT_L3_ALLOW`. First-match L3/L4 policy still
chooses the connection. An application list can restrict a matched ALLOW after
strong asynchronous App-ID evidence arrives; it cannot open traffic denied at
L3/L4. UNKNOWN times out to `UNKNOWN_ALLOWED` because M3 supports OPEN failure
mode only. An IPS mismatch installs a scoped timeout guard keyed by conntrack
zone, conntrack ID and the complete original IPv4 TCP/UDP tuple. Packet verdict
`REPORTED` and session guard `APPLIED` remain distinct states.

Suricata records are correlated to the existing M2 session using sensor epoch,
flow binding, full observed/flow tuples, NAT aliases, conntrack identity and
bounded recent-session lookup. Ambiguous evidence stays visible and is not
enforced. Sensor restart changes the epoch and invalidates old flow bindings.
Security events are stored before correlation, then updated by revision so late
correlation does not create a second physical alert.

Activation uses a versioned `ActivationSnapshot` containing the exact config,
generation, M2 compiler options, inspection plan and artifact hashes. Candidate
validation and immutable artifact preflight occur before kernel mutation. The
journal retains independent target and previous snapshots; compensation applies
the previous snapshot, and rollback after publication receives a newer monotonic
generation. Engine startup clears/rebuilds runtime inspection state and never
trusts stale application evidence or an expired IPS lease.

The deployment uses separate `ngfw-inspect` Suricata services. Sensor config,
rules and manifest are root-owned and hash-verified. EVE/control runtime paths
are writable only by the sensor account and readable by the engine supplementary
group. `ngfw-api` receives no network capability and cannot invoke Suricata.

## Consequences

M3 can observe HTTP, TLS, DNS and SSH metadata, report IDS alerts, enforce
Suricata packet drops in IPS mode, and restrict an already allowed session after
App-ID. Classification and alert correlation can arrive after early packets.
TLS is not decrypted, HTTP/3 is not inspected, and M3 is not a WAF or pre-server
HTTP request gate. A failed/stalled sensor degrades coverage and fails open; the
health API reports requested, configured, reachable, capture-live and lease
states separately rather than claiming clean traffic.

No flowtable offload or new conntrack mark bits are introduced. Live correctness
and performance claims require the Ubuntu 24.04 capability probe and the M3
acceptance matrix; local Windows unit/build results do not satisfy that gate.
