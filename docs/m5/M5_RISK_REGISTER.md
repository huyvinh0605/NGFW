# M5 risk register

This register distinguishes design decisions from prerequisites that must be
measured during implementation. No risk here is reported as tested or resolved
by the existing M1 VM logs. Owners below are coding task IDs; the implementing
agent records mitigation evidence and reviewer disposition in the execution map.

| ID | Risk | Severity | Impact | Detection | Required mitigation | Owner | Acceptance | Disposition / release gate |
|---|---|---|---|---|---|---|---|---|---|
| R01 | Legacy/dirty M4 baseline accidentally rewritten or misreported | HIGH | All milestones; existing local work | T00 source hashes and selected baseline tests; git diff scoped to task files | No broad refactor/reset; preserve exact working-tree M4 changes; unit/VM regression gate before accepting M5 | T00/T29 | A28/A32 | Block core for any new regression; pre-existing failure must have separate evidence |
| R02 | M1 route replace or link deletion collides with FRR/VIP | CRITICAL | Static/dynamic route or VIP loss, management outage | Typed exact route/provenance diff; phase trace; referenced-interface validator | Union old+target exact-prefix FRR reservation before M1 mutation, proto196+manifest+exact key, reject foreign collision; block externally referenced link recreation | T05/T06/T09 | A04/A05/A23 | Block routing if reservation/withdrawal cannot be proven on pinned FRR |
| R03 | External process privileges exceed assumptions | HIGH | Host compromise boundary; FRR startup failure under false minimum caps | Installed unit plus /proc actual capsets, UID/file/socket probes | API none, engine NET_ADMIN; isolated external profiles; stock FRR SYS_ADMIN request explicitly recorded; never add blanket caps to fix failure | T01/T25 | A00/A27 | Blocked if chosen deployment policy disallows required measured profile; no silent expansion |
| R04 | Vendor version/JSON/native reload semantics differ | HIGH | False status/partial apply/unsupported config | Pinned versions, required-key fixtures, native syntax and config-diff tests | Capability gate; bounded adapter parse; unknown required schema unavailable; FRR --test is diff not atomic validator | T01/T09/T12/T21 | A20/A22/A26/A27 | No enabled feature on unverified family/revision |
| R05 | Optional subtree lost or ignored across clone/UI/old engine | HIGH | Partial config applied silently; legacy round-trip changed | Old/new fixture round-trip, clone isolation, mixed-version IPC | Strict M5 decode, optional pointer/deep clone, lossless whole Candidate, capability negotiation and paired release | T02/T22/T23 | A01/A25/A32 | Old engine must reject before M5 commit; downgrade only after clearing both Running/previous |
| R06 | Route leak or learned prefix implicitly authorizes security zone | CRITICAL | Protected MGMT/local route exposure or incorrect policy | Peer advertised/received JSON, explicit zone compile assertions, negative packet cases | Default-deny routing maps; generated protected constraints cannot be overridden; configured ReachablePrefixes only; no live RIB grants a zone | T03/T09/T14/T17 | A07/A17/A29 | Block core if any protected prefix leak or admission bypass |
| R07 | WAN path/NAT/conntrack/M3 assumptions diverge | HIGH | Asymmetric state, NAT source change, incorrect session correlation | Original/reply/NAT tuple plus session ID/mark/epoch and multi-interface pcap | Routed FRR/ECMP only; no overlapping NAT/weighted/PBR; no M5 marks; same-zone paths; preserve M2 identity/M3 alias checks | T15/T16/T29 | A10–A13/A28 | No seamless established-session or sticky-ISP claim; future NAT design separate |
| R08 | Secrets escape through generated configs/errors/backups | CRITICAL | BGP auth/TLS private key disclosure | Synthetic sentinel leak scan, mode/UID probes and bounded error tests | Opaque versioned refs, local provisioning, private roots, secret output suppression, redacted evidence; private material never API response | T04/T18/T25 | A16/A27 | Any leak blocks release; rotate affected test/deployment secrets outside shared evidence |
| R09 | HAProxy bypasses M4 or local admission assumed from FORWARD | CRITICAL | Uninspected delivery incorrectly represented as security-enforced | Both-direction validation, source/egress negative probes, request/backend pcap | M4+LB rejected node-wide; DELIVERY_ONLY explicit; scoped INPUT/OUTPUT; no shared TLS/request pipeline invented | T03/T17/T18/T29 | A17/A28 | Unsupported combined processing is rejected, not warned-and-allowed |
| R10 | Multi-daemon partial apply or wrong-generation rollback | CRITICAL | Running/kernel/daemon disagreement; stale security metadata | Exact inner snapshot, outer WAL phases, failure-at-every-step tests | Write-ahead receipts, reverse compensation, old/target Running recovery, M2 options cloned exactly, failed recovery retains fences/journal | T07/T08/T28 | A23/A24 | RECOVERY_REQUIRED is valid failure state, never report PASS as healthy |
| R11 | Disk/fsync/journal corruption and abandoned artifact state | HIGH | Recovery data lost or wrong artifact trusted | Atomic file fault injection; digest/reference verification; quota metrics | fsync+rename+parent fsync, active vs accepted refs, retain WAL dependencies, bound retention, no timestamp-only selection | T04/T07 | A23/A24/A26 | Do not delete corrupt journal automatically; isolate affected feature and preserve diagnosis |
| R12 | IPC/HTTP timeout or lost reply creates duplicate activation | HIGH | Caller sees failure while commit published; repeated generation | Operation IDs/version/checksum, timeline, current Running/status retrieval | Negotiated config-only190/200/205s deadlines; separate60s compensation; same operation ID while live; after restart inspect Running because receipts are in-memory | T07/T22 | A24/A25 | No blind retry with new operation; no false claim of cross-reboot receipt durability |
| R13 | BFD/probe/ECMP performance claims exceed VM evidence | MEDIUM | Flapping, misleading 'fast failover' or distribution charts | Negotiated timers, idle-load timestamps, per-flow counts, CPU/scheduling observations | Conservative300ms BFD default, bounded probes, debounce, label measurement-specific bounds; no exact50/50 or guaranteed old TCP survival | T13/T16/T26 | A09–A12 | Use measured lab bounds; fail/record overload instead of weakening hidden thresholds |
| R14 | VRRP split brain, stale readiness or VIP dual ownership | HIGH | Duplicate VIP, packet blackhole or wrong MASTER display | Both-node FIFO+fresh JSON+kernel VIP snapshots; peer-partition and engine-crash tests | Keepalived only writer, unicast allowlists/TTL, disjoint M1 IPs, readiness expiry, no automatic role forcing; explicit lack of quorum/fencing/state sync | T20/T21/T27 | A18/A19/A22 | Partition resilience is a documented limitation; HA demo sign-off does not imply production fencing |
| R15 | VRRP mistaken for stateful firewall/proxy HA | HIGH | Existing connections fail while report claims continuity | Long-lived stream sequence, conntrack/M2 state on both nodes, NAT tuple evidence | Core VIP/new-flow failover only; separate per-node config; conntrackd future; no M2/M3/M4/HAProxy state replication claim | T27/T29 | A18/A19/A31 | Stateful HA cannot be accepted by VIP movement alone |
| R16 | Unbounded status/tool output or polling DoS | MEDIUM | Engine CPU/memory exhaustion and stale status shown healthy | Page/cursor/output-limit/cancel tests; process and worker counts | Cached immutable status, page<=200 total<=4096, bounded tools/pools, explicit stale/unknown; no generic vty/admin endpoint | T04/T12/T22/T24 | A25/A27 | Required field/output truncation is failure; never partial healthy success |
| R17 | Optional IPVS ownership/return path/library scope grows | HIGH | Double writers, bypass return path, session ambiguity | Netlink ownership and packet path; module/API capability fixtures | Optional NAT only, checker-only single writer, structured observer, no direct Go IPVS writer/DR/TUN/fwmark; no core schedule dependency | T31–T33 | A30 | Leave capability absent if optional profile/binding/legacy regressions not proved |
## Open execution prerequisites (architecture decisions are settled)

- **O01 / T00:** actual current test baseline and uncommitted M4 hashes. Source
  audit is complete enough to plan; no prior test pass is invented for M4.
- **O02 / T01:** installed OS/kernel/package revisions, FRR syntax/JSON/filtering,
  proto196 collision-free reservation, actual daemon caps and scoped socket probe
  support. If the profile fails, that capability remains unavailable.
- **O03 / T01/T21:** Keepalived protected JSON dump/mount behavior and FIFO loss
  recovery on the pinned Ubuntu package. Snapshot behavior is a concrete gate,
  not a reason to scrape human console output.
- **O04 / T26/T27:** R2/shared destination/G2 VMs and exact new NIC mappings. Core
  failover/HA VM cases stay BLOCKED until topology exists.
- **O05 / optional T32:** select/pin an IPVS generic-netlink binding with required
  attributes and maintained source. No new dependency is guessed in core.

## Explicit residual limitations after a successful core acceptance

IPv4-only dynamic routing; no VRF/PBR/weighted sticky multi-ISP NAT. HAProxy
provides separately admitted DELIVERY_ONLY services and cannot run alongside
effective M4. VRRP has no fencing/quorum/config sync/kernel connection sync or
M2/M3/M4/proxy state replication. FRR, HAProxy and Keepalived apply operations are
compensated and can interrupt traffic; they are not a cross-daemon atomic commit.
Root engine service orchestration and native daemon privilege remain trusted
boundaries. Test success in the KLTN isolated VM topology is not a production HA
or convergence SLA.

## Planning checkpoint

FINDINGS: route provenance, local service admission, transaction recovery and
legacy compatibility are the blocking correctness risks, not UI completeness.
DECISIONS: explicit fail-closed capability gates; optional features cannot weaken
core boundaries; residual HA/session limitations remain visible after sign-off.
UNRESOLVED: O01–O05 are measured execution prerequisites above; core design choices
are captured in ARCHITECTURE and are not reopened without contrary evidence.
FILES ALREADY INSPECTED: CURRENT_ARCHITECTURE_MAP and named source symbols.
SOURCES ALREADY INSPECTED: SOURCE_NOTES upstream/package ledger.
NEXT TARGETS: use EXECUTION_MAP for later coding; do not repeat repository audit.
