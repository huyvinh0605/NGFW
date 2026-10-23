# M5 execution map — start here

**Status: specification complete; implementation NOT_STARTED; all M5 VM cases
NOT_RUN.** Updated2026-10-09. This phase created documentation only.

Baseline source: HEAD `6a1905789f3f071c92549fc3bf628c3b7f7edfc6` plus existing
uncommitted M4 work recorded in [CURRENT_ARCHITECTURE_MAP](CURRENT_ARCHITECTURE_MAP.md).
Do not reset/revert those changes. The user assigns M5 to advanced networking;
older ML/risk references to “M5” are a naming conflict, not authority to rename
legacy code. Start T00 only after a separate instruction to implement.

## Read once, then use the relevant contract

| Document | Use |
|---|---|
| [M5_CURRENT_STATE_AUDIT](M5_CURRENT_STATE_AUDIT.md) | Existing capability/symbol evidence |
| [M5_FEATURE_INVENTORY](M5_FEATURE_INVENTORY.md) | Required / optional / future / rejected scope |
| [M5_ARCHITECTURE](M5_ARCHITECTURE.md) | Ownership, transaction/recovery order, 20 decisions |
| [M5_CODE_CONTRACTS](M5_CODE_CONTRACTS.md) | Exact config fields/defaults/validation, interfaces, errors, API |
| [M5_FILE_IMPLEMENTATION_PLAN](M5_FILE_IMPLEMENTATION_PLAN.md) | File classifications and F/B function cards |
| [M5_CODING_TASKS](M5_CODING_TASKS.md) | Small dependency-aware tasks T00–T33 |
| [M5_ACCEPTANCE_MATRIX](M5_ACCEPTANCE_MATRIX.md) | A00–A32 topology/actions/evidence/cleanup/pass-fail |
| [M5_DEPENDENCY_AND_PACKAGING](M5_DEPENDENCY_AND_PACKAGING.md) | Version families, capability proof, units/permissions/upgrade |
| [M5_RISK_REGISTER](M5_RISK_REGISTER.md) | R01–R17; O01–O05 measured prerequisites |
| [M5_COMPATIBILITY_MATRIX](M5_COMPATIBILITY_MATRIX.md) | M1–M4 impact, minimal legacy edits, regression gate |

Cache sources in CURRENT_ARCHITECTURE_MAP and [SOURCE_NOTES](SOURCE_NOTES.md).
Search exact symbol before a <=100-line read; do not re-audit unchanged directories
or re-open researched pages merely to remember their contents. Update this map
with actual task/evidence state as implementation proceeds.

## Phase order, touched modules and checkpoint gates

| Phase | Tasks / dependency order | Main files touched (full list in task cards) | Checkpoint |
|---|---|---|---|
| Baseline/package proof | T00 -> T01; T02 after T00 | execution map, verifier/profile; domain model+clone/interfaces | Old JSON and dirty baseline preserved; package proof is data, not feature enablement |
| Validation/execution/ownership | T03 after T02; T04 after T01/T02 -> T05 -> T06 | config validator; netserviceexec; state artifacts; resources/ownership; dataplane linux hook/accessor | Scoped unit tests + existing config/dataplane regression; A01/A04 readiness |
| Transaction foundation | T07 | outer WAL/state, engine network_services coordinator | Crash/compensation/cancel + exact M2/M3 activation metadata tests |
| Routing | T09 -> T10/T11 -> T12 -> T13; T14 after T03 | routingpolicy, routing/frr, connectivity prefix helper | Native syntax/JSON fixtures; static reservation + zone compatibility |
| WAN | T15 after T07/T11/T14 -> T16 | wan leases/observer/health | No route/mark writer, scoped leases, bounded fresh-socket probe |
| Local admission | T17 after T03/T04/T07 | networkservices/nftguard | New scoped table only; positive/negative protocol+LB admission |
| Load balancing | T18 -> T19 after T17 | loadbalancer/haproxy | Native TLS/config validation, JSON/new-worker reload proof, M4 conflicts |
| HA | T20 -> T21 after T17 | ha/keepalived/readiness, cmd/ngfw-ha-health | VIP exclusive writer, stale-readiness/JSON/FIFO recovery |
| Management | T22 after T02/T07 -> T23 -> T24 (adapter status deps) | optional IPC/API, web/networkServices and existing editor wiring | Authentication, old-engine reject, timeout, lossless Candidate UI, bounded status |
| Package + assemble | T25 after T19/T21/T01/T04; **T08 after all its listed deps including T22/T25** | units/installer; cmd/ngfw-engine composition | A00/A27 preflight; old no-op path unchanged; keep M3/M4 hook order |
| Live acceptance | T26 -> T27 -> T28 -> T29 -> T30 | tests/integration/m5, fresh artifacts, status in this map | Core A00–A29/A32, A31 negative boundary, directly touched tests + M1–M4 selected regressions |
| Optional IPVS | T31 -> T32 -> T33 after core | optional domain/validator, loadbalancer/ipvs, checker-only unit | Separate A30 + legacy NAT/correlation; never required for core |

T01 implements package/verifier discovery only; Go capability Probe F63 is T04,
once its typed contracts and execution adapter exist. T08 numbering is stable
but its execution is late assembly; do not construct nonexistent adapters early.

## Authority and adapter ownership

| Owner | Owns | Must not own |
|---|---|---|
| ngfw-engine / existing Manager | Candidate/Running authority, commit/rollback, policy/session/security state, adapter orchestration | Reimplemented OSPF/BGP/VRRP algorithms |
| M1 network/dataplane | Physical/VLAN/ordinary IP/static routes/firewall/NAT | Learned FRR routes or Keepalived VIP |
| routing core -> FRR adapter | Protocol config, route policy intent -> native config/reload/JSON; FRR installs dynamic FIB | M1 staticd replacement or firewall policy |
| wan observer | FIB/BFD/probe status; scoped ECMP sysctl lease | New route table/ip rule/ct-mark/session authority |
| LB core -> HAProxy adapter | Delivery sockets/backend health/TLS; engine guards admission/egress | M4 verdicts or firewall ALLOW decisions |
| HA core -> Keepalived adapter | Desired groups/readiness -> VRRP role/VIP runtime | Ordinary M1 IPs/config publisher |
| API / web | Authenticated Candidate/status management through IPC | Tool execution, secrets or NET_ADMIN |
| Optional IPVS | Checker-only Keepalived owns virtual entries, observer reads netlink | Simultaneous direct Go IPVS writer |
| Future conntrackd/VRF/PBR | No active config/runtime in core | Implicit M2 authority or unproven seamless HA |

## Invariants to check in every review

1. Absent/steady disabled M5 produces no M5 mutation/daemon/table/lease. One bounded
   read-only startup WAL/ownership check discovers an interrupted first enable.
   Transition from
   enabled to disabled cleans only owned resources once. Old configs still load.
2. M1 static reservation/provenance is exact; union(old,target) guarded in FRR
   before M1 mutation; no route flush/dynamic snapshot replay. Link dependencies
   include VIP/FRR references, not just ordinary interface fields.
3. Main FIB shared through explicit writer coordination. WAN uses FRR ECMP/failover;
   no weighted/sticky-NAT/PBR/VRF or new conntrack marks in core.
4. Dynamic prefix zones come from validated config, never arbitrary learned RIB.
   M2 identity/epoch and M3 correlation semantics remain unchanged.
5. HAProxy is DELIVERY_ONLY, explicit ordinary address and scoped INPUT/OUTPUT.
   Effective M4+HAProxy rejected in both directions; no combined pipeline invented.
6. Keepalived alone owns VIPs; engine readiness expires on crash; API restart is
   irrelevant to HA readiness. VRRP is new-flow/VIP failover, not session replication.
7. Prepare has no live mutation. WAL precedes runtime change. Preserve exact old
   inner snapshot; existing Manager publishes Running. Compensation/recovery is
   explicit; failed compensation retains journal and fences.
8. No mutex held across Prepare/Apply/Finalize callbacks. Existing commit and
   rollback acquire inspection gate in different places; per-method M5 locking
   plus in-flight flag prevents deadlock/reconcile races.
9. API stays unprivileged; engine cap bound remains NET_ADMIN. External FRR has a
   separately audited broader profile. Secret refs only in Config/log/status.
10. Status is cached/structured/bounded; schema/timeout failures show UNKNOWN/
    DEGRADED. Config-applied is distinct from routing adjacency/backend health.
11. Config mutation deadlines negotiate190s IPC/200s HTTP/205s frontend only for
    the optional M5 interface. Lost response requires Running/status inspection.
12. An M5 feature is unfinished if it breaks accepted M1–M4 behavior.

## Task status ledger

All entries begin NOT_STARTED. A coding agent updates status, validation and
evidence per task; do not infer VM PASS from a merged renderer.

| Task | Title | State |
|---|---|---|
| T00 | Freeze the existing working-tree baseline | NOT_STARTED |
| T01 | Verify package and sandbox capabilities | NOT_STARTED |
| T02 | Add optional shared model, clone and interfaces | NOT_STARTED |
| T03 | Implement pure M5 validation and conflict checks | NOT_STARTED |
| T04 | Build bounded execution, artifact and secret adapters | NOT_STARTED |
| T05 | Add kernel resource observation and provenance DTOs | NOT_STARTED |
| T06 | Protect M1 mutations and expose exact rollback snapshot | NOT_STARTED |
| T07 | Compose the outer M5 activation journal | NOT_STARTED |
| T08 | Wire engine construction and startup recovery | NOT_STARTED |
| T09 | Implement routing policy, FRR foundation and reservations | NOT_STARTED |
| T10 | Render OSPFv2 and filtered redistribution | NOT_STARTED |
| T11 | Render BGP and AF routing policy | NOT_STARTED |
| T12 | Normalize FRR operational status | NOT_STARTED |
| T13 | Add FRR BFD profiles and peer binding | NOT_STARTED |
| T14 | Extend zone attribution for routed prefixes | NOT_STARTED |
| T15 | Add scoped ECMP sysctl leases | NOT_STARTED |
| T16 | Observe routed WAN failover and bounded health probes | NOT_STARTED |
| T17 | Add scoped engine admission for local services/protocols | NOT_STARTED |
| T18 | Render HAProxy delivery, algorithms and TLS | NOT_STARTED |
| T19 | Apply and observe HAProxy lifecycle | NOT_STARTED |
| T20 | Render VRRP and fixed unprivileged readiness helper | NOT_STARTED |
| T21 | Apply and observe Keepalived role/VIPs | NOT_STARTED |
| T22 | Expose optional IPC and read-only API status | NOT_STARTED |
| T23 | Add lossless typed Candidate editor | NOT_STARTED |
| T24 | Add typed live status views | NOT_STARTED |
| T25 | Package isolated units and manifests | NOT_STARTED |
| T26 | Implement and run routing/WAN VM acceptance | NOT_STARTED |
| T27 | Implement and run LB/VRRP acceptance | NOT_STARTED |
| T28 | Run transaction and daemon failure injection | NOT_STARTED |
| T29 | Run M1–M4 compatibility and downgrade gate | NOT_STARTED |
| T30 | Publish core readiness and evidence index | NOT_STARTED |
| T31 | OPTIONAL: add IPVS NAT model/validation | NOT_STARTED |
| T32 | OPTIONAL: checker-only IPVS adapter | NOT_STARTED |
| T33 | OPTIONAL: IPVS VM and legacy regression | NOT_STARTED |

## Unresolved execution gates

O01 T00 actual legacy baseline; O02 T01 installed tool/hash/schema/route-filter/
capability proof; O03 protected Keepalived JSON/FIFO proof; O04 extra VM/NIC
availability; O05 optional IPVS netlink binding. Details and blocking behavior are
in RISK_REGISTER. No unresolved question here authorizes architectural redesign
or widening engine/API privileges without evidence.

## Planning checkpoint

FINDINGS: eleven required deliverables and two cache documents are present.
DECISIONS: core IPv4 FRR/route policy/BFD/ECMP/routed failover + HAProxy + VRRP;
IPVS optional, VRF/PBR/conntrackd deferred with explicit boundaries.
UNRESOLVED: measured execution gates above; implementation and VM tests have not run.
FILES ALREADY INSPECTED: CURRENT_ARCHITECTURE_MAP; use the function manifest.
SOURCES ALREADY INSPECTED: SOURCE_NOTES; upstream links selected and cached.
NEXT TARGETS: T00 on a subsequent coding instruction; this specification phase ends here.
