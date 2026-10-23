# M5 architecture — advanced networking, routing, load balancing and HA

Status: implementation specification, 2026-10-09. Nothing in this document is a
claim of installed/running M5 functionality. Existing symbols are in the
[audit](M5_CURRENT_STATE_AUDIT.md); all new names below are PROPOSED.

## 1. Scope and decisions

**Core M5**: IPv4 FRR OSPFv2, BGP unicast, bounded prefix-list/route-map policy,
BFD, FRR/Linux ECMP and routed uplink failover; HAProxy TCP/HTTP delivery,
TLS termination and verified backend TLS; Keepalived IPv4 VRRP with sync groups,
health tracking, configuration transactions and operational APIs/UI.

**Optional M5 extension**: IPVS NAT-mode virtual servers. It is not a core
completion prerequisite; its adapter contract and gated tasks are specified.
**Future**: IPv6 dynamic forwarding, VRF, arbitrary PBR, independently weighted
per-flow multi-ISP NAT, conntrackd stateful failover, IPVS DR/tunnel, IS-IS,
SD-WAN, ML/risk. Do not add inactive configuration fields for future features.

| Decision | Binding choice |
|---|---|
| D01 Authority | Engine owns Running, validation, security and orchestration; API stays unprivileged; adapters own vendor syntax. |
| D02 Legacy compatibility | Nil/disabled M5 with no previous M5 state takes the exact legacy path: no daemon calls, generated files, new rules, capabilities or timers. Disabling previously active M5 performs journaled removal once; steady disabled state is a no-op. |
| D03 Static routes | M1 retains static route semantics and writes. No FRR staticd configuration. |
| D04 Dynamic routes | FRR zebra writes BGP/OSPF routes. Core uses IPv4 main table; generated FIB filtering reserves exact M1 static prefixes. Protocol tagging alone is never considered writer isolation. |
| D05 WAN choice | Architecture C from the brief: FRR selects routing paths and Linux executes ECMP. `internal/wan` is a configuration/status facade, not a route/mark writer. No simultaneous independent WAN-LB implementation exists. |
| D06 Zones | Explicit configured reachable prefixes map to one routing zone. All active dynamic next-hop interfaces use that zone; route learning cannot change security-zone membership. |
| D07 M4/LB | Core HAProxy is DELIVERY_ONLY. Any effective M4 configuration plus enabled HAProxy is rejected on the node. Combined inspection/delivery is unsupported, not silently bypassed. |
| D08 VIPs | Keepalived alone adds/removes VRRP VIPs. VIPs cannot also be ordinary M1 addresses, proxy listener addresses, route gateways on the same node or manually managed addresses. |
| D09 Transactions | Existing M1–M4 inner activation plus new outer compensating transaction; no distributed atomicity claim. |
| D10 Secrets | Immutable versioned SecretRef values in Config; protected files outside API-readable state; generated secret-bearing files never become API payloads. |
| D11 Runtime | Engine status cache/events observe daemons; peers DOWN/backends DOWN are operational state, not desired-config drift. |
| D12 HA semantics | Router VIP redundancy is core. No live replication of M2 decisions, M3 evidence, M4 requests or HAProxy connections; no seamless TCP failover claim. |

Source rationale: [FRR route filtering F04](SOURCE_NOTES.md), [VyOS WAN V09](SOURCE_NOTES.md),
[Linux VRF L03](SOURCE_NOTES.md), and [HAProxy/Keepalived H01–K02](SOURCE_NOTES.md).
The narrower choices are SENTINEL decisions, not restrictions attributed to VyOS.

## 2. Resource ownership matrix

Classes: **S** SENTINEL_MANAGED; **E** EXTERNAL_DAEMON_MANAGED; **K** KERNEL_RUNTIME;
**O** OBSERVED_ONLY. Desired configuration is always engine Running for enabled
features. Kernel runtime/foreign resources have no SENTINEL desired copy.
“Repair” means the named owner repairs its own resource only.

| Resource / class | Desired owner | Apply owner / kernel writer | Observer | Drift repair | Restart behavior | Daemon crash behavior | Two writers? |
|---|---|---|---|---|---|---|---|
| Physical interfaces S | Engine/M1 | M1 IP adapter | Kernel observer | M1 reconciler | Existing snapshot reconcile | FRR/LB cannot rewrite link | No |
| VLAN S | Engine/M1 | M1 IP adapter | Kernel observer | M1; external references gate deletion | Existing create/delete | External state remains protected | No |
| Ordinary addresses S | Engine/M1 | M1 IP adapter | Kernel observer | M1 exact snapshot | Restore Running addresses | No vendor action | No |
| Static routes S | Engine/M1 | M1 with provenance guard | Kernel + FRR view | M1 exact claim | Preserve/acquire static reservation, restore own route | FRR failure cannot authorize deletion/replacement | No; FRR excludes reserved prefixes |
| BGP/OSPF routes E | Engine owns protocol intent; learned routes not Config | FRR zebra | FRR JSON + kernel JSON | FRR reconvergence | Reapply protocol config, preserve/relearn actual routes | Routes can withdraw or linger; report actual FIB until owner recovers | No |
| Connected/local routes K | Kernel consequence of addresses | Kernel | Kernel observer | Address owner, never route sweeper | Kernel rebuild | No M5 deletion | No |
| Main table S/E/K entries | Per-entry ownership above | Corresponding owner only | Kernel observer | Per-entry | No table flush | No cross-owner flush | Coordinated per entry, never independent same key |
| RPDB rules O in core | OS/administrator | No core M5 writer | Kernel observer | None | Preserve | Preserve | No |
| VRF devices O in core | OS/administrator | No core M5 writer | Kernel observer | None; incompatible core references rejected | Preserve | Preserve | No |
| `inet ngfw` and NAT S | Engine/M1 | Existing nft adapter/compiler | nft readback | Existing controller | Existing activation journal | FRR/HAProxy/Keepalived cannot flush it | No |
| M2/M3 tables/marks S/K | Existing engine contracts | Existing nft/conntrack mechanisms | M2/M3 | Existing runtime | Epoch/leases remain legacy controlled | M5 cannot clear or reassign | No new writer |
| M5 local-service guard S | Engine service-access intent | New M5 nft adapter only | nft readback | M5 coordinator | Closed admission until valid desired service | A crashed service never broadens admission | No |
| SENTINEL sessions S | Engine runtime | M2 RuntimeStore; kernel owns conntrack data | IPC API/M3/M4 | Existing resync | Rebuild from conntrack | No daemon may replace store | No |
| OSPF config/process E | Engine | FRR adapter/config; ospfd + zebra | FRR JSON/systemd | M5 desired config; systemd process; FRR protocol | Generated config restored | Watchfrr/systemd restart; engine bounded reconcile | No |
| BGP config/process E | Engine | FRR adapter; bgpd + zebra | Same | Same | Same | Same | No |
| BFD E | Engine | FRR bfdd only | FRR JSON | FRR + coordinator | Restore sessions/profile config | Routing reacts to loss | No Keepalived BFD writer |
| HAProxy listeners E | Engine | HAProxy sockets; no route writer | Runtime JSON + socket probe | Adapter config/systemd | Closed guard then validate/load/open | Process restarts; active connections may end | No |
| HAProxy backends E | Engine | HAProxy runtime; ordinary sockets only | Runtime JSON | Health belongs to HAProxy | Rebuild pools; fresh health | Routing/firewall intact | No |
| VRRP VIPs E | Engine defines group; Keepalived elects | Keepalived NET_ADMIN | FIFO/JSON + kernel | Keepalived; engine repairs config only | Start BACKUP with readiness gate | VIP must be released or crash residue reconciled by Keepalived before healthy | No M1 address writer |
| IPVS virtual/real servers E, optional | Engine | Keepalived checker-only instance through IPVS adapter | IPVS structured state | Checker instance | Gated optional recovery | No nft NAT ownership transfer | No competing direct IPVS writer |
| HA conntrack state FUTURE | Engine defines sync policy | conntrackd only after a new acceptance gate | Kernel/conntrackd | Future adapter | Explicit recovery barrier required | Local M2 stays authoritative | Never another session authority |
| Foreign routes/addresses/tables O | External administrator/OS | Their existing owner | Bounded snapshots | No automated adoption | Preserve | Preserve | M5 reports conflict |

## 3. Static/dynamic coexistence and provenance

Current `PlanNetwork` deletes only previous snapshot objects. Keep that behavior.
Add optional `dataplane.NetworkOwnership` and typed route metadata on planned
operations; the default constructor supplies no hook. An M5 `ownership.Guard`
implements the hook and inspects only affected route keys/interfaces.

M1 static claims are `(family,table=254,prefix,metric,gateway,ifindex,type)` plus
config route ID, observed protocol and manifest digest. Newly adopted M5-managed
static entries use protocol **196**, reserved by installer after conflict checks.
An existing untagged M1 route is adopted only if it uniquely and exactly matches
the previous Running/applied snapshot and kernel readback. Unknown same-key
routes cause `RESOURCE_CONFLICT`; protocol number alone never establishes ownership.
No mutation of the legacy Route JSON schema is needed.

FRR generation contains engine-generated protocol-specific zebra FIB route maps
for `bgp` and `ospf`: deny exact M1-owned prefixes, deny management/local protected
prefixes, permit only configured reachable prefixes, then deny all. Reserved
rules use an internal namespace users cannot reference or override. Routing
policy import/export filters remain separate. Connected routes remain kernel
owned. FRR route sources come from its JSON and kernel route protocol together;
unknown/inconsistent provenance is OBSERVED_ONLY, never a deletion candidate.

When static ownership changes, first install FIB reservations for the **union**
of old and target static prefixes; wait for dynamic entries at those exact keys
to withdraw (bounded readback, not a fixed sleep). Then M1 changes its routes.
Finally reduce reservations to target prefixes. Reverse this handoff during
compensation. A DOWN/unreachable FRR or a lingering conflicting dynamic entry
causes failure before the conflicting M1 mutation. An unrelated FRR peer change
does not cause M1 reconciliation or an M2 generation increment.

FRR receives no `ip route`, interface `ip address`, VLAN, NAT or firewall commands.
M1 static redistribution is not FRR `staticd`: the adapter maps the supported
`M1_STATIC` source to an exact configured-prefix allowlist over kernel routes.
Require VM evidence that the pinned FRR sees protocol-196 entries correctly.
Unfiltered kernel/connected redistribution, redistribution loops, and implicit
advertisement of management/VIPs are rejected.

Interface removal, parent/VLAN replacement, admin-down, address removal used as
peer source, and MTU changes on active peers require an explicit updated target
that removes/quiesces dependents first. The coordinator sequences shutdown before
M1 link mutation; validator never repairs dependency conflicts by silently deleting
another subsystem. VRRP VIP/ordinary address ownership transfer needs two commits:
remove the old owner and verify absence, then introduce the new owner.

## 4. Routing, policy, WAN and session contracts

`internal/routing` owns abstract desired plans/status; `routing/frr` alone renders
FRR commands. `routingpolicy` compiles typed prefix lists and route maps into a
vendor-neutral plan; it never imports `connectivity.SecurityPolicy` internals.
Core routing is one default VRF, one configured routing zone, IPv4 unicast,
at most 32 BGP neighbors, 32 OSPF interfaces, 128 BFD sessions and 4096 observed
routes. `reachable_prefixes` is configured authority for zone enrichment and FIB
admission; learned routes do not expand it. All non-passive next-hop interfaces
must use that zone. Management subnets/local addresses and conflicting cross-zone
prefixes cannot be imported. This is a scoped extension to `connectivity.Compile`,
not a runtime RIB dependency in the policy evaluator.

`WANMultiLink` is a facade selecting **FRR_FAILOVER** or **FRR_ECMP**, explicit BGP
neighbors/interface paths, and monitored prefixes. FRR attributes choose primary/
backup; BFD drives withdrawal. ECMP uses equal eligible paths; no user-space
balancing algorithm, RPDB rule, packet mark, ct label or second route writer.
Fixed weighted ISP distribution is unsupported and rejected. For these monitored
multi-path prefixes the core rejects potentially overlapping SNAT/MASQUERADE/
DNAT and interfaces in different zones. This restriction does not disable ordinary
M1 NAT on unrelated single-path traffic. Conservative overlap uncertainty rejects
the combination rather than weakening validation.

New connections use current FIB. With unchanged paths, kernel hashing provides
flow selection according to the observed kernel configuration. After withdrawal
or recovery, established flows may be rehashed, retransmit, stall or reconnect;
there is no sticky-path or transparent migration guarantee. No global conntrack
flush occurs. NAT aliases/identity remain M2-owned. A status probe failure alone
does not rewrite routing; BFD/protocol state determines FRR behavior. All selected
paths must have return reachability to the LAN source prefix. ECMP demo pins and
records `fib_multipath_hash_policy`; enabling L4 hashing is a scoped, journaled
sysctl lease only when WAN ECMP is enabled, restored on disable/compensation.

VRF, PBR and multi-ISP NAT require a separate proven design for route tables,
conntrack isolation and return-path persistence. Their fields are not accepted by
v1, and their absence is not represented as a successful feature.

## 5. HAProxy and local-service security

HAProxy owns frontend/backend delivery, scheduling, health checks and configured
TLS endpoints. SENTINEL owns admission. Core services bind explicit ordinary M1
IPv4 addresses, never wildcard/MGMT/VRRP addresses or existing API/M4 listeners.
Each service requires source zones and CIDRs; unspecified access is deny.

Packet path: client -> engine-owned scoped INPUT admission -> HAProxy listener ->
HAProxy selected backend -> scoped OUTPUT allowance for the dedicated HAProxy UID
and configured backend/check endpoints. This is a new **local service** access
contract; existing FORWARD policies cannot be assumed to protect a local socket.
The guard narrows access only: matching disallowed service traffic drops; other
traffic returns to existing hooks. It does not replace M1 filter/NAT tables or
claim M3 forward inspection covers either proxy leg.

TLS termination is HAProxy only for DELIVERY_ONLY services; bridging always
verifies the backend CA and hostname. Rules select backend by exact host/SNI or
bounded path prefix; they cannot issue security ALLOW decisions. Arbitrary regex,
Lua, freeform directives, user scripts, arbitrary redirects and TLS `verify none`
are outside v1. Optional redirect is same-host HTTP->HTTPS to a configured service.
Proxy Protocol is opt-in to explicitly capable backends, disabled by default.

The validator rejects `domain.UsesM4(config) && load_balancer.enabled` in either
direction, including existing Running HAProxy when a Candidate enables M4.
There is **no supported combined order** in core M5. A future order would require
engine request verdict before any application write to a downstream HAProxy,
single TLS owner, original-destination/client identity propagation, retry/body
replay rules and live bypass tests. This plan does not invent that pipeline.

## 6. VRRP and HA boundaries

Keepalived starts groups as BACKUP and owns protocol 112, election and VIP changes.
Core uses IPv4 VRRPv3, configured unicast peers on the same L2 link, priority
1..254, advert interval 1..10 seconds; preemption is explicit and initially off.
Sync groups tie related WAN/LAN VIPs; member settings/health dependencies must
agree. No Candidate-supplied scripts, `virtual_routes`, static addresses, firewall
directives, BFD instance or IPVS stanza is allowed in the VRRP adapter.

Engine writes an atomic readiness record every second only while its committed
generation, M1 dataplane verification and configured tracked subsystems are good.
A fixed unprivileged `ngfw-ha-health` helper checks boot ID, generation, complete
record and age <=5 seconds. Keepalived `track_script` uses weight zero so failure
enters FAULT. Missing/expired readiness after engine crash prevents indefinite
MASTER ownership. Keepalived, not the helper, changes VIPs. API liveness is not
a readiness dependency. Recovery obeys configured preemption/delay.

Two nodes have separate physical/MGMT addresses and separate Running versions.
Core supplies no config replication or consensus. Acceptance deploys matching
VIP/VRID/group contracts with node-specific source IP/priority and verifies both
hashes. Network partition can produce two masters: VRRP is not fencing or quorum.
Status reports local state and observed duplicate evidence without claiming a
partition-proof global truth. Node API remains on its fixed MGMT IP.

## 7. Subsystem lifecycle and adapter isolation

| Subsystem | Core -> adapter / runtime | Read and verification | Failure / restart / reconcile | Rollback and limits |
|---|---|---|---|---|
| Routing | RoutingBackend -> FRRBackend; zebra/ospfd/bgpd/bfdd | `vtysh` allowlisted JSON; exact config delta/readback; kernel affected-prefix readback | watchfrr/systemd process supervision; engine verifies desired config digest every 15s; peer DOWN is health, not config drift | Reload previous immutable artifact, restore reservation order, then reconverge. 5s status, 10s validation, 30s reload; output <=4 MiB. |
| WAN | WANObserver -> FRR status + kernel/probe adapters | Path neighbor/BFD state, selected nexthops, transitions | Read-only probes (optional TCP bound source), no custom route changes | Only ECMP sysctl lease needs compensation; no conntrack cleanup. |
| LB | LoadBalancerBackend -> HAProxyBackend | Native syntax check then Runtime JSON/schema, listener probes | systemd restarts active desired artifact; coordinator recovers stale config while admission remains closed until verified | Soft reload previous artifact; old accepted connections cannot be undone. 10s check, 20s reload, 2s socket status. |
| HA | HABackend -> KeepalivedBackend | Syntax check; structured FIFO events; JSON v2 resnapshot and kernel VIP readback | systemd restart gated by readiness; event gap yields UNKNOWN until snapshot; role transitions are not drift | Reapply previous config, election may flap; never force old MASTER role. 10s check, 20s reload, 3s snapshot. |
| IPVS optional | VirtualServerBackend -> checker-only Keepalived IPVS backend | Native generated-config validation + IPVS structured kernel observation | Exclusive writer checker process; requires optional acceptance | Restore exact virtual-server config, no claim to restore lost connections. |
| conntrackd future | ConntrackSyncBackend -> conntrackd | Kernel sync/cache status; import barriers | Not constructed in core | No supported state-sync runtime until mark/identity/security regressions are resolved. |

All processes/files/commands are encapsulated by adapters and a bounded
`netserviceexec.Runner`/`ServiceManager`. Vendor strings do not appear in API,
domain or engine orchestration. Rendering is deterministic, identifiers are
validated, argv is passed without a shell, child process groups are terminated
on cancellation, and secret-bearing stderr/deltas never enter general logs.

Status has separate `configured`, `process_reachable`, `config_applied`,
`operational`, `degraded`, `generation`, `observed_at`, `stale_after`, and reason.
No-neighbor and no-backend are not syntax success failures, but are visibly
unhealthy. Emit structured events/counters for validation/apply/reconcile failures,
role/neighbor/backend changes, timeouts, stale observations and compensation.
Read APIs use immutable bounded caches; they never spawn a process per browser poll.

## 8. Apply transaction and recovery

The new coordinator lives in engine construction and composes existing callbacks.
It owns an outer `/var/lib/ngfw/network-services/activation.json` journal with
schema, operation ID, old/target digests and generations, legacy activation
snapshot, per-adapter artifacts/checksums, completed steps, resource reservations,
sysctl leases and failure state. Files are fsynced then atomically renamed; journal
and artifact directories are private to orchestration. Learned routes, live TCP
connections and VRRP election roles are observations, never rollback desired state.

1. **Save/validate Candidate**: pure typed validation and cross-reference checks;
   no daemon writes. Runtime-dependent capability/secret/socket conflicts are
   checked again on commit. Existing version conflict behavior remains.
2. **Prepare** (`BeforeActivate`, composed with M3 preflight): clone exact target;
   validate, render to a new immutable generation, run all syntax checks, capture
   desired previous artifacts and affected resources. No listener/VIP/route changes.
3. **Journal + quiesce** (`ApplyGeneration` wrapper): persist outer WAL before
   first mutation; pause M5 reconcile; close new/changed listener admission; mark
   changed HA groups unready; quiesce removed dependents. Establish old+target
   static-prefix reservations and verify withdrawal before route handoff.
4. **Legacy apply**: call existing prepared controller with original M2/M3/M4
   generation/options semantics. No M5 adapter reaches into the legacy manager.
5. **External apply**: FRR policies before peers; HAProxy certificates/backends
   before services; Keepalived groups after interfaces/readiness dependencies.
   Stage desired artifacts so daemon restart during a pending transaction is
   recoverable. Verify syntax-independent operational installation, not adjacency.
6. **Publish**: existing manager persists Running; existing runtime advances
   generation and M3 lifecycle. No second Running file is created.
7. **Finalize**: confirm target digest/generation, verify all applied artifacts,
   release admitted services/HA readiness, finalize existing inner journal, mark
   outer transaction committed and remove it. Pending journal survives any error.

On pre-publication failure, compensate completed external steps in reverse while
guards are closed, restore exact legacy snapshot through `ApplySnapshotPrepared`,
restore prior external desired config, then reopen only verified prior services.
`CommitWithGeneration` can invoke the old apply callback again: coordinator must
recognize old digest/generation and return the idempotent compensation result.
On post-publication failure, retain existing RuntimeServiceAdapter recovery through
a newer generation; do not decrement policy generation or install target epoch
with previous policy. Administrative rollback uses the same forward transaction.

If compensation fails, record `RECOVERY_REQUIRED`, retain both journals/artifacts,
keep affected service admission/HA readiness closed, report exact subsystem error
and refuse further M5 mutations until recovery. Unrelated M1 forwarding/NAT remains
installed; no flush/reboot is a rollback strategy. Reconcile uses bounded exponential
backoff (1,2,4,8,16,30s) and a single-flight gate, not a restart storm.

Startup checks the outer journal **before** trusting generated active pointers.
If persisted Running is old, restore old desired state; if target was published,
reconcile target (or use normal newer-generation recovery on failure). Corrupt
digests cause affected M5 services to remain fenced. Existing legacy recovery is
still executed. M5 daemon availability failures produce DEGRADED M5 health and
do not tear down an otherwise valid legacy dataplane. Dynamic learned routes are
not compared with Running static arrays or replayed from snapshots.

## 9. Required architectural answers

| # | Concrete answer |
|---|---|
| 1 | M1 owns static routes; FRR staticd is disabled. |
| 2 | FRR zebra owns dynamically learned routes. |
| 3 | No same-key independent write. Generated FIB reservations and a verified handoff prevent it; a conflict fails before M1 mutation. |
| 4 | Exact resource claims + protocol196 for adopted M1 routes; FRR protocol/source evidence for dynamic entries; connected kernel routes stay separate. |
| 5 | Yes by design: startup restores desired protocol config and owned static objects; it never sweeps dynamic routes. VM A04/A05 prove it. |
| 6 | Separate RoutingPolicy/PrefixList/RouteMap types, not SecurityPolicy fields. |
| 7 | FRR-managed WAN ECMP/failover coexists with dynamic routing because FRR is the only dynamic writer. Independent WAN-LB is not supported. |
| 8 | Unknown/weighted/PBR WAN modes and unsafe NAT/multi-zone combinations are rejected by ValidateWAN before apply. |
| 9 | Yes, equal-cost routed distribution and BFD withdrawal; it does not replace ISP-specific sticky NAT. |
| 10 | Existing M2 identity/NAT mappings unchanged; no mark allocation/flush. FIB changes may alter established paths. |
| 11 | It may retransmit/recover on a common routed source or fail and reconnect; no transparent ISP migration promise. |
| 12 | Local listeners/selected traffic could overlap; core prohibits simultaneous effective M4 and HAProxy and checks socket/NAT collisions. |
| 13 | No shared path is supported in this milestone; therefore no invented processing order. |
| 14 | Mandatory validation rejects the overlap; local-service admission is explicitly engine controlled; UI/API label DELIVERY_ONLY. |
| 15 | Keepalived only. |
| 16 | VIPs are separate HA config/claims, forbidden in ordinary address arrays; referenced links cannot be removed until HA is quiesced. |
| 17 | Provenance classes and exact previous claims; no whole-table/address cleanup or replay of learned state. |
| 18 | systemd/watchfrr supervise; engine structured polling/FIFO detects failures and reconciles desired artifacts with backoff. |
| 19 | Reverse compensation with both journals retained until verified; failed restoration fences affected M5 services and preserves unrelated legacy state. |
| 20 | Core OSPF/BGP/filtering/BFD, routed two-uplink ECMP/failover, HAProxy and two-node VRRP; extra router peers/second NGFW are required by the lab topology. |

## Architecture checkpoint

FINDINGS: ownership and all twenty questions have concrete answers.
DECISIONS: D01–D12 frozen; optional/future restrictions are deliberate scope, not
claims that upstream tools lack the capabilities.
UNRESOLVED: T01 VM capability/provenance measurements; core stays disabled if any
required contract fails. FILES ALREADY INSPECTED: source cache. SOURCES ALREADY
INSPECTED: source ledger. NEXT TARGETS: schema, adapter signatures, file/function
cards, dependency tasks and reproducible VM cases.
