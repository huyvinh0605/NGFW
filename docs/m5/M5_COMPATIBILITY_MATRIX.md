# M5 compatibility matrix

**Specification only — 2026-10-09.** EXISTING means inspected source, not a new VM
acceptance claim. All M5 changes below are PROPOSED. Existing local M4 edits are
part of the input baseline. See [audit](M5_CURRENT_STATE_AUDIT.md) and
[source cache](CURRENT_ARCHITECTURE_MAP.md) for exact current symbols.

## Feature compatibility

| Feature | M1 interaction | M2 interaction | M3 interaction | M4 interaction | Shared contract/resources | Regression risk | Mitigation | Required regressions / VM |
|---|---|---|---|---|---|---|---|---|
| Optional M5 config and disabled state | Existing Candidate/Running/rollback serializes optional subtree | No new generation allocator or session store | Existing activation callbacks still run in order | Preserve RequestGate fields, pending local implementation | Config, cloneConfig, Validator.Validate, whole-Candidate UI | Aliasing, discarded fields, accidental daemon start | nil clone preserved; absent/steady disabled means no M5 IO; disabling active config performs one scoped cleanup | Old JSON golden round-trip, clone mutation, disabled spy Runner; A00/A01/A28 |
| OSPFv2 | FRR owns learned routes; M1 owns static routes/interfaces | A changed FIB can alter path, not session ID/mark | New remote prefixes need explicit zone attribution | Forwarded M4 selector remains legacy-owned | Interface IDs, static prefix reservation, routing ReachablePrefixes | M1 route replace collision, VLAN delete removes learned nexthop | Exact provenance guard + FRR reserved-prefix deny; block referenced link deletion | M1 PlanNetwork/reconcile; OSPF A02–A05; M2/M3 regressions |
| BGP | Same ownership; no FRR staticd | No tuple/epoch copying from RIB | Route filter must not grant a security zone implicitly | No BGP-origin policy verdicts | RoutePolicy separate from SecurityPolicy | Route leaks, max-prefix reset, false status success | Mandatory import/export route map and exact origin prefixes, upper bound, fail-closed render | A06–A08/A29; legacy firewall default deny |
| Route policy/redistribution | Static redistribution is exact M1-owned kernel routes through generated filters | No mark allocation | Cannot rewrite original/translated tuples | No request rules in route map | Routing-specific prefix lists/maps | Accidentally exporting connected MGMT/default | Generated protected exclusions cannot be overridden; denied unless explicit map | A07/A29; compiler negative fixtures |
| BFD | Only FRR reacts by changing its routes | Established flow may stop or rehash; no conntrack flush | Existing sensor events still require valid identity/epoch | Existing request failures use M4 handling | FRR peer/interface/profile | Claiming guaranteed detection from configured timer | Measure real wall time + negotiated timers; no global TCP continuity promise | A09/A11 plus late-event correlation |
| ECMP / routed WAN failover | FRR owns ECMP nexthops; scoped sysctl lease only | No second flow selector; no sticky-NAT guarantee | All candidate next hops must have same declared zone | Existing M4 flows may need reconnect | Main FIB, route status, netlink observer | Double writer, asymmetric return, changing source address | Architecture C; reject overlapping NAT/weighted/PBR; advertise LAN return route | A10–A13, unchanged M1 NAT tuple/mark regressions |
| WAN health observer | Does not withdraw/install routes | No session entries created by probes | Probes are local diagnostic connections, not security evidence | No probe request gating | Source/device-bound TCP socket | False per-link results, stale task leaks | Fresh one-bind socket, bounded pool, label probe separately from BFD; no routing authority | A12, cancellation/race tests |
| HAProxy delivery/TLS | New scoped INPUT/OUTPUT admission; legacy FORWARD rules do not secure local sockets | Two TCP legs appear separately; do not merge identities | Forward inspection does not imply inspection of proxy's local legs | Effective M4 and HAProxy enabled together rejected in either direction | Ordinary explicit listener addresses; dedicated UID; opaque secret refs | Inspection bypass, port conflict, arbitrary egress | DELIVERY_ONLY label; engine admission; no wildcard/MGMT/VIP binds; backend egress allowlist | A14–A17/A21; M4 gate tests unchanged |
| VRRP | Keepalived owns VIP, M1 owns ordinary IP; link dependency guard | New flow may work after takeover; old flow state is not replicated | Standby has no authoritative replica of M3 evidence | M4/TLS streams cannot migrate | Per-node Running, VIP registry, readiness | M1 removes VIP indirectly; dual MASTER; stale ready file | Disjoint addresses; block referenced link changes; age+boot/gen readiness; explicit partition limitation | A18/A19/A22/A24; M1 address lifecycle |
| Optional IPVS NAT | Separate Keepalived checker owns virtual service, legacy NAT must not overlap | Kernel IPVS connection and conntrack association are not SENTINEL sessions | NAT aliases require dedicated regressions | M4 overlap rejected; separate from HAProxy | Virtual tuple registry, real-server return path | Duplicate writer, shortcut return path, persistence mislabel | One checker writer; NAT only; structured read-only observer | T31–T33; A30, NAT alias correlation |
| Future VRF/PBR | New tables/link enslaving would affect M1 route/address contract | Namespace/zone identity cannot be assumed VRF-aware | Ambiguous identical tuples across VRFs | Proxy socket VRF binding not designed | FUTURE; no accepted fields | Cross-tenant identity and wrong egress | Reject unknown config; design dedicated contract before coding | A01; no VRF acceptance claim |
| Future conntrackd | Imported NAT state belongs to kernel sync adapter | Does not replicate M2 boot identity, epoch, policy revision or caches | No sensor epoch/verdict replication | No HTTP/TLS/proxy memory replication | FUTURE ConntrackSyncBackend only | Stale ct marks authorize wrong generation; split brain | Separate takeover/import barrier spec; no code/config/runtime in core | A31 negative contract only; no seamless failover claim |

## Existing evidence and the regression gate

M1 VM evidence is available under the following existing directories. These are
baseline evidence references, not proof that any M5 integration has passed:

- [preflight/reboot](../../artifacts/m1-preflight-reboot-20261005T110434Z/RESULTS.md);
- [NAT](../../artifacts/m1-nat-acceptance-20261005T0905Z/RESULTS.md);
- [startup/VLAN](../../artifacts/m1-startup-vlan-20261005T140631Z/RESULTS.md);
- network/policy and remaining runs: `artifacts/m1-network-policy-20261007T074203Z/`,
  `artifacts/m1-remaining-20261007T082100Z/`.

Do not edit those raw logs or relabel their time windows as M5 evidence. T00
records the actual baseline of M2–M4 tests, including incomplete M4 work.
A baseline failure is recorded separately; it cannot be hidden by disabling a
test. A new regression blocks release even if the new M5 feature passes.

## Minimal changes to existing files

All names in the first column exist. New files are catalogued in the
[file plan](M5_FILE_IMPLEMENTATION_PLAN.md).

| File classification / exact integration | Why a new adapter alone is insufficient | Smallest proposed change | Backward compatibility | Regression gate | Rollback |
|---|---|---|---|---|---|
| SHARED_CONTRACT `internal/domain/types.go::Config` | Running serializer needs a supported root field | Add optional NetworkServices pointer only; preserve Route/Interface JSON | Old JSON unchanged when nil | Round-trip old fixtures; nil/disabled tests | Disable M5 through normal commit, export old-compatible config, then revert field |
| M1_FILE `internal/config/manager.go::Validator.Validate, cloneConfig` | Explicit validator/clone otherwise loses or aliases the subtree | Delegate pure validation; clone pointer/slices | Legacy errors, persistence/version/locks unchanged | Existing commit/rollback/clone tests | Revert delegations only after disabling |
| M1_FILE `internal/dataplane/linux.go::NetworkOperation, NetworkReconciler.Reconcile, PlanNetwork` | Current route replace can collide with external route; changing vendor renderer alone cannot protect it | Add typed route metadata and optional ownership hook before commands; preserve nil path/routeArgs | M5 disabled follows current argv/order; no broad cleanup | Existing PlanNetwork, unchanged-route, failure restore; A04/A05 | Restore baseline static metadata while M5 still running; remove FRR/VIP deps, disable; revert hook |
| M2_FILE `internal/engine/runtime_service.go` | Status must be served by authoritative engine optional interface | Add optional coordinator field; optional methods implemented in new file; preserve existing activation functions | Same M2 authority/order; no new session store | Runtime activation/order/recovery tests | Remove optional wiring after disabled cleanup |
| M2_FILE `internal/connectivity/program.go::Compile` | Zone inference currently sees only connected/static prefixes | Invoke new pure validated dynamic-prefix helper once | nil M5 leaves prefix program identical | Ambiguous/overlap/longest-prefix tests, M3 resolver regressions | Remove call only after disabling routing |
| SHARED_CONTRACT `internal/engineipc/runtime.go::dispatch, call, handle, CommitConfig` | Old server can ignore unknown config unless client negotiates; 60s mutation bound too short | Add optional methods/capability and per-operation negotiated config timeout | Protocol v3 retained; old methods payloads unchanged; unsupported engine rejects M5 locally | IPC old-server/mismatch/cancellation/idempotency; A25 | Paired API/engine rollback; old config exported first |
| SHARED_CONTRACT `internal/management/api.go::Handler, commit, rollback` | New HTTP routes and long commit response budget | Register read-only M5 handlers; conditional 200s response deadline only for config mutation | Authentication and Candidate/commit endpoints retained; no exec path/caps | Auth, API dependency audit, request cancellation; A25/A27 | Revert route/deadline hook with paired release |
| SHARED_CONTRACT `cmd/ngfw-engine/main.go::main` | Composition root constructs existing callbacks | Construct adapters/coordinator; compose callbacks; recover outer journal before normal startup | Preserve existing M3 hooks/M4 additions, epoch allocation and legacy startup | Full stage-order fixtures; A05/A23/A24/A28 | Disable and verify no outer WAL before old binary |
| SHARED_CONTRACT `web/src/types.ts, runtimeData.ts, App.tsx, navigation.ts` | Current editors save whole Candidate | Optional types, lossless normalization, new views and mutation budget; reuse existing api.ts timeout argument without editing it | Legacy editor round-trip cannot erase M5/M3/M4 fields | Frontend round-trip and request tests | UI downgrade only with compatible config or read-only old UI |
| SHARED_CONTRACT `deploy/ngfw-engine.service` | ProtectSystem and DAC restrict new artifacts/control sockets | Add scoped M5 drop-in paths and supplementary component groups; retain NET_ADMIN-only bound | API unchanged; no NET_RAW/SYS_ADMIN grant; no group requirement without installed drop-in | A00/A27 cap/file probes | Restore previous drop-in after disable + daemon stop |

`internal/dataplane/controller_m5.go` is **NEW_M5_FILE**, in the existing package:
read-only snapshot accessor under the existing mutex; no algorithm change in
`controller.go`. It clones `currentSnapshot`, or constructs an exact snapshot
from current config/options/generation when known; unknown state returns false
and an active M5 activation must stop before mutation. This is needed so rollback
uses the actual old epoch/inspection metadata, not recomputed target metadata.

No changes planned to `internal/session/`, conntrack identity/mark layout,
`internal/inspection/correlation/`, `internal/proxy/`, `internal/gateipc/`,
`cmd/ngfw-proxy/`, existing nft M1/M3/M4 compilers or existing M1–M4 raw evidence.
These are regression consumers. Newly created tests in these packages do not
authorize rewriting their production algorithms.

## Mandatory tests at every implementation checkpoint

The task's new tests plus directly touched package tests must pass. Selected
regressions (existing names located during audit):

- M1: `TestPlanNetworkRemovesStaleStateAndBuildsVLAN`,
  `TestPlanNetworkDoesNotDeleteUnchangedRoute`,
  `TestReconcilerRestoresPreviousSnapshotAfterCommandFailure`,
  `TestControllerRestoresNetworkAndNftablesAfterNftFailure`,
  `TestControllerLoadsSnapshotAndReconcilesOnStartup`,
  `TestControllerUsesInterruptedTargetAsRecoverySource`.
- M2/M3 activation: `TestRuntimeServiceM3ActivationStageOrderAndGeneration`,
  `TestRuntimeServicePreflightFailureHasNoActivationSideEffect`,
  `TestRuntimeServiceFailedApplyRestoresPreviousExactGenerationAndFinalizes`,
  `TestRuntimeServicePostPublishFailureRestoresThroughNewerGeneration`,
  `TestRuntimeServiceHoldsInspectionGateAcrossApplyAndReleasesBeforeLifecycleHook`.
- M3 correlation: `TestResolverUsesTupleAndBindsFlowID`,
  `TestResolverNewSensorEpochDropsOldFlowBinding`,
  `TestResolverDoesNotGuessAmbiguous`,
  `TestResolverDoesNotEnforceAgainstSessionMissingKernelStart`,
  `TestResolverMapsSNATDNATAndDoubleNATAliases`.
- M4: use existing `tests/integration/m4/` procedures and current targeted
  `internal/proxy`, `internal/engine`, `internal/gateipc` test files recorded at
  T00. Do not guess a test function name or claim the uncommitted M4 work passed.

Kernel/network claims require the referenced Axx VM cases in addition to these
tests. A model/renderer-only task may merge behind disabled capability after
unit/legacy gates, but cannot be marked operational until its VM gate passes.

## Planning checkpoint

FINDINGS: required legacy production edits are narrowly bounded; dynamic zone
attribution and route provenance are proven dependencies.
DECISIONS: adapter-first; no session/M3 correlation/M4 traffic redesign; release
requires both new acceptance and selected legacy regressions.
UNRESOLVED: T00 baseline and T01 installed capabilities are future execution gates.
FILES ALREADY INSPECTED: exact legacy symbols above and CURRENT_ARCHITECTURE_MAP.
SOURCES ALREADY INSPECTED: SOURCE_NOTES F01–F08/H01–H02/K01–K02/L01–L05/C01.
NEXT TARGETS: task/file traceability, packaging and executable VM procedures.
