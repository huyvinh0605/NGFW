# CURRENT_ARCHITECTURE_MAP — M5 planning cache

Inspected 2026-10-09 (Asia/Bangkok). Specification work only. Baseline HEAD:
`6a1905789f3f071c92549fc3bf628c3b7f7edfc6`. Existing uncommitted M4 changes
are input to this audit, not changes produced by M5 planning. Do not discard them.
The user supplied the M5 networking brief and a separate legacy-compatibility
brief; the latter requires adapter-first extension and an additional compatibility matrix.
No AGENTS.md was returned by the bounded repository instruction-file search.

## Cached source facts

| FILE | IMPORTANT TYPES / FUNCTIONS | OWNS / CALLS / CALLED BY | RELEVANT TESTS | OPEN QUESTIONS |
|---|---|---|---|---|
| `internal/domain/types.go` | `Interface`, `Route`, `Config` | Interface IDs, VLAN parent/ID, v4/v6 address lists, MTU/admin state. Route has destination/gateway/interface/metric/enabled; no table/protocol/VRF/multipath. Config has optional Inspection/RequestGate and TLSExclusions; no M5 fields. | config manager, dataplane Linux tests | None about model. |
| `internal/config/manager.go` | `Validator.Validate`, `Manager.SetCandidateIfValid`, `CommitWithGeneration`, `RollbackWithGeneration`, `persist`, `cloneConfig` | Engine Running authority; Candidate validation; activation/version locks. Commit calls apply(target,next generation), then fsync/rename Running; failures call apply(old,old generation). Post-publication recovery is coordinated by RuntimeServiceAdapter. `running.json` includes previous config and is 0640; store assumes no plaintext credentials. Cloning is explicit. | `TestCommitApplyFailureRestoresOldConfigAndDoesNotPublish`, `TestCommitWithGenerationNeverRestoresOldConfigUsingTargetGeneration`, `TestRollbackWithApplySurvivesManagerRestart` | Add optional M5 deep clone/validation only. |
| `internal/dataplane/linux.go` | `IPCommandRunner`, `NetworkReconciler.Reconcile`, `PlanNetwork`, `routeArgs`, `ensureVLAN` | Direct argv `ip` adapter. Deletes only routes/addresses in previous desired snapshot, not an enumeration of all live objects. Deletes stale VLAN links. Adds desired addresses and route replace commands. Existing route commands do not specify table/protocol. Link deletion can indirectly remove external addresses/routes; route replace can collide with another writer even without a broad flush. | `TestPlanNetworkRemovesStaleStateAndBuildsVLAN`, `TestPlanNetworkDoesNotDeleteUnchangedRoute`, `TestReconcilerRestoresPreviousSnapshotAfterCommandFailure` | Need minimal provenance guard and dependency validation before external routing/VIPs. |
| `internal/dataplane/controller.go` | `NewController`, `ApplyRuntimePrepared`, `ApplySnapshotPrepared`, `FinalizeActivation`, `RecoveryPending` | Existing inner dataplane transaction: journal -> forwarding -> network.Reconcile -> nft bundle -> applied snapshot. Prepared mode retains journal until Running/runtime lifecycle match. Rollback uses stored previous snapshot/compiler metadata, not target metadata. | controller tests; activation_snapshot tests | M5 outer journal must compose with this lifecycle, never replace it. |
| `cmd/ngfw-engine/main.go` | `main`, local `applyDataplane`, `validateInspectionArtifacts`, `configureInspection`, `makeZoneSlots` | Creates config manager, IP/nft adapters, controller, durable epoch allocator, conntrack Runtime, inspection lifecycle and GateService. Startup reconciles Running before runtime. Wires `BeforeActivate`, `ApplyGeneration`, `AfterActivate`, `FinalizeActivation` into RuntimeServiceAdapter. M4 working-tree additions must be preserved. | engine runtime/service and dataplane tests | Exact new orchestrator binding recorded in implementation plan. |
| `internal/engine/runtime_service.go` | `RuntimeServiceAdapter.CommitConfig`, `RollbackConfig`, recovery helpers | Serializes commits and inspection activation; manager apply/persist -> runtime generation -> inspection lifecycle -> journal finalize. Recovery after publication uses a newer monotonic generation. | runtime service/activation tests | M5 must compose existing callbacks and idempotent compensation. |
| `internal/engineipc/runtime.go` | `RuntimeService`, optional `InspectionRuntimeService`, optional `RequestGateRuntimeService`, `RuntimeServer.dispatch` | Versioned bounded Unix JSON IPC; strict version/request matching. Optional interfaces are an existing extension pattern. | runtime_test.go, request_gate_runtime_test.go | Add optional M5 status/capability interface; no tool syntax in IPC. |
| `internal/management/api.go` | `API.Handler`, `candidate`, `validate`, `commit`, `rollback`, `sessions` | Candidate PUT at `/api/v1/config/candidate`; existing validation/commit/rollback endpoints are under `/api/v1/policies/`. Runtime GET/commit through IPC. Session detail returns RuntimeSession. | management tests | Verify exact body/envelope before writing acceptance command recipes. |
| `internal/session/runtime_store.go` / `internal/domain/session_m2.go` | `RuntimeStore`, `RuntimeSession`, `makeNAT`, identity/tuple indexes | Sole conntrack-derived session store. Original/reply/translated aliases, boot/ns/zone/ID/start identity, revisions and policy generation. In-memory bounded lifecycle; no second session authority permitted. | runtime_store_test.go | No M5 changes planned to store/identity. |
| `internal/dataplane/mark.go`, ADR 0002 | M2 mark layout | Upper 24 ct-mark bits: 12 epoch + two 6-bit zones; low byte preserved, not free for M5 to claim. Startup changes epoch. | mark_test.go, epoch_test.go | WAN design must not allocate marks. |
| `internal/inspection/correlation/resolver.go`, ADR 0003 | `Resolver.Resolve`, `SessionLookup` | Correlates sensor epoch, tuples/NAT aliases, conntrack identity/time; ambiguity is not enforcement evidence. M3 uses M2 store. | resolver tests, M3 regression matrix | Route/zone and proxy-leg regressions need explicit cases. |
| `web/src/App.tsx`, `types.ts`, `runtimeData.ts` | `saveCandidate`, `NGFWConfig`, config/session normalization | Existing network/routes/NAT pages; whole Candidate PUT; derived session display; no FRR/LB/VRRP status model. | web tests | Preserve M5 nested fields through all legacy editing paths. |
| `deploy/ngfw-engine.service` | systemd service | root:ngfw, NET_ADMIN only, NoNewPrivileges, strict filesystem; writable paths limited to state/log/sysctl/runtime. | deployment/VM evidence | M5 needs isolated orchestration paths/groups; API still no caps. |
| `deploy/ngfw-api.service` | systemd service | ngfw:ngfw, no capability grant, read-only main state plus management state writes. | M1 process-capability evidence | No privilege changes planned. |
| `docs/architecture.md`, ADR 0003/0004 | milestone boundaries | Early M1 prose about API publishing Running is superseded by M2+ engine manager implementation. ADR 0004 still calls later ML/risk “M5”; current user reassigns M5 to networking. | milestone matrices | Record naming conflict without rewriting legacy docs. |

## First-pass checkpoint

FINDINGS: Existing network and transaction machinery can be extended; no routing
protocol, HAProxy or VRRP backend is present in audited integration points. Static
route provenance and local service security are real dependencies, not grounds
for a wholesale dataplane refactor.

DECISIONS: New documents live in `docs/m5/`; preserve all existing working-tree
files. Treat present M1–M4 behavior as compatibility contracts independently of
their individual acceptance status. Reuse optional IPC interfaces and existing
commit callbacks. No implementation, tests, VM mutation or package installation
during this phase.

UNRESOLVED: exact upstream integration/version contracts; route collision
coordination; dynamic-prefix zone attribution; local HAProxy admission versus
M4 interception; VRRP readiness and address ownership; exact frontend config
normalization boundary. Investigate these symbols only.

FILES ALREADY INSPECTED: all rows above; `go.mod`; top-level names; M1–M4 ADRs.
SOURCES ALREADY INSPECTED: initial VyOS 1.5 WAN/BGP/HA search excerpts; source
notes will contain resolved links and selected sections.
NEXT TARGETS at first pass were `Program.InferAddressZone`, API envelopes and M4
selector runtime. Those questions are resolved by the checkpoint below.

## Completed targeted-pass cache (supersedes first-pass open questions)

| FILE | IMPORTANT TYPES / FUNCTIONS | OWNS / CALLS / CALLED BY | RELEVANT TESTS | OPEN QUESTIONS |
|---|---|---|---|---|
| `internal/connectivity/program.go` | `Compile(config,generation)`, `InferZones`, `InferAddressZone` | Uses connected/static prefixes and longest-prefix zone mapping; no learned-RIB authority | connectivity program tests, M3 resolver alias/ambiguity tests | None; proposed configured-prefix helper specified as F33/F34 |
| `internal/management/api.go` | `configView`, `candidate`, `validate`, `commit`, `rollback` | GET config returns data.running/candidate/version.version; Candidate PUT full Config; commit expected_version/author/comment; no vendor tools | management API tests | None; C0 recipe uses actual envelope |
| `internal/dataplane/activation_snapshot.go` | `cloneActivationSnapshot`, `cloneActivationConfig` | JSON deep config clone + M2Options.Clone + inspection-plan clone | activation/controller tests | None; proposed accessor F19 reuses exact metadata |
| `internal/dataplane/controller.go` | `currentSnapshot`, current config/options/generation fields under mu | Snapshot/current-known state exists privately; no public exact accessor currently | controller exact rollback tests | None; additive controller_m5.go only |
| `internal/engine/runtime_service.go` | `CommitConfig`, `RollbackConfig`, `pauseInspection` | Commit calls BeforeActivate before inspection pause; rollback pauses first. Existing applyMu serializes mutations; receipt map is memory-only | M3 stage-order/recovery tests | None; M5 per-method mutex must not span callbacks |
| `internal/engineipc/runtime.go` | `call`, `handle`, `dispatch`, client/server constructors | v3, 2s query, 60s mutation defaults; bounded8MiB/16 pending | IPC tests | None; config-only negotiated M5 timeout is a documented extension |
| `cmd/ngfw-api/main.go` | HTTP server construction | WriteTimeout95s, ReadHeader5s/Read10s, Idle60s | API lifecycle tests | No source modification needed; per-request write deadline in API handler |
| `web/src/api.ts` | `api<T>(path,init,token,timeoutMs?)` | Already accepts timeout override; can reuse without modifying this helper | web API tests | None; App/new wrappers supply negotiated budget |
| `web/src/runtimeData.ts` | `normalizeConfig`, `normalizeConfigExport` | Spreads raw record before normalizing known fields; typed lossless optional subtree still needs explicit tests | runtimeData tests | None; F57 minimal extension |
| `internal/dataplane/compiler.go` | `CompileRuleset`, `renderNATRule`, `renderDNATZoneGuard` | Existing M1 firewall/NAT compile; no M5 local-service guards | compiler tests | No production compiler edit planned |
| Current dirty M4 files / `internal/domain/runtime_ipc.go` | runtime supervisor/SyncProxy/engine gate wiring; runtime IPC DTOs | Working tree, not just old README, is architectural input; selector compiler does not prove Linux transparent path complete | T00 records actual baseline | No redesign; M4+HAProxy rejected |

DECISIONS (final): D01–D12 in M5_ARCHITECTURE; exact model/function/task contracts
in the eleven M5 deliverables. Resource provenance uses leaf resources DTOs and
separate ownership adapter; concrete WAL/artifacts are in state/ so contracts
do not import dataplane. Node-local HAProxy and control protocol admission uses
one scoped engine-owned nft table. No new session/security authority.

OPEN_QUESTIONS (execution only): O01 baseline tests; O02 installed versions/caps/
reservation proof; O03 Keepalived protected snapshot; O04 extra VM/NIC mapping;
O05 optional IPVS library. See M5_RISK_REGISTER. No further repository scan needed.

FINDINGS: architecture, ownership, envelope and privilege questions resolved for
planning. FILES ALREADY INSPECTED: both cache tables above. SOURCES ALREADY
INSPECTED: SOURCE_NOTES including pinned Linux/FRR privilege source. UNRESOLVED:
measured gates above. NEXT TARGETS: subsequent implementation starts T00 using
M5_EXECUTION_MAP. No source code or VM state was modified during this phase.
