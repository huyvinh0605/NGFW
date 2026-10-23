# M5 current-state audit

Audit date: 2026-10-09. Source baseline and inspected-symbol cache:
[CURRENT_ARCHITECTURE_MAP](CURRENT_ARCHITECTURE_MAP.md). This audits the current
working tree, including pre-existing M4 work, without claiming VM acceptance.

| Capability | Status | Existing source / symbol | Finding and minimum extension |
|---|---|---|---|
| Physical/VLAN/admin/MTU | EXISTS | [types.go](../../internal/domain/types.go), `Interface`; [linux.go](../../internal/dataplane/linux.go), `PlanNetwork`, `ensureVLAN` | Preserve model and lifecycle. Reject deleting/recreating an interface still referenced by FRR/VRRP/service configuration. |
| Ordinary v4/v6 addresses | EXISTS | `Interface.IPv4Addresses/IPv6Addresses`, `PlanNetwork` | Snapshot-scoped deletion, not address flush. External VIP must never enter these arrays or the legacy applied address snapshot. |
| Static routes | EXISTS / NEEDS_EXTENSION | `domain.Route`, `routeArgs` | CIDR/gateway/interface/metric/enabled; no protocol/table attribute. Continue M1 ownership. Add an opt-in typed provenance hook, without changing legacy JSON semantics. |
| Dynamic routes | ABSENT | `domain.Config`, `cmd/ngfw-engine.main` construction | No routing backend configured. Add FRR adapter and explicit FIB reservation protocol. |
| Routing-table/PBR/VRF/ECMP model | ABSENT | `Route`, `routeArgs` | Current commands implicitly target main table and one next hop. Core M5 adds FRR ECMP only; no generic table or VRF migration. |
| Reconciliation route ownership | PARTIAL | `PlanNetwork`, `routeSignatures` | Removal uses previous snapshots; safe for unrelated objects. `route replace` can still collide. VLAN deletion can indirectly destroy external state. Guard both cases. |
| nftables/firewall/NAT | EXISTS | [compiler.go](../../internal/dataplane/compiler.go), `Compile`; [nft.go](../../internal/dataplane/nft.go), `NftRunner`; controller apply | Preserve `inet ngfw`/existing runtime and inspection ownership. Additional local-service guard table is engine-owned and scoped, never a vendor-owned firewall. |
| Session/conntrack/cache | EXISTS | [session_m2.go](../../internal/domain/session_m2.go), `RuntimeSession`; `RuntimeStore`; [mark.go](../../internal/dataplane/mark.go) | Boot/ns/ct-zone identity and NAT aliases already exist. M5 allocates no mark bits and creates no session database. |
| Dynamic-prefix zone attribution | NEEDS_EXTENSION | [program.go](../../internal/connectivity/program.go), `Compile`, `InferAddressZone` | Prefixes come from configured interfaces and static routes, not learned routes. Add explicit configured remote-prefix/zone bindings; do not feed untrusted RIB changes into security policy. |
| M3 correlation | EXISTS | [resolver.go](../../internal/inspection/correlation/resolver.go), `Resolve`; ADR 0003 | Tuple/NAT aliases, sensor epoch, scoped identity/time; ambiguity is not enforcement. No new correlation authority. |
| M4 helper architecture | PARTIAL / existing contract | [cmd/ngfw-proxy/main.go](../../cmd/ngfw-proxy/main.go), `main`; [runtime.go](../../internal/proxy/runtime.go), `RuntimeSupervisor`; [gate_runtime.go](../../internal/engine/gate_runtime.go), `SyncProxy`; [compiler_m4.go](../../internal/dataplane/compiler_m4.go), `CompileM4ProxySelection` | Working tree uses engine IPC runtime descriptors; selector remains mechanism-neutral. Do not reuse stale ADR prototype prose as proof of current code. HAProxy plus enabled M4 is rejected in core M5. |
| Candidate/Running/version lifecycle | EXISTS | [manager.go](../../internal/config/manager.go), `SetCandidateIfValid`, `CommitWithGeneration`, `RollbackWithGeneration` | Save Candidate does not apply; engine validates exact snapshot/version; apply precedes atomic Running publication. Add optional `network_services`, deep cloning and validation. |
| Journal/compensation/restart | EXISTS / NEEDS_EXTENSION | [controller.go](../../internal/dataplane/controller.go), `ApplyRuntimePrepared`, `ApplySnapshotPrepared`, `FinalizeActivation`; [runtime_service.go](../../internal/engine/runtime_service.go), `CommitConfig`, recovery helpers | Retain legacy inner transaction; add outer multi-daemon journal and compose callbacks. No distributed atomicity claim. |
| API authority | EXISTS | [cmd/ngfw-api/main.go](../../cmd/ngfw-api/main.go), `main`; [api.go](../../internal/management/api.go), `candidate`, `commit` | API edits management Candidate and forwards full target through IPC; Running authority is engine. Commit URL is `/api/v1/policies/commit`, not an invented `/config/commit`. |
| IPC extension pattern | EXISTS | [runtime.go](../../internal/engineipc/runtime.go), `RuntimeService`, optional inspection/request-gate interfaces, `dispatch` | Add an optional M5 read interface and capability negotiation; preserve existing protocol behavior. |
| Frontend | PARTIAL | [App.tsx](../../web/src/App.tsx), `saveCandidate`; [runtimeData.ts](../../web/src/runtimeData.ts), `normalizeConfig`; [types.ts](../../web/src/types.ts), `NGFWConfig` | Existing interfaces/routes/NAT/editor. `normalizeConfig` spreads raw config before normalizing known fields; preserve this compatibility property. Add M5 editor/status without losing new fields on legacy edits. |
| External adapters | PARTIAL | `IPCommandRunner`, `NftRunner`, [sensor/control.go](../../internal/inspection/sensor/control.go), requestworker/proxy packages | Small boundaries exist, but no FRR/HAProxy/Keepalived orchestration framework. New bounded tool/service runner belongs only to M5 adapters. |
| Privileges/systemd | EXISTS / NEEDS_EXTENSION | [engine unit](../../deploy/ngfw-engine.service), [API unit](../../deploy/ngfw-api.service) | Engine root:ngfw with NET_ADMIN; API ngfw without network capabilities. Add separate service accounts/runtime groups; do not add API privileges. |
| Secrets | NEEDS_EXTENSION | `Manager.persist` and `Config` | Running is group-readable and explicitly assumes no credentials. Store only opaque versioned references; never BGP keys/private keys in Config. |
| Milestone naming | CONFLICTING | [ADR 0004](../adr/0004-m4-http-tls-request-gate.md), legacy roadmap | Old references reserve M5 for ML/risk. This user request defines M5 networking; ML/risk is FUTURE, no opportunistic rename/refactor of legacy source. |

The M1 acceptance artefacts under `artifacts/m1-*` remain the baseline evidence.
They do not certify M5, M2/M3 packet-path claims, or the uncommitted M4 branch.
The compatibility requirement preserves actual behavior regardless of whether a
legacy matrix has been fully signed off.

## Integration call flow

`API.candidate` -> management `SetCandidateIfValid` -> `API.commit` ->
`RuntimeClient.CommitConfig` -> `RuntimeServiceAdapter.CommitConfig` ->
`BeforeActivate` -> manager `CommitWithGeneration` -> `ApplyGeneration` ->
Running persist -> runtime generation/inspection lifecycle -> `AfterActivate` ->
`FinalizeActivation`. On startup `cmd/ngfw-engine.main` loads Running and
reconciles before exposing engine runtime. M5 composes these existing points.

## Audit checkpoint

FINDINGS: route provenance, local-service admission, explicit dynamic zone prefixes,
secret references and multi-daemon compensation are concrete integration needs.
DECISIONS: preserve ownership; extensions only; source claims above cite symbols.
UNRESOLVED: installed capability measurements at T01.
FILES ALREADY INSPECTED: see source map plus exact file/symbol links above.
SOURCES ALREADY INSPECTED: [source ledger](SOURCE_NOTES.md).
NEXT TARGETS: approved scope/ownership, then precise data and function contracts.
