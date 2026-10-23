# M5 file and function implementation plan

**All additions below are PROPOSED; no implementation is created by this document.**
This is the code-change manifest, not a request to edit all files at once. Tasks
and scope gates in [CODING_TASKS](M5_CODING_TASKS.md) control when a row is touched.
No production file is scheduled for deletion. Optional IPVS rows are excluded
from the core change set. Future VRF/PBR/conntrackd have no core implementation files.

## Normative reading rules

Each file card supplies all required fields. Function IDs refer to the complete
function cards below, whose semantics apply to each signature on that card. A
multi-signature card is used only where related methods share the same contract;
method-specific effects are stated explicitly. Signature aliases refer to types
in [CODE_CONTRACTS](M5_CODE_CONTRACTS.md). Private helpers may be extracted during
coding only within the owning module; update this manifest if they add IO, state,
privilege, ownership or a public contract. Tests named here are PROPOSED unless
explicitly labelled existing in the compatibility matrix.

Defaults for files: NEW files have no existing behavior/functions to modify.
Model/interface/data files have no side effects or callable functions unless an
F/B card is listed. Pure model/config files need no capabilities. Test/fixture
files run unprivileged except explicitly gated VM scripts. External mutations
are restricted to adapter functions and engine coordinator contracts; API/web
never run tools. Existing file changes require the exact justification/rollback
row in [COMPATIBILITY_MATRIX](M5_COMPATIBILITY_MATRIX.md).

The leaf dependency graph is domain -> contracts/resources -> adapters/state ->
engine composition (arrows here mean increasing layer, not Go imports). Concrete
ownership guard can import dataplane; dataplane imports only resources DTOs, never
the guard, FRR, HAProxy or Keepalived. State/WAL may import ActivationSnapshot;
networkservices/contracts.go may not import state or dataplane. No cycles.

## File cards

### P001 — `internal/domain/types.go`

- **FILE / ACTION / CLASS:** `internal/domain/types.go` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Optional Config.NetworkServices root field.
- **DEPENDENCIES:** new domain model. **CURRENT RELEVANT BEHAVIOR:** Config has optional M3/M4, no network-services subtree.
- **NEW TYPES:** Config field only.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** None (types/data/unit template/test only).
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/types_m5_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P002 — `internal/domain/network_services.go`

- **FILE / ACTION / CLASS:** `internal/domain/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: NetworkServicesConfig + strict decode/deep clone/predicate.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** NetworkServicesConfig + strict decode/deep clone/predicate.
- **NEW FUNCTIONS:** F01, F02, F46. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/domain/network_services_test.go`. **ACCEPTANCE CASES:** A01; A00/A01.

### P003 — `internal/domain/routing.go`

- **FILE / ACTION / CLASS:** `internal/domain/routing.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: RoutingConfig, OSPFConfig, OSPFInterface, BGPConfig, BGPNeighbor, BGPAddressFamily, BFDConfig/Profile/Peer, Redistribution.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** RoutingConfig, OSPFConfig, OSPFInterface, BGPConfig, BGPNeighbor, BGPAddressFamily, BFDConfig/Profile/Peer, Redistribution.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/routing_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P004 — `internal/domain/routing_policy.go`

- **FILE / ACTION / CLASS:** `internal/domain/routing_policy.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: RoutePolicy, PrefixList/Entry, RouteMap/Entry.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** RoutePolicy, PrefixList/Entry, RouteMap/Entry.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/routing_policy_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P005 — `internal/domain/wan.go`

- **FILE / ACTION / CLASS:** `internal/domain/wan.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: WANMultiLinkConfig, WANPath, WANHealthCheck.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** WANMultiLinkConfig, WANPath, WANHealthCheck.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/wan_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P006 — `internal/domain/loadbalancer.go`

- **FILE / ACTION / CLASS:** `internal/domain/loadbalancer.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: HAProxyConfig, HAProxyService, HAProxyBackend/Server, ServiceAccess, DeliveryRule, HealthCheck, BackendTLS, timeout DTOs.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** HAProxyConfig, HAProxyService, HAProxyBackend/Server, ServiceAccess, DeliveryRule, HealthCheck, BackendTLS, timeout DTOs.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/loadbalancer_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P007 — `internal/domain/ha.go`

- **FILE / ACTION / CLASS:** `internal/domain/ha.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: VRRPConfig/Group/SyncGroup.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** VRRPConfig/Group/SyncGroup.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/ha_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P008 — `internal/domain/network_services_status.go`

- **FILE / ACTION / CLASS:** `internal/domain/network_services_status.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: All status/query/capability/page DTOs from CODE_CONTRACTS.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** All status/query/capability/page DTOs from CODE_CONTRACTS.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/network_services_status_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P009 — `internal/networkservices/contracts.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/contracts.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: Generation, Prepared, Snapshot, receipts/errors, artifact/clock/observer interfaces.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Generation, Prepared, Snapshot, receipts/errors, artifact/clock/observer interfaces.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/networkservices/contracts_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P010 — `internal/networkservices/resources/types.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/resources/types.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: ResourceOwner, RouteKey/Claim, KernelSnapshot, InterfaceIndex.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** ResourceOwner, RouteKey/Claim, KernelSnapshot, InterfaceIndex.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/networkservices/resources/types_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P011 — `internal/routing/backend.go`

- **FILE / ACTION / CLASS:** `internal/routing/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: RoutingBackend.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** RoutingBackend.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/routing/backend_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P012 — `internal/loadbalancer/backend.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: LoadBalancerBackend.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** LoadBalancerBackend.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/loadbalancer/backend_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P013 — `internal/ha/backend.go`

- **FILE / ACTION / CLASS:** `internal/ha/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: HABackend.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** HABackend.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/ha/backend_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P014 — `internal/wan/backend.go`

- **FILE / ACTION / CLASS:** `internal/wan/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: WANBackend.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** WANBackend.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/wan/backend_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P015 — `internal/domain/ipvs.go`

- **FILE / ACTION / CLASS:** `internal/domain/ipvs.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: OPTIONAL IPVSConfig, VirtualServer, RealServer.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** OPTIONAL IPVSConfig, VirtualServer, RealServer.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/domain/ipvs_test.go`. **ACCEPTANCE CASES:** A30 (optional).

### P016 — `internal/loadbalancer/virtualserver.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/virtualserver.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed contract: OPTIONAL VirtualServerBackend.
- **DEPENDENCIES:** domain/net types only; leaf package rules in CODE_CONTRACTS. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** OPTIONAL VirtualServerBackend.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/loadbalancer/virtualserver_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P017 — `internal/engine/runtime_service.go`

- **FILE / ACTION / CLASS:** `internal/engine/runtime_service.go` / MODIFIED / M2_FILE.
- **PURPOSE:** Optional NetworkServices coordinator reference; methods in new file.
- **DEPENDENCIES:** existing RuntimeServiceAdapter. **CURRENT RELEVANT BEHAVIOR:** Authoritative runtime service with activation callbacks.
- **NEW TYPES:** New optional field only.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** None (types/data/unit template/test only).
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `internal/engine/runtime_service_m5_test.go`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No modification to CommitConfig/RollbackConfig algorithms.

### P018 — `internal/dataplane/linux.go`

- **FILE / ACTION / CLASS:** `internal/dataplane/linux.go` / MODIFIED / M1_FILE.
- **PURPOSE:** Typed route metadata and optional ownership hook.
- **DEPENDENCIES:** resources leaf DTO only; no FRR. **CURRENT RELEVANT BEHAVIOR:** Previous-vs-desired route/address operations, optional reverse plan.
- **NEW TYPES:** NetworkOwnership, RouteMutation; optional r.Ownership.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F18.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/dataplane/linux_m5_test.go`. **ACCEPTANCE CASES:** A04/A05/A23/A28.

### P019 — `internal/config/manager.go`

- **FILE / ACTION / CLASS:** `internal/config/manager.go` / MODIFIED / M1_FILE.
- **PURPOSE:** Delegate M5 validation and clone only.
- **DEPENDENCIES:** domain/config M5 pure functions. **CURRENT RELEVANT BEHAVIOR:** Existing Candidate/Running/persist/version/locks.
- **NEW TYPES:** No new manager authority.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F10.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/config/manager_m5_test.go`. **ACCEPTANCE CASES:** A00/A01/A23/A28.

### P020 — `internal/connectivity/program.go`

- **FILE / ACTION / CLASS:** `internal/connectivity/program.go` / MODIFIED / M2_FILE.
- **PURPOSE:** Append configured remote-prefix zone mapping.
- **DEPENDENCIES:** new pure helper. **CURRENT RELEVANT BEHAVIOR:** Compile sees connected and static prefixes.
- **NEW TYPES:** No session schema change.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F34.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/connectivity/program_m5_test.go`. **ACCEPTANCE CASES:** A02/A10/A28.

### P021 — `internal/engineipc/runtime.go`

- **FILE / ACTION / CLASS:** `internal/engineipc/runtime.go` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Optional v3 dispatch/capability and config-operation timeout.
- **DEPENDENCIES:** new optional service interface. **CURRENT RELEVANT BEHAVIOR:** Existing v3 bounded IPC.
- **NEW TYPES:** Negotiated config budget/cache fields.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F49.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/engineipc/runtime_m5_test.go`. **ACCEPTANCE CASES:** A01/A23/A25.

### P022 — `internal/management/api.go`

- **FILE / ACTION / CLASS:** `internal/management/api.go` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Register read-only handlers; conditional response deadline.
- **DEPENDENCIES:** new status handlers. **CURRENT RELEVANT BEHAVIOR:** Existing HTTP Candidate and commit endpoints.
- **NEW TYPES:** No new privileged client.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F51.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/management/api_m5_test.go`. **ACCEPTANCE CASES:** A25/A27.

### P023 — `cmd/ngfw-engine/main.go`

- **FILE / ACTION / CLASS:** `cmd/ngfw-engine/main.go` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Construction/startup/recovery and callback composition.
- **DEPENDENCIES:** coordinator and current adapters. **CURRENT RELEVANT BEHAVIOR:** Existing prepared apply + M3 lifecycle + uncommitted M4 wiring.
- **NEW TYPES:** No tool syntax.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F53.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `cmd/ngfw-engine/main_m5_test.go`. **ACCEPTANCE CASES:** A05/A23–A28.

### P024 — `web/src/types.ts`

- **FILE / ACTION / CLASS:** `web/src/types.ts` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Optional NGFWConfig.network_services import.
- **DEPENDENCIES:** networkServices/types.ts. **CURRENT RELEVANT BEHAVIOR:** Existing M1–M4 TS models.
- **NEW TYPES:** Optional field only.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** None (types/data/unit template/test only).
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P025 — `web/src/runtimeData.ts`

- **FILE / ACTION / CLASS:** `web/src/runtimeData.ts` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Lossless optional subtree normalization.
- **DEPENDENCIES:** new TS DTOs. **CURRENT RELEVANT BEHAVIOR:** Existing whole-config normalizer.
- **NEW TYPES:** None.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F57.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** A00/A01/A25.

### P026 — `web/src/App.tsx`

- **FILE / ACTION / CLASS:** `web/src/App.tsx` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Wire editor/status using existing Candidate flow.
- **DEPENDENCIES:** new React views. **CURRENT RELEVANT BEHAVIOR:** Existing saveCandidate + routes.
- **NEW TYPES:** View state only.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** F58.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** A01/A25.

### P027 — `web/src/navigation.ts`

- **FILE / ACTION / CLASS:** `web/src/navigation.ts` / MODIFIED / SHARED_CONTRACT.
- **PURPOSE:** Add Network services navigation entry.
- **DEPENDENCIES:** existing navigation types. **CURRENT RELEVANT BEHAVIOR:** Static navigation model.
- **NEW TYPES:** Entry only; no function change.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** None (types/data/unit template/test only).
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P028 — `web/src/networkServices/types.ts`

- **FILE / ACTION / CLASS:** `web/src/networkServices/types.ts` / CREATED / NEW_M5_FILE.
- **PURPOSE:** TS mirror of exact DTOs; disabled/unsupported variants.
- **DEPENDENCIES:** domain schema correspondence. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** NetworkServicesConfig/status/query/page types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.

### P029 — `internal/config/network_services.go`

- **FILE / ACTION / CLASS:** `internal/config/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Dispatch enabled/disabled/schema and all validators; disabled subtree still syntactically valid.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F03, F04, F05, F06, F07, F08, F09. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/config/network_services_test.go`. **ACCEPTANCE CASES:** A01; A01/A02/A06/A09; A01/A07; A10/A13; A14–A17; A18/A19; A01/A04/A17.

### P030 — `internal/netserviceexec/runner.go`

- **FILE / ACTION / CLASS:** `internal/netserviceexec/runner.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Only place executing external adapter commands.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F11. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/netserviceexec/runner_test.go`. **ACCEPTANCE CASES:** A20–A23/A27.

### P031 — `internal/netserviceexec/service.go`

- **FILE / ACTION / CLASS:** `internal/netserviceexec/service.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Central allowlisted process lifecycle/control.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F12. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/netserviceexec/service_test.go`. **ACCEPTANCE CASES:** A03/A20–A27.

### P032 — `internal/netserviceexec/secrets.go`

- **FILE / ACTION / CLASS:** `internal/netserviceexec/secrets.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Resolve immutable name@version, validate purpose and redact.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F13. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/netserviceexec/secrets_test.go`. **ACCEPTANCE CASES:** A16/A27.

### P033 — `internal/networkservices/state/artifacts.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/state/artifacts.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Safe staging/publication/retention.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F14, F62. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/state/artifacts_test.go`. **ACCEPTANCE CASES:** A23/A24/A26/A27; A23/A24/A26.

### P034 — `internal/networkservices/state/journal.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/state/journal.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Durable outer transaction progress.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F15. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/state/journal_test.go`. **ACCEPTANCE CASES:** A23/A24/A27.

### P035 — `internal/networkservices/resources/observer_linux.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/resources/observer_linux.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Observe exact route/address/link/listener provenance without mutation.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F16. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/resources/observer_linux_test.go`. **ACCEPTANCE CASES:** A04/A05/A27.

### P036 — `internal/networkservices/ownership/guard.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/ownership/guard.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Protect route keys and link dependencies; authorize exact old-static adoption.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F17. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/ownership/guard_test.go`. **ACCEPTANCE CASES:** A04/A05/A23.

### P037 — `internal/dataplane/controller_m5.go`

- **FILE / ACTION / CLASS:** `internal/dataplane/controller_m5.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Read exact current config/M2 options/generation/inspection metadata for outer WAL.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F19. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/dataplane/controller_m5_test.go`. **ACCEPTANCE CASES:** A23/A24.

### P038 — `internal/engine/network_services.go`

- **FILE / ACTION / CLASS:** `internal/engine/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Validate dependency graph and create disabled coordinator.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F20, F21, F22, F23, F24, F25, F26. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/engine/network_services_test.go`. **ACCEPTANCE CASES:** A00; A01/A20/A21/A22; A04/A23/A24; A23/A24; A05/A24; A03/A26; A06/A12/A25.

### P039 — `internal/routingpolicy/compile.go`

- **FILE / ACTION / CLASS:** `internal/routingpolicy/compile.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Create typed user policy with mandatory protected/static-prefix intersections.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F27. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routingpolicy/compile_test.go`. **ACCEPTANCE CASES:** A04/A07/A29.

### P040 — `internal/routing/frr/render.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/render.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Build deterministic complete FRR config from typed models.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F28. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/render_test.go`. **ACCEPTANCE CASES:** A02/A04/A06/A09.

### P041 — `internal/routing/frr/ospf.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/ospf.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Interface-specific area/passive/auth/cost/timers/default/filtered redistribution.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F29. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/ospf_test.go`. **ACCEPTANCE CASES:** A02/A03.

### P042 — `internal/routing/frr/bgp.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/bgp.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Single-hop neighbor AF/import/export/network/max-prefix/default/multipath configuration.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F30. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/bgp_test.go`. **ACCEPTANCE CASES:** A06–A08.

### P043 — `internal/routing/frr/bfd.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/bfd.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Profiles, explicit peers and referenced OSPF/BGP BFD integration; echo off.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F31. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/bfd_test.go`. **ACCEPTANCE CASES:** A09.

### P044 — `internal/routing/frr/status.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/status.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Normalize pinned FRR JSON and kernel source provenance.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F32. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/status_test.go`. **ACCEPTANCE CASES:** A02/A06/A09/A27.

### P045 — `internal/connectivity/network_services.go`

- **FILE / ACTION / CLASS:** `internal/connectivity/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Return only configured validated reachable prefixes in declared zone.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F33. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/connectivity/network_services_test.go`. **ACCEPTANCE CASES:** A02/A10/A28.

### P046 — `internal/wan/lease_linux.go`

- **FILE / ACTION / CLASS:** `internal/wan/lease_linux.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Lease only ECMP hash and participating-interface rp_filter.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F35. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/wan/lease_linux_test.go`. **ACCEPTANCE CASES:** A10/A11/A23/A24.

### P047 — `internal/wan/observer.go`

- **FILE / ACTION / CLASS:** `internal/wan/observer.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Merge FRR/BFD/FIB/probe observations into path status; never choose route.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F36. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/wan/observer_test.go`. **ACCEPTANCE CASES:** A10–A13.

### P048 — `internal/wan/health/tcp.go`

- **FILE / ACTION / CLASS:** `internal/wan/health/tcp.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Attempt source+device-bound TCP connect and record monotonic outcome.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F37. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/wan/health/tcp_test.go`. **ACCEPTANCE CASES:** A12/A27.

### P049 — `internal/networkservices/nftguard/render.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/nftguard/render.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Compile scoped local service/protocol admission and LB egress.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F38. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/nftguard/render_test.go`. **ACCEPTANCE CASES:** A17/A29.

### P050 — `internal/networkservices/nftguard/apply.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/nftguard/apply.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Atomic change of only inet ngfw_m5_services.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F39. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/nftguard/apply_test.go`. **ACCEPTANCE CASES:** A17/A23/A27/A29.

### P051 — `internal/loadbalancer/haproxy/render.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/render.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Render bounded TCP/HTTP delivery, algorithms, health checks/TLS/ACL delivery selection.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F40. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/loadbalancer/haproxy/render_test.go`. **ACCEPTANCE CASES:** A14–A17.

### P052 — `internal/loadbalancer/haproxy/status.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/status.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Read and normalize JSON schema/info/stats; distinguish disabled/down/draining.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F41. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/loadbalancer/haproxy/status_test.go`. **ACCEPTANCE CASES:** A14/A15/A19/A27.

### P053 — `internal/ha/keepalived/render.go`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/render.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Render unicast VRRPv3 groups with fixed readiness tracking.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F42. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/ha/keepalived/render_test.go`. **ACCEPTANCE CASES:** A18/A19.

### P054 — `internal/ha/readiness.go`

- **FILE / ACTION / CLASS:** `internal/ha/readiness.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Bounded authenticated local readiness record.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F43. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/ha/readiness_test.go`. **ACCEPTANCE CASES:** A18/A19/A24.

### P055 — `cmd/ngfw-ha-health/main.go`

- **FILE / ACTION / CLASS:** `cmd/ngfw-ha-health/main.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Keepalived fixed unprivileged health script entry point.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F44. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `cmd/ngfw-ha-health/main_test.go`. **ACCEPTANCE CASES:** A19/A27.

### P056 — `internal/ha/keepalived/status.go`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/status.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Combine validated FIFO transitions with fresh JSON v2 role snapshot and kernel VIP presence.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F45. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/ha/keepalived/status_test.go`. **ACCEPTANCE CASES:** A18/A19/A22/A26.

### P057 — `internal/engine/network_services_runtime.go`

- **FILE / ACTION / CLASS:** `internal/engine/network_services_runtime.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Expose engine-owned immutable status/capabilities.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F47. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/engine/network_services_runtime_test.go`. **ACCEPTANCE CASES:** A25/A27.

### P058 — `internal/engineipc/network_services.go`

- **FILE / ACTION / CLASS:** `internal/engineipc/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Optional v3 methods and cached capability negotiation.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F48. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/engineipc/network_services_test.go`. **ACCEPTANCE CASES:** A25/A27.

### P059 — `internal/management/network_services.go`

- **FILE / ACTION / CLASS:** `internal/management/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Authenticated read-only management views.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F50. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/management/network_services_test.go`. **ACCEPTANCE CASES:** A25/A27.

### P060 — `cmd/ngfw-engine/network_services.go`

- **FILE / ACTION / CLASS:** `cmd/ngfw-engine/network_services.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Composition factory: immutable profiles/adapters/callbacks; no external syntax in main.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F52. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `cmd/ngfw-engine/network_services_test.go`. **ACCEPTANCE CASES:** A00/A05.

### P061 — `web/src/networkServices/api.ts`

- **FILE / ACTION / CLASS:** `web/src/networkServices/api.ts` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed bounded GET wrappers.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F54. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** A25.

### P062 — `web/src/networkServices/Editor.tsx`

- **FILE / ACTION / CLASS:** `web/src/networkServices/Editor.tsx` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Typed Candidate editor with routing/OSPF/BGP/BFD, WAN, LB/TLS/backend and HA tabs.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F55. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** A01/A17/A25.

### P063 — `web/src/networkServices/Status.tsx`

- **FILE / ACTION / CLASS:** `web/src/networkServices/Status.tsx` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Display applied/configured/reachable/operational, routes sources and HA/LB/WAN state.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F56. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `Corresponding *.test.ts(x) and A25`. **ACCEPTANCE CASES:** A06/A12/A18/A25.

### P064 — `internal/config/ipvs.go`

- **FILE / ACTION / CLASS:** `internal/config/ipvs.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** OPTIONAL T31 exact NAT virtual-server schema/conflicts.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F59. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/config/ipvs_test.go`. **ACCEPTANCE CASES:** A30/A31.

### P065 — `internal/loadbalancer/ipvs/render.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/render.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** OPTIONAL render checker-only Keepalived virtual servers.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F60. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/loadbalancer/ipvs/render_test.go`. **ACCEPTANCE CASES:** A30.

### P066 — `internal/loadbalancer/ipvs/status_linux.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/status_linux.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** OPTIONAL observe IPVS kernel generic-netlink services/destinations.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F61. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/loadbalancer/ipvs/status_linux_test.go`. **ACCEPTANCE CASES:** A30.

### P067 — `internal/routing/frr/backend.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Validate immutable dependencies/profile; no IO.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** B1New, B1Prepare, B1Snapshot, B1Apply, B1Verify, B1Restore, B1Status. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/backend_test.go`. **ACCEPTANCE CASES:** A02–A09/A20/A23–A27.

### P068 — `internal/loadbalancer/haproxy/backend.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Validate immutable dependencies/profile; no IO.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** B2New, B2Prepare, B2Snapshot, B2Apply, B2Verify, B2Restore, B2Status. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/loadbalancer/haproxy/backend_test.go`. **ACCEPTANCE CASES:** A14–A17/A21/A23–A27.

### P069 — `internal/ha/keepalived/backend.go`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Validate immutable dependencies/profile; no IO.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** B3New, B3Prepare, B3Snapshot, B3Apply, B3Verify, B3Restore, B3Status. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/ha/keepalived/backend_test.go`. **ACCEPTANCE CASES:** A18/A19/A22–A27.

### P070 — `internal/loadbalancer/ipvs/backend.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/backend.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Validate immutable dependencies/profile; no IO.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** B4New, B4Prepare, B4Snapshot, B4Apply, B4Verify, B4Restore, B4Status. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/loadbalancer/ipvs/backend_test.go`. **ACCEPTANCE CASES:** A30.

### P071 — `internal/routing/frr/reservation.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/reservation.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Publish union(old,target) exact-prefix ownership filter and confirm dynamic withdrawal before M1 route mutation.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** B1Reserve. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/routing/frr/reservation_test.go`. **ACCEPTANCE CASES:** A04/A05/A07/A23/A24.

### P072 — `internal/networkservices/capabilities/probe.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/capabilities/probe.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Verify installed immutable tools/schema/paths and build a cached capability report before feature enablement.
- **DEPENDENCIES:** Function contracts below; no unlisted vendor dependencies. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Concrete implementation types from linked function cards.
- **NEW FUNCTIONS:** F63. **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Exact function-card called-by/calls entries below.
- **ERRORS / CONCURRENCY / PRIVILEGE:** Exact function-card error, locking and side-effect contracts below; packaging privilege profile is normative.
- **TEST FILE:** `internal/networkservices/capabilities/probe_test.go`. **ACCEPTANCE CASES:** A00/A20/A27.

### P073 — `deploy/ngfw-engine.service`

- **FILE / ACTION / CLASS:** `deploy/ngfw-engine.service` / EXISTING REFERENCE, UNCHANGED / SHARED_CONTRACT.
- **PURPOSE:** Scoped M5 filesystem access; retain root:ngfw NET_ADMIN-only bounds.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** See function cards for additions; otherwise none. **MODIFIED FUNCTIONS:** None (types/data/unit template/test only).
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P074 — `deploy/network-services/frr.service.d/ngfw.conf`

- **FILE / ACTION / CLASS:** `deploy/network-services/frr.service.d/ngfw.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Pinned vendor FRR sandbox/drop-in; no second instance.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P075 — `deploy/network-services/frr-daemons.conf`

- **FILE / ACTION / CLASS:** `deploy/network-services/frr-daemons.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Installer process profile; staticd disabled.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P076 — `deploy/network-services/ngfw-haproxy.service`

- **FILE / ACTION / CLASS:** `deploy/network-services/ngfw-haproxy.service` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Unprivileged master-worker foreground/reload/restart.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P077 — `deploy/network-services/ngfw-keepalived.service`

- **FILE / ACTION / CLASS:** `deploy/network-services/ngfw-keepalived.service` / CREATED / NEW_M5_FILE.
- **PURPOSE:** VRRP-only bounded capability unit; unprivileged readiness helper.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P078 — `deploy/network-services/ngfw-ipvs.service`

- **FILE / ACTION / CLASS:** `deploy/network-services/ngfw-ipvs.service` / CREATED / NEW_M5_FILE.
- **PURPOSE:** OPTIONAL separate checker-only instance.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P079 — `deploy/network-services/tmpfiles.conf`

- **FILE / ACTION / CLASS:** `deploy/network-services/tmpfiles.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Create users' runtime paths/FIFO/dump/readiness parent with correct permissions.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P080 — `deploy/network-services/profile.example.json`

- **FILE / ACTION / CLASS:** `deploy/network-services/profile.example.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Version family/tool ID/unit/path/hash/schema capability profile; no secrets.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P081 — `scripts/install-m5-linux.sh`

- **FILE / ACTION / CLASS:** `scripts/install-m5-linux.sh` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Preflight collisions/package identity, install manifests/units; default disabled; no auto enable.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P082 — `scripts/verify-m5-linux.sh`

- **FILE / ACTION / CLASS:** `scripts/verify-m5-linux.sh` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Bounded read-only package/sandbox/profile proof and disabled preflight.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `A00/A27 packaging or integration script checks`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P083 — `tests/integration/m5/README.md`

- **FILE / ACTION / CLASS:** `tests/integration/m5/README.md` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Executable topology/setup/evidence/cleanup runbook matching Axx.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P084 — `tests/integration/m5/lab.sh`

- **FILE / ACTION / CLASS:** `tests/integration/m5/lab.sh` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Explicit baseline save/apply case overlays/restore by expected version; refusal outside disposable lab.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P085 — `tests/integration/m5/run-case.sh`

- **FILE / ACTION / CLASS:** `tests/integration/m5/run-case.sh` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Axx orchestration with phase exitcodes and scoped cleanup traps.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P086 — `tests/integration/m5/collect.sh`

- **FILE / ACTION / CLASS:** `tests/integration/m5/collect.sh` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Timestamped bounded commands/caps/route/status/pcap evidence; exclude secrets.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P087 — `tests/integration/m5/traffic.py`

- **FILE / ACTION / CLASS:** `tests/integration/m5/traffic.py` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Deterministic backend IDs, health toggle, HTTP/TCP hold, multi-flow client; no external deps.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P088 — `tests/integration/m5/fault-runner.sh`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fault-runner.sh` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Lab-only argv-compatible exact one-shot tool failure wrapper; not installed in production.
- **DEPENDENCIES:** Packaging and acceptance contracts; bash/python standard library only. **CURRENT RELEVANT BEHAVIOR:** Absent except engine unit.
- **NEW TYPES:** No production Go types.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Scripts have named actions defined in ACCEPTANCE_MATRIX; do not run during planning.

### P089 — `tests/integration/m5/fixtures/ospf.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ospf.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ospf sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P090 — `tests/integration/m5/fixtures/ospf-off.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ospf-off.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ospf-off sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P091 — `tests/integration/m5/fixtures/bgp.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/bgp.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** bgp sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P092 — `tests/integration/m5/fixtures/bgp-policy.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/bgp-policy.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** bgp-policy sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P093 — `tests/integration/m5/fixtures/bgp-max-prefix.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/bgp-max-prefix.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** bgp-max-prefix sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P094 — `tests/integration/m5/fixtures/bfd.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/bfd.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** bfd sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P095 — `tests/integration/m5/fixtures/ecmp.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ecmp.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ecmp sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P096 — `tests/integration/m5/fixtures/failover.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/failover.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** failover sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P097 — `tests/integration/m5/fixtures/wan-probe.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/wan-probe.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** wan-probe sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P098 — `tests/integration/m5/fixtures/haproxy-tcp.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/haproxy-tcp.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** haproxy-tcp sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P099 — `tests/integration/m5/fixtures/haproxy-http.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/haproxy-http.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** haproxy-http sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P100 — `tests/integration/m5/fixtures/haproxy-tls.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/haproxy-tls.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** haproxy-tls sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P101 — `tests/integration/m5/fixtures/ha-g1.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ha-g1.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ha-g1 sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P102 — `tests/integration/m5/fixtures/ha-g2.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ha-g2.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ha-g2 sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P103 — `tests/integration/m5/fixtures/ha-preempt.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ha-preempt.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ha-preempt sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P104 — `tests/integration/m5/fixtures/combined.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/combined.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** combined sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P105 — `tests/integration/m5/fixtures/invalid-m5.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/invalid-m5.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** invalid-m5 sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P106 — `tests/integration/m5/fixtures/ipvs.json`

- **FILE / ACTION / CLASS:** `tests/integration/m5/fixtures/ipvs.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** ipvs sparse Candidate overlay with IDs/IPs in acceptance recipe.
- **DEPENDENCIES:** lab.sh merges only specified keys into saved baseline; not a standalone unsafe config. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** JSON domain config only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** No private key/auth material; optional ipvs fixture gated T31.

### P107 — `tests/integration/m5/peers/r1.conf`

- **FILE / ACTION / CLASS:** `tests/integration/m5/peers/r1.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** FRR lab peer setup for exact routed topology/return routes.
- **DEPENDENCIES:** Pinned FRR profile and lab addresses. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Vendor config on peer only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Not installed on SENTINEL.

### P108 — `tests/integration/m5/peers/r2.conf`

- **FILE / ACTION / CLASS:** `tests/integration/m5/peers/r2.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** FRR lab peer setup for exact routed topology/return routes.
- **DEPENDENCIES:** Pinned FRR profile and lab addresses. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Vendor config on peer only.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Not installed on SENTINEL.

### P109 — `internal/domain/network_services_test.go`

- **FILE / ACTION / CLASS:** `internal/domain/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/domain/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P110 — `internal/config/network_services_test.go`

- **FILE / ACTION / CLASS:** `internal/config/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/config/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P111 — `internal/config/manager_m5_test.go`

- **FILE / ACTION / CLASS:** `internal/config/manager_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/config/manager.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P112 — `internal/netserviceexec/runner_test.go`

- **FILE / ACTION / CLASS:** `internal/netserviceexec/runner_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/netserviceexec/runner.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P113 — `internal/netserviceexec/service_test.go`

- **FILE / ACTION / CLASS:** `internal/netserviceexec/service_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/netserviceexec/service.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P114 — `internal/netserviceexec/secrets_test.go`

- **FILE / ACTION / CLASS:** `internal/netserviceexec/secrets_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/netserviceexec/secrets.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P115 — `internal/networkservices/state/artifacts_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/state/artifacts_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/state/artifacts.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P116 — `internal/networkservices/state/journal_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/state/journal_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/state/journal.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P117 — `internal/networkservices/resources/observer_linux_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/resources/observer_linux_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/resources/observer_linux.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P118 — `internal/networkservices/ownership/guard_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/ownership/guard_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/ownership/guard.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P119 — `internal/dataplane/linux_m5_test.go`

- **FILE / ACTION / CLASS:** `internal/dataplane/linux_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/dataplane/linux.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P120 — `internal/dataplane/controller_m5_test.go`

- **FILE / ACTION / CLASS:** `internal/dataplane/controller_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/dataplane/controller_m5.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P121 — `internal/engine/network_services_test.go`

- **FILE / ACTION / CLASS:** `internal/engine/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/engine/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P122 — `internal/routingpolicy/compile_test.go`

- **FILE / ACTION / CLASS:** `internal/routingpolicy/compile_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routingpolicy/compile.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P123 — `internal/routing/frr/render_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/render_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/render.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P124 — `internal/routing/frr/ospf_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/ospf_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/ospf.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P125 — `internal/routing/frr/bgp_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/bgp_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/bgp.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P126 — `internal/routing/frr/bfd_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/bfd_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/bfd.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P127 — `internal/routing/frr/status_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/status_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/status.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P128 — `internal/connectivity/network_services_test.go`

- **FILE / ACTION / CLASS:** `internal/connectivity/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/connectivity/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P129 — `internal/connectivity/program_m5_test.go`

- **FILE / ACTION / CLASS:** `internal/connectivity/program_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/connectivity/program.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P130 — `internal/wan/lease_linux_test.go`

- **FILE / ACTION / CLASS:** `internal/wan/lease_linux_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/wan/lease_linux.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P131 — `internal/wan/observer_test.go`

- **FILE / ACTION / CLASS:** `internal/wan/observer_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/wan/observer.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P132 — `internal/wan/health/tcp_test.go`

- **FILE / ACTION / CLASS:** `internal/wan/health/tcp_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/wan/health/tcp.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P133 — `internal/networkservices/nftguard/render_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/nftguard/render_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/nftguard/render.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P134 — `internal/networkservices/nftguard/apply_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/nftguard/apply_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/nftguard/apply.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P135 — `internal/loadbalancer/haproxy/render_test.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/render_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/loadbalancer/haproxy/render.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P136 — `internal/loadbalancer/haproxy/status_test.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/status_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/loadbalancer/haproxy/status.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P137 — `internal/ha/keepalived/render_test.go`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/render_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/ha/keepalived/render.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P138 — `internal/ha/readiness_test.go`

- **FILE / ACTION / CLASS:** `internal/ha/readiness_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/ha/readiness.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P139 — `cmd/ngfw-ha-health/main_test.go`

- **FILE / ACTION / CLASS:** `cmd/ngfw-ha-health/main_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for cmd/ngfw-ha-health/main.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P140 — `internal/ha/keepalived/status_test.go`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/status_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/ha/keepalived/status.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P141 — `internal/engine/network_services_runtime_test.go`

- **FILE / ACTION / CLASS:** `internal/engine/network_services_runtime_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/engine/network_services_runtime.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P142 — `internal/engineipc/network_services_test.go`

- **FILE / ACTION / CLASS:** `internal/engineipc/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/engineipc/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P143 — `internal/engineipc/runtime_m5_test.go`

- **FILE / ACTION / CLASS:** `internal/engineipc/runtime_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/engineipc/runtime.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P144 — `internal/management/network_services_test.go`

- **FILE / ACTION / CLASS:** `internal/management/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/management/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P145 — `internal/management/api_m5_test.go`

- **FILE / ACTION / CLASS:** `internal/management/api_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/management/api.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P146 — `cmd/ngfw-engine/network_services_test.go`

- **FILE / ACTION / CLASS:** `cmd/ngfw-engine/network_services_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for cmd/ngfw-engine/network_services.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P147 — `cmd/ngfw-engine/main_m5_test.go`

- **FILE / ACTION / CLASS:** `cmd/ngfw-engine/main_m5_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for cmd/ngfw-engine/main.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P148 — `web/src/networkServices/api.test.ts`

- **FILE / ACTION / CLASS:** `web/src/networkServices/api.test.ts` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for web/src/networkServices/api.ts.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P149 — `web/src/networkServices/Editor.test.tsx`

- **FILE / ACTION / CLASS:** `web/src/networkServices/Editor.test.tsx` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for web/src/networkServices/Editor.tsx.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P150 — `web/src/networkServices/Status.test.tsx`

- **FILE / ACTION / CLASS:** `web/src/networkServices/Status.test.tsx` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for web/src/networkServices/Status.tsx.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P151 — `web/src/runtimeData.test.ts`

- **FILE / ACTION / CLASS:** `web/src/runtimeData.test.ts` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for web/src/runtimeData.ts.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P152 — `web/src/App.test.tsx`

- **FILE / ACTION / CLASS:** `web/src/App.test.tsx` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for web/src/App.tsx.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P153 — `internal/config/ipvs_test.go`

- **FILE / ACTION / CLASS:** `internal/config/ipvs_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/config/ipvs.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P154 — `internal/loadbalancer/ipvs/render_test.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/render_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/loadbalancer/ipvs/render.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P155 — `internal/loadbalancer/ipvs/status_linux_test.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/status_linux_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/loadbalancer/ipvs/status_linux.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P156 — `internal/routing/frr/backend_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/backend_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/backend.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P157 — `internal/loadbalancer/haproxy/backend_test.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/backend_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/loadbalancer/haproxy/backend.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P158 — `internal/ha/keepalived/backend_test.go`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/backend_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/ha/keepalived/backend.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P159 — `internal/loadbalancer/ipvs/backend_test.go`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/backend_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/loadbalancer/ipvs/backend.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P160 — `internal/routing/frr/reservation_test.go`

- **FILE / ACTION / CLASS:** `internal/routing/frr/reservation_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/routing/frr/reservation.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P161 — `internal/networkservices/capabilities/probe_test.go`

- **FILE / ACTION / CLASS:** `internal/networkservices/capabilities/probe_test.go` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Tests for internal/networkservices/capabilities/probe.go.
- **DEPENDENCIES:** Fake Runner/ServiceManager/clock + no-secret pinned fixtures. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** Test-only fakes; no new production behavior.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Use function UNIT TESTS below; run directly affected legacy tests unchanged too.

### P162 — `internal/routing/frr/testdata/status.json`

- **FILE / ACTION / CLASS:** `internal/routing/frr/testdata/status.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P163 — `internal/routing/frr/testdata/expected.conf`

- **FILE / ACTION / CLASS:** `internal/routing/frr/testdata/expected.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P164 — `internal/loadbalancer/haproxy/testdata/stats.json`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/testdata/stats.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P165 — `internal/loadbalancer/haproxy/testdata/schema.json`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/testdata/schema.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P166 — `internal/loadbalancer/haproxy/testdata/expected.cfg`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/haproxy/testdata/expected.cfg` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P167 — `internal/ha/keepalived/testdata/state-v2.json`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/testdata/state-v2.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P168 — `internal/ha/keepalived/testdata/events.txt`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/testdata/events.txt` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P169 — `internal/ha/keepalived/testdata/expected.conf`

- **FILE / ACTION / CLASS:** `internal/ha/keepalived/testdata/expected.conf` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** Owning task Axx mapping in CODING_TASKS; types A00/A01, packaging A00/A27, harness A02–A30.
- **BOUNDARY:** Optional IPVS fixture only T32.

### P170 — `internal/loadbalancer/ipvs/testdata/netlink.json`

- **FILE / ACTION / CLASS:** `internal/loadbalancer/ipvs/testdata/netlink.json` / CREATED / NEW_M5_FILE.
- **PURPOSE:** Sanitized pinned structured/raw fixture and expected renderer output.
- **DEPENDENCIES:** T01 profile; record package/source version in fixture header/adjacent test metadata. **CURRENT RELEVANT BEHAVIOR:** Absent.
- **NEW TYPES:** No secrets/live production addresses.
- **NEW FUNCTIONS:** None (types/data/unit template/test only). **MODIFIED FUNCTIONS:** None.
- **CALLERS / CALLEES:** Importer/consumer in the owning task; declarations/data do not invoke runtime functions.
- **ERRORS / CONCURRENCY / PRIVILEGE:** No new exception or lock behavior; tests bounded; deployment scripts root only when executing a documented install/lab action.
- **TEST FILE:** `This file / referenced owning test`. **ACCEPTANCE CASES:** A30 (optional).
- **BOUNDARY:** Optional IPVS fixture only T32.

## Additional platform and packaging files

These complete the manifest; they carry existing F-card signatures, not new
public behavior. **No broad platform refactor is authorized.**

| FILE / ACTION / CLASS | PURPOSE / CURRENT BEHAVIOR | TYPES / FUNCTIONS | DEPENDENCIES / CALLERS / CALLEES | ERRORS / CONCURRENCY / PRIVILEGE | TEST FILE / ACCEPTANCE |
|---|---|---|---|---|---|
| `deploy/network-services/ngfw-engine.service.d/network-services.conf` / CREATED / NEW_M5_FILE | M5-only filesystem and supplementary-group access; absent currently. This is the actual change; leave base `deploy/ngfw-engine.service` unchanged | No functions; unit directives | Installer T25; existing base unit | Fail install if groups/paths missing; no capability increase; admin installer writes | Installer dry-run and A00/A27/A32 |
| `internal/networkservices/resources/observer_unsupported.go` / CREATED / NEW_M5_FILE | Non-Linux implementation of F16; absent | Same observer method signature; common portable types stay in types.go | F16 callers; no netlink import | CAPABILITY_UNSUPPORTED; no IO/goroutine/caps | observer_test.go cross-platform + A00 |
| `internal/wan/lease_unsupported.go` / CREATED / NEW_M5_FILE | Non-Linux counterpart of F35 | Same methods/common portable lease receipt | Coordinator; no /proc writes | CAPABILITY_UNSUPPORTED when explicitly requested; nil disabled bypasses | lease_linux_test.go on Linux; portable disabled test + A00 |
| `internal/wan/health/tcp_unsupported.go` / CREATED / NEW_M5_FILE | Non-Linux counterpart of F37; tcp.go implementation has linux build tag | Same ProbeTCP signature | WAN observer; no raw/socket option fallback | UNKNOWN/CAPABILITY_UNSUPPORTED, no sockets | tcp_test.go build-tagged Linux; disabled portable test + A00 |
| `internal/loadbalancer/ipvs/status_unsupported.go` / CREATED / NEW_M5_FILE, OPTIONAL | Non-Linux counterpart of F61 | Same Snapshot signature | Optional backend; no IPVS library import | Unsupported without mutation | Optional netlink fixtures on Linux; A30 |
| `internal/netserviceexec/process_linux.go` / CREATED / NEW_M5_FILE | Linux child process group/cancel part of F11 | `configureChild(cmd *exec.Cmd) error`, `terminateChild(cmd *exec.Cmd) error` | ExecRunner.Run; syscall process group/kill | Validate started PID/group, no PID reuse kill; context-bound; only its own child | runner_test.go hung descendant, A27 |
| `internal/netserviceexec/process_unsupported.go` / CREATED / NEW_M5_FILE | Other-platform counterparts for F11 subprocess methods | Same signatures | Runner; stdlib process cancel only for unprivileged synthetic tests | Live networking profile unsupported; no pretending Linux behavior | Runner pure/fake tests and Linux cross-build |
| `go.mod`, `go.sum` / CONDITIONALLY MODIFIED / SHARED_CONTRACT | Reuse current pinned libraries; promote already indirect x/sys only if direct socket/boottime import requires it | No functions | F37/F43 platform calls; T16/T20 | No protocol implementation library; no unexplained upgrades | go mod tidy diff review, selected tests and Linux cross-build |

For the two process helper functions: INPUT is the owned exec.Cmd; OUTPUT is error;
PRECONDITION is an allowlisted Runner invocation; VALIDATION is started PID/process
group identity; SIDE EFFECT is child setup/termination only; ERROR CONDITIONS are
start/kill/cancellation failures; CALLED BY is F11, CALLS are the platform process
API; ROLLBACK is reap the same child (never unrelated processes); TIMEOUT inherits
F11 and CONCURRENCY is per-invocation ownership with no global PID mutable state.
Their unit/integration evidence is TestRunnerKillsChildren/A27. No API process
can use these helpers to execute networking tools.

The base engine-unit reference defines existing restrictions; install only the
new M5 drop-in above and leave the base unit unchanged.
Constructors/wiring common types must compile on the current Windows development
host; live networking adapters return unsupported there. Linux-specific tests
use build tags, while pure render/model/transaction fake tests remain portable.
Test-only packet generation uses python3-scapy on the disposable sender VM;
it is not a production Go/appliance dependency.

## Function cards

Privileges follow the file's adapter role in DEPENDENCY_AND_PACKAGING. Pure functions
have none; Runner/ServiceManager/ownership mutations run in the engine NET_ADMIN
profile; external processes keep their own service capabilities. No function can
persist Running except the existing config manager. Context-less functions are
pure/bounded memory operations or existing framework entry points.

### F01 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesConfig) UnmarshalJSON(data []byte) error`.
- **FILE:** `internal/domain/network_services.go`.
- **RESPONSIBILITY:** Strictly decode the M5 subtree only.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Unknown M5 fields, enum values and duplicate JSON keys rejected; preserve legacy decoder outside subtree.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** json decoder.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestNetworkServicesStrictDecode. **INTEGRATION TESTS:** A01 in M5_ACCEPTANCE_MATRIX.

### F02 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func CloneNetworkServices(v *NetworkServicesConfig) *NetworkServicesConfig`.
- **FILE:** `internal/domain/network_services.go`.
- **RESPONSIBILITY:** Deep copy optional model, nested pointers and every slice/map.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Nil remains nil; preserve nil vs explicit values; do not insert defaults during read/clone.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** config.cloneConfig.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestNetworkServicesCloneIsolation. **INTEGRATION TESTS:** A00/A01 in M5_ACCEPTANCE_MATRIX.

### F03 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateNetworkServices(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** Dispatch enabled/disabled/schema and all validators; disabled subtree still syntactically valid.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateNetworkServices. **INTEGRATION TESTS:** A01 in M5_ACCEPTANCE_MATRIX.

### F04 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateRouting(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** OSPF/BGP/BFD fields, families, interface/up-state/references/ordinary source IP; limit neighbors and paths.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateRouting. **INTEGRATION TESTS:** A01/A02/A06/A09 in M5_ACCEPTANCE_MATRIX.

### F05 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateRoutePolicy(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** Prefix list/map IDs/sequences; exact family/length; restrict setter context; guarded redistribution.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateRoutePolicy. **INTEGRATION TESTS:** A01/A07 in M5_ACCEPTANCE_MATRIX.

### F06 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateWAN(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** FRR mode, two compatible neighbors/paths, same zone, no overlapping NAT/weights/PBR, bounded probes.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateWAN. **INTEGRATION TESTS:** A10/A13 in M5_ACCEPTANCE_MATRIX.

### F07 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateLoadBalancer(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** Listener/mode/TLS/routing/secret refs/backends/access/M4 exclusion; no wildcard or MGMT/VIP.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateLoadBalancer. **INTEGRATION TESTS:** A14–A17 in M5_ACCEPTANCE_MATRIX.

### F08 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateHA(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** VRID/interface/VIPs/peers/sync groups/dependency refs; no ordinary/VIP overlap.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateHA. **INTEGRATION TESTS:** A18/A19 in M5_ACCEPTANCE_MATRIX.

### F09 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateResourceConflicts(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/network_services.go`.
- **RESPONSIBILITY:** Cross-feature ports, VIP/link dependencies, route/protocol/table reservations, M4 conflicts in both directions.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** All exact field and cross-field constraints in CODE_CONTRACTS; no installed-secret/tool checks.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Validator.Validate / parent validator.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestValidateResourceConflicts. **INTEGRATION TESTS:** A01/A04/A17 in M5_ACCEPTANCE_MATRIX.

### F10 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `func (Validator) Validate(c domain.Config) []string; func cloneConfig(value domain.Config) domain.Config`.
- **FILE:** `internal/config/manager.go`.
- **RESPONSIBILITY:** Append formatted M5 issues and deep clone optional subtree.
- **INPUT:** Existing Config. **OUTPUT:** Existing output types.
- **PRECONDITIONS:** Keep legacy checks/order/error strings.
- **VALIDATION:** F03; legacy validation unchanged.
- **SIDE EFFECTS:** None added.
- **ERROR CONDITIONS:** Existing errors plus formatted M5 issues.
- **CALLS:** F02/F03. **CALLED BY:** Manager Candidate/commit/rollback.
- **ROLLBACK BEHAVIOR:** Existing manager owns all recovery.
- **TIMEOUT/CANCELLATION:** Existing bounds.
- **CONCURRENCY NOTES:** Preserve current manager mutex behavior.
- **UNIT TESTS:** Existing config tests + TestLegacyConfigRoundTripM5. **INTEGRATION TESTS:** A00/A01/A23/A28 in M5_ACCEPTANCE_MATRIX.

### F11 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (r *ExecRunner) Run(ctx context.Context, cmd Command) (Result, error)`.
- **FILE:** `internal/netserviceexec/runner.go`.
- **RESPONSIBILITY:** Only place executing external adapter commands.
- **INPUT:** Allowlisted ToolID + typed argv/stdin, installed immutable profile. **OUTPUT:** Bounded Result / AdapterError.
- **PRECONDITIONS:** Executable/hash/profile verified; no Candidate-supplied executable.
- **VALIDATION:** Args NUL/newline/size rules; absolute profile executable; reject shell tool.
- **SIDE EFFECTS:** Exec one child process group; bounded buffers.
- **ERROR CONDITIONS:** Unavailable, exit, timeout, truncated output, cancellation.
- **CALLS:** exec.CommandContext; kill child process group on deadline; drain bounded output. **CALLED BY:** All adapters.
- **ROLLBACK BEHAVIOR:** Do not undo caller effects; report phase accurately.
- **TIMEOUT/CANCELLATION:** Profile deadline intersect ctx; terminate/reap children.
- **CONCURRENCY NOTES:** Per-call; global semaphore max8; no global mutable argv.
- **UNIT TESTS:** TestRunnerRejectsTool; TestRunnerKillsChildren; TestRunnerRedactsSecrets. **INTEGRATION TESTS:** A20–A23/A27 in M5_ACCEPTANCE_MATRIX.

### F12 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (s *SystemdManager) Inspect(ctx context.Context, id ServiceID) (ServiceState,error); func (s *SystemdManager) Ensure(ctx context.Context, id ServiceID, action ServiceAction) error`.
- **FILE:** `internal/netserviceexec/service.go`.
- **RESPONSIBILITY:** Central allowlisted process lifecycle/control.
- **INPUT:** Fixed service enum/actions START,STOP,RELOAD,JSON_SNAPSHOT. **OUTPUT:** Machine-readable service properties / error.
- **PRECONDITIONS:** Root engine local manager; profile names fixed.
- **VALIDATION:** Reject unlisted unit/action; verify PID/start stamp before status signal.
- **SIDE EFFECTS:** Ensure changes only selected unit; Inspect read-only.
- **ERROR CONDITIONS:** Tool unavailable, timeout, unit failed, PID changed.
- **CALLS:** Runner with fixed systemctl show/start/stop/reload/kill argv. **CALLED BY:** Adapters.
- **ROLLBACK BEHAVIOR:** Caller Restore chooses previous desired service; no restart-all.
- **TIMEOUT/CANCELLATION:** 5s inspect, action profile bounds.
- **CONCURRENCY NOTES:** Serialize lifecycle per unit; never call Config.
- **UNIT TESTS:** TestServiceAllowlist; TestSignalPIDRace. **INTEGRATION TESTS:** A03/A20–A27 in M5_ACCEPTANCE_MATRIX.

### F13 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (s *FileSecretResolver) Resolve(ctx context.Context, ref string, purpose SecretPurpose) (SecretMaterial,error)`.
- **FILE:** `internal/netserviceexec/secrets.go`.
- **RESPONSIBILITY:** Resolve immutable name@version, validate purpose and redact.
- **INPUT:** Opaque reference; enum BGP_AUTH/OSPF_AUTH/LB_CERT/LB_CA. **OUTPUT:** Private bounded bytes / parsed metadata; never returned over IPC.
- **PRECONDITIONS:** Local admin provisioned file.
- **VALIDATION:** No traversal/symlinks; owner/mode/type/size; X509 expiry/key match or auth length.
- **SIDE EFFECTS:** Read protected file only.
- **ERROR CONDITIONS:** Missing, wrong purpose/permission/invalid certificate.
- **CALLS:** os open/stat; crypto/x509; no external openssl. **CALLED BY:** Adapter.Prepare.
- **ROLLBACK BEHAVIOR:** No change; release references/zero owned buffers best-effort.
- **TIMEOUT/CANCELLATION:** ctx checks; max1MiB per cert bundle.
- **CONCURRENCY NOTES:** No shared plaintext cache.
- **UNIT TESTS:** TestSecretRefTraversal; TestCertificateKeyMatch; TestSecretNeverInError. **INTEGRATION TESTS:** A16/A27 in M5_ACCEPTANCE_MATRIX.

### F14 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (s *ArtifactStore) Stage(ctx context.Context, subsystem string, generation Generation, files []ArtifactFile) (Prepared,error); func (s *ArtifactStore) Publish(ctx context.Context, p Prepared) error; func (s *ArtifactStore) Prune(ctx context.Context) error`.
- **FILE:** `internal/networkservices/state/artifacts.go`.
- **RESPONSIBILITY:** Safe staging/publication/retention.
- **INPUT:** Bounded generated bytes, opaque subsystem enum, generation. **OUTPUT:** Hashed refs / error.
- **PRECONDITIONS:** Root-managed directories; caller owns activation.
- **VALIDATION:** Digest/path/permission/space/retention and no symlink escape.
- **SIDE EFFECTS:** Stage disk-only; Publish active references; Prune only unreferenced old generations.
- **ERROR CONDITIONS:** Disk full, fsync/rename/permission/hash mismatch.
- **CALLS:** fsync+rename file operations; manifest snapshot. **CALLED BY:** Adapter.Prepare/Apply; coordinator idle cleanup.
- **ROLLBACK BEHAVIOR:** Publish old Snapshot reference; retain WAL artifacts on failure.
- **TIMEOUT/CANCELLATION:** 5s disk step, ctx before rename; post-rename report actual phase.
- **CONCURRENCY NOTES:** Serial store writer; readers immutable refs.
- **UNIT TESTS:** TestArtifactAtomicPublish; TestPruneKeepsJournalReferences. **INTEGRATION TESTS:** A23/A24/A26/A27 in M5_ACCEPTANCE_MATRIX.

### F15 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (j *Journal) Load() (ActivationRecord,bool,error); func (j *Journal) Save(ctx context.Context, r ActivationRecord) error; func (j *Journal) Remove(ctx context.Context, expectedDigest string) error`.
- **FILE:** `internal/networkservices/state/journal.go`.
- **RESPONSIBILITY:** Durable outer transaction progress.
- **INPUT:** Exact old/target snapshots, claims, receipts, leases, phase. **OUTPUT:** Validated record / presence / error.
- **PRECONDITIONS:** Private directory; includes no raw secret material.
- **VALIDATION:** Schema/hash/monotonic phase/generation; reject corruption; remove only matching digest.
- **SIDE EFFECTS:** Atomic WAL file writes/removal.
- **ERROR CONDITIONS:** Corrupt, missing referenced artifact, disk/permission/fsync.
- **CALLS:** Artifact-style atomic IO. **CALLED BY:** Coordinator Apply/Finalize/Recover.
- **ROLLBACK BEHAVIOR:** Never discard recovery-required WAL; previous record retained on failed write.
- **TIMEOUT/CANCELLATION:** 5s step; critical fsync completes before return.
- **CONCURRENCY NOTES:** M5 method mutex; process single writer.
- **UNIT TESTS:** TestJournalCrashBoundaries; TestCorruptJournalStopsMutation. **INTEGRATION TESTS:** A23/A24/A27 in M5_ACCEPTANCE_MATRIX.

### F16 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (o *NetlinkObserver) Snapshot(ctx context.Context) (KernelSnapshot,error)`.
- **FILE:** `internal/networkservices/resources/observer_linux.go`.
- **RESPONSIBILITY:** Observe exact route/address/link/listener provenance without mutation.
- **INPUT:** Default netns only; bounded scopes. **OUTPUT:** Detached typed snapshot including family/table/protocol/priority/nexthops/ifindex.
- **PRECONDITIONS:** Profile NETLINK support.
- **VALIDATION:** Discard incomplete dump; attach observed time; unknown proto is FOREIGN.
- **SIDE EFFECTS:** Read netlink/proc listener data.
- **ERROR CONDITIONS:** Interrupted dump, overflow, timeout.
- **CALLS:** Pinned netlink library; fixed namespace. **CALLED BY:** Guard, adapter verification/status.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** 3s snapshot, retry interrupted dump once within ctx.
- **CONCURRENCY NOTES:** Immutable result; no session store locks.
- **UNIT TESTS:** TestRouteProtocolClassification; TestInterruptedDump. **INTEGRATION TESTS:** A04/A05/A27 in M5_ACCEPTANCE_MATRIX.

### F17 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (g *Guard) PreparePlan(ctx context.Context, previous, desired domain.Config, ops []dataplane.NetworkOperation) ([]dataplane.NetworkOperation,error)`.
- **FILE:** `internal/networkservices/ownership/guard.go`.
- **RESPONSIBILITY:** Protect route keys and link dependencies; authorize exact old-static adoption.
- **INPUT:** Previous/desired config + typed operation metadata. **OUTPUT:** Deep-owned permitted operations with proto196/exact delete qualifiers.
- **PRECONDITIONS:** FRR union reservations already verified for an active routing transaction.
- **VALIDATION:** Exact key/provenance/manifest; foreign collision rejected; referenced link deletion rejected.
- **SIDE EFFECTS:** Read kernel; no live changes in this method.
- **ERROR CONDITIONS:** Resource conflict, ambiguous legacy adoption, missing reservation, stale snapshot.
- **CALLS:** F16; pure resource claim matcher. **CALLED BY:** NetworkReconciler.Reconcile.
- **ROLLBACK BEHAVIOR:** Same guard also processes reverse plan; only recognized own mutations.
- **TIMEOUT/CANCELLATION:** 3s read bound; one generation snapshot.
- **CONCURRENCY NOTES:** Caller serializes; no call into FRR here.
- **UNIT TESTS:** TestGuardRejectsForeignRoute; TestGuardPreservesVIP; TestGuardExactAdoption. **INTEGRATION TESTS:** A04/A05/A23 in M5_ACCEPTANCE_MATRIX.

### F18 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `func PlanNetwork(previous, desired domain.Config) ([]NetworkOperation,error); func (r *NetworkReconciler) Reconcile(ctx context.Context, previous, desired domain.Config) error`.
- **FILE:** `internal/dataplane/linux.go`.
- **RESPONSIBILITY:** Attach typed RouteMutation and invoke optional guard for forward and reverse plans.
- **INPUT:** Existing inputs; r.Ownership optional interface. **OUTPUT:** Same operations/result when nil.
- **PRECONDITIONS:** No vendor dependency; existing constructor unchanged.
- **VALIDATION:** Existing plan validation; guard before first command.
- **SIDE EFFECTS:** Existing ip operations only after authorization.
- **ERROR CONDITIONS:** Existing errors plus guard conflicts.
- **CALLS:** PlanNetwork, ownership.PreparePlan, existing runner/rollback. **CALLED BY:** Controller prepared apply.
- **ROLLBACK BEHAVIOR:** Existing reverse plan also runs guard; never delete foreign state.
- **TIMEOUT/CANCELLATION:** Preserve existing bounded recovery; honor parent for forward apply.
- **CONCURRENCY NOTES:** No new global lock; controller serializes.
- **UNIT TESTS:** Existing linux_test.go + TestOwnershipHookNilIsLegacy. **INTEGRATION TESTS:** A04/A05/A23/A28 in M5_ACCEPTANCE_MATRIX.

### F19 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *Controller) CurrentActivationSnapshot() (ActivationSnapshot,bool)`.
- **FILE:** `internal/dataplane/controller_m5.go`.
- **RESPONSIBILITY:** Read exact current config/M2 options/generation/inspection metadata for outer WAL.
- **INPUT:** None. **OUTPUT:** Detached ActivationSnapshot; false if not known.
- **PRECONDITIONS:** No mutation; use currentSnapshot when available.
- **VALIDATION:** Clone exact existing state; never allocate epoch or derive from target.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Unknown represented false.
- **CALLS:** cloneActivationSnapshot; current fields under c.mu. **CALLED BY:** Coordinator snapshot callback.
- **ROLLBACK BEHAVIOR:** Not applicable.
- **TIMEOUT/CANCELLATION:** Immediate memory copy.
- **CONCURRENCY NOTES:** Existing controller mutex only; no IO under it.
- **UNIT TESTS:** TestCurrentActivationSnapshotIsDetachedAndExact. **INTEGRATION TESTS:** A23/A24 in M5_ACCEPTANCE_MATRIX.

### F20 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func NewNetworkServicesCoordinator(d Deps) (*NetworkServicesCoordinator,error)`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Validate dependency graph and create disabled coordinator.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Prepare may write staging only; others no runtime mutation.
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** No IO constructors. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** No live effect to undo; retain referenced staged artifacts.
- **TIMEOUT/CANCELLATION:** 120s activation aggregate, separate60s compensation; adapter step bounds; cancel/reap IO.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestCoordinatorConstructionNoIO. **INTEGRATION TESTS:** A00 in M5_ACCEPTANCE_MATRIX.

### F21 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesCoordinator) Prepare(ctx context.Context, target domain.Config, generation uint64) error`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Pure validation plus staged artifacts and native syntax checks; snapshot deps.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Prepare may write staging only; others no runtime mutation.
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** Validators; backend.Prepare; F13/F14/F16. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** No live effect to undo; retain referenced staged artifacts.
- **TIMEOUT/CANCELLATION:** 120s activation aggregate, separate60s compensation; adapter step bounds; cancel/reap IO.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestPreflightHasNoRuntimeSideEffects. **INTEGRATION TESTS:** A01/A20/A21/A22 in M5_ACCEPTANCE_MATRIX.

### F22 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesCoordinator) Apply(ctx context.Context, target domain.Config, generation uint64) error`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Write WAL, quiesce dependents, reserve old/target static keys, invoke legacy apply and adapters in dependency order.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Only phase-owned changes defined in ARCHITECTURE; does not publish Running.
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** F15/F19, Guard, FRR.Reserve, legacy prepared apply, adapter.Apply/Verify. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** Reverse dependency compensation; never replay learned routes/session state; recognize manager's repeated old-config callback.
- **TIMEOUT/CANCELLATION:** 120s activation aggregate, separate60s compensation; adapter step bounds; cancel/reap IO.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestApplyCompensatesEveryPhase. **INTEGRATION TESTS:** A04/A23/A24 in M5_ACCEPTANCE_MATRIX.

### F23 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesCoordinator) Finalize(ctx context.Context, target domain.Config, generation uint64) error`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Verify accepted generation; open admission and readiness; inner finalize then close outer WAL.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Only phase-owned changes defined in ARCHITECTURE; .
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** legacy FinalizeActivation; adapter.Verify; F15; guards/readiness. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** Reverse dependency compensation; never replay learned routes/session state; recognize manager's repeated old-config callback.
- **TIMEOUT/CANCELLATION:** 120s activation aggregate, separate60s compensation; adapter step bounds; cancel/reap IO.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestFinalizeGenerationMismatchKeepsJournal. **INTEGRATION TESTS:** A23/A24 in M5_ACCEPTANCE_MATRIX.

### F24 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesCoordinator) Recover(ctx context.Context, running domain.Config, generation uint64) error`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Recover based on authoritative Running old/target digest; restore exact artifacts/claims, not learned routes.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Only phase-owned changes defined in ARCHITECTURE; .
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** F15/F19, legacy snapshot restore, adapters Restore/Apply. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** Reverse dependency compensation; never replay learned routes/session state; recognize manager's repeated old-config callback.
- **TIMEOUT/CANCELLATION:** 120s activation aggregate, separate60s compensation; adapter step bounds; cancel/reap IO.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestRecoveryAtEachDurableBoundary. **INTEGRATION TESTS:** A05/A24 in M5_ACCEPTANCE_MATRIX.

### F25 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesCoordinator) Reconcile(ctx context.Context) error`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Repair desired external config drift and refresh immutable status without fighting live RIB/role.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Only phase-owned changes defined in ARCHITECTURE; .
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** adapter Verify/Status/Apply for drift; cached accepted config; no Config commit. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** Reverse dependency compensation; never replay learned routes/session state; recognize manager's repeated old-config callback.
- **TIMEOUT/CANCELLATION:** 120s activation aggregate, separate60s compensation; adapter step bounds; cancel/reap IO.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestReconcileIgnoresLearnedRoutesAndVRRPRole. **INTEGRATION TESTS:** A03/A26 in M5_ACCEPTANCE_MATRIX.

### F26 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *NetworkServicesCoordinator) Status(q domain.NetworkStatusQuery) (domain.NetworkStatusPage,error)`.
- **FILE:** `internal/engine/network_services.go`.
- **RESPONSIBILITY:** Serve bounded immutable status pages from a snapshot.
- **INPUT:** Typed arguments; Deps/Config copies per CODE_CONTRACTS. **OUTPUT:** Return values per signature; typed phase/code error.
- **PRECONDITIONS:** Follow architecture transaction and exact old snapshot requirement.
- **VALIDATION:** Generation+digest; duplicate phase idempotent; disabled steady state returns before IO.
- **SIDE EFFECTS:** Prepare may write staging only; others no runtime mutation.
- **ERROR CONDITIONS:** All M5 typed errors; RecoveryRequired on unverifiable compensation.
- **CALLS:** No IO; status cache. **CALLED BY:** Composition-root callbacks / runtime status / background worker.
- **ROLLBACK BEHAVIOR:** No live effect to undo; retain referenced staged artifacts.
- **TIMEOUT/CANCELLATION:** Memory only; <=2s query budget.
- **CONCURRENCY NOTES:** Per-method mutex; in-flight flag spans callbacks, no mutex held across callbacks; lock order in CODE_CONTRACTS.
- **UNIT TESTS:** TestStatusCursorGenerationAndBounds. **INTEGRATION TESTS:** A06/A12/A25 in M5_ACCEPTANCE_MATRIX.

### F27 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func Compile(c domain.RoutingConfig, claims []resources.RouteClaim) (CompiledPolicy,error)`.
- **FILE:** `internal/routingpolicy/compile.go`.
- **RESPONSIBILITY:** Create typed user policy with mandatory protected/static-prefix intersections.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Stable order, generated reserved names; filtered M1_STATIC/connected redistribution; no source directives.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** FRR renderer.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestPolicyCannotOverrideProtectedPrefixes. **INTEGRATION TESTS:** A04/A07/A29 in M5_ACCEPTANCE_MATRIX.

### F28 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func Render(c domain.Config, claims []resources.RouteClaim, secrets SecretBindings) (RenderedConfig,error)`.
- **FILE:** `internal/routing/frr/render.go`.
- **RESPONSIBILITY:** Build deterministic complete FRR config from typed models.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** No staticd/routes/VIP/firewall directives; pinned grammar; secret bytes only in protected output.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** FRRBackend.Prepare/Reserve.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestFRRRenderDeterministicAndNoStaticd. **INTEGRATION TESTS:** A02/A04/A06/A09 in M5_ACCEPTANCE_MATRIX.

### F29 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func RenderOSPF(c domain.RoutingConfig, b RenderBindings) ([]Directive,error)`.
- **FILE:** `internal/routing/frr/ospf.go`.
- **RESPONSIBILITY:** Interface-specific area/passive/auth/cost/timers/default/filtered redistribution.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Use validated IDs/IPs; no freeform fragments; stable ordering; native syntax gate still mandatory.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Render.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestRenderOSPF. **INTEGRATION TESTS:** A02/A03 in M5_ACCEPTANCE_MATRIX.

### F30 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func RenderBGP(c domain.RoutingConfig, b RenderBindings) ([]Directive,error)`.
- **FILE:** `internal/routing/frr/bgp.go`.
- **RESPONSIBILITY:** Single-hop neighbor AF/import/export/network/max-prefix/default/multipath configuration.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Use validated IDs/IPs; no freeform fragments; stable ordering; native syntax gate still mandatory.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Render.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestRenderBGP. **INTEGRATION TESTS:** A06–A08 in M5_ACCEPTANCE_MATRIX.

### F31 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func RenderBFD(c domain.RoutingConfig, b RenderBindings) ([]Directive,error)`.
- **FILE:** `internal/routing/frr/bfd.go`.
- **RESPONSIBILITY:** Profiles, explicit peers and referenced OSPF/BGP BFD integration; echo off.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Use validated IDs/IPs; no freeform fragments; stable ordering; native syntax gate still mandatory.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Render.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestRenderBFD. **INTEGRATION TESTS:** A09 in M5_ACCEPTANCE_MATRIX.

### F32 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func DecodeRoutingStatus(raw RawRoutingJSON, q domain.RoutingQuery, interfaces InterfaceIndex) (domain.RoutingStatus,error)`.
- **FILE:** `internal/routing/frr/status.go`.
- **RESPONSIBILITY:** Normalize pinned FRR JSON and kernel source provenance.
- **INPUT:** Named JSON documents, bounded query, interface ID map. **OUTPUT:** Typed status with unavailable fields nullable.
- **PRECONDITIONS:** Raw size already bounded; does not infer success from empty output.
- **VALIDATION:** Required keys/types; additive unknown keys ignored; uptime units pinned.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Unsupported schema/missing fields/oversize; UNKNOWN rather than invented0.
- **CALLS:** encoding/json; kernel observer merge. **CALLED BY:** FRRBackend.Status.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** Bounded parse/query sizes.
- **CONCURRENCY NOTES:** Pure detached output.
- **UNIT TESTS:** TestFRRJSONSchemaFixtures. **INTEGRATION TESTS:** A02/A06/A09/A27 in M5_ACCEPTANCE_MATRIX.

### F33 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func NetworkServicePrefixes(c domain.Config) ([]ZonePrefix,error)`.
- **FILE:** `internal/connectivity/network_services.go`.
- **RESPONSIBILITY:** Return only configured validated reachable prefixes in declared zone.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Reject cross-zone/protected conflicts; no live RIB lookup; same-zone multipath.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** connectivity.Compile.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestDynamicPrefixZoneIsExplicit. **INTEGRATION TESTS:** A02/A10/A28 in M5_ACCEPTANCE_MATRIX.

### F34 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `func Compile(config domain.Config, generation uint64) (Program,error)`.
- **FILE:** `internal/connectivity/program.go`.
- **RESPONSIBILITY:** Append F33 prefixes once without changing legacy rules/identity.
- **INPUT:** Existing config/generation. **OUTPUT:** Existing Program.
- **PRECONDITIONS:** Retain legacy connected/static behavior.
- **VALIDATION:** F33; no M5 yields identical Program.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Existing compile errors + prefix conflict.
- **CALLS:** F33. **CALLED BY:** runtime compile/activation.
- **ROLLBACK BEHAVIOR:** No side effect.
- **TIMEOUT/CANCELLATION:** Existing bound.
- **CONCURRENCY NOTES:** Pure.
- **UNIT TESTS:** Existing connectivity tests + F33 tests. **INTEGRATION TESTS:** A02/A10/A28 in M5_ACCEPTANCE_MATRIX.

### F35 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (l *SysctlLease) Apply(ctx context.Context, cfg domain.WANMultiLinkConfig, interfaces InterfaceIndex) (LeaseReceipt,error); func (l *SysctlLease) Restore(ctx context.Context, r LeaseReceipt) error`.
- **FILE:** `internal/wan/lease_linux.go`.
- **RESPONSIBILITY:** Lease only ECMP hash and participating-interface rp_filter.
- **INPUT:** Typed WAN config; exact previous values from WAL. **OUTPUT:** Receipt/value readback.
- **PRECONDITIONS:** No MGMT scope; WAL written first.
- **VALIDATION:** Only allowlisted sysctl keys; preserve observed operator drift.
- **SIDE EFFECTS:** Scoped sysctl write/readback.
- **ERROR CONDITIONS:** Conflict/unsupported/permission/verify failure.
- **CALLS:** Fixed sysctl file adapter. **CALLED BY:** Coordinator WAN phase/compensation.
- **ROLLBACK BEHAVIOR:** Restore if current still equals lease; otherwise RecoveryRequired.
- **TIMEOUT/CANCELLATION:** 2s per step; ctx.
- **CONCURRENCY NOTES:** Activation serialized.
- **UNIT TESTS:** TestSysctlLeaseDoesNotOverwriteForeignDrift. **INTEGRATION TESTS:** A10/A11/A23/A24 in M5_ACCEPTANCE_MATRIX.

### F36 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (o *Observer) Observe(ctx context.Context, c domain.WANMultiLinkConfig) (domain.WANStatus,error)`.
- **FILE:** `internal/wan/observer.go`.
- **RESPONSIBILITY:** Merge FRR/BFD/FIB/probe observations into path status; never choose route.
- **INPUT:** Immutable config + observations. **OUTPUT:** WANStatus with path selected/health/counters/times.
- **PRECONDITIONS:** Validated FRR references.
- **VALIDATION:** Generation/age align; selected paths from kernel not probe score.
- **SIDE EFFECTS:** Read-only queries; schedules bounded probes.
- **ERROR CONDITIONS:** Stale/unavailable/timeout separate from DOWN.
- **CALLS:** FRR Status; KernelObserver; health.ProbeTCP. **CALLED BY:** Coordinator status worker.
- **ROLLBACK BEHAVIOR:** Cancel removed-generation probes; no route rollback.
- **TIMEOUT/CANCELLATION:** 5s refresh; max4 concurrent probes, jitter10%, bounded timer stop.
- **CONCURRENCY NOTES:** Immutable snapshots; counters locked briefly.
- **UNIT TESTS:** TestWANProbeDoesNotMutateRoutesOrMarks. **INTEGRATION TESTS:** A10–A13 in M5_ACCEPTANCE_MATRIX.

### F37 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ProbeTCP(ctx context.Context, target ProbeTarget) ProbeResult`.
- **FILE:** `internal/wan/health/tcp.go`.
- **RESPONSIBILITY:** Attempt source+device-bound TCP connect and record monotonic outcome.
- **INPUT:** IP/port/source/interface/timing; no DNS resolution. **OUTPUT:** UP/DOWN/UNKNOWN + elapsed/error code.
- **PRECONDITIONS:** T01 fresh socket bind capability proven.
- **VALIDATION:** Endpoint whitelist from config; iface/source match; bind once before connect.
- **SIDE EFFECTS:** One outbound socket, no raw packets/route change.
- **ERROR CONDITIONS:** EPERM => unsupported, timeout/refused => failed; cancellation => unknown.
- **CALLS:** net.Dialer.ControlContext with x/sys socket option. **CALLED BY:** WAN Observer.
- **ROLLBACK BEHAVIOR:** Close socket; no connection reuse.
- **TIMEOUT/CANCELLATION:** Configured100..5000ms max, <=interval; ctx wins.
- **CONCURRENCY NOTES:** Independent fresh socket; no worker leak.
- **UNIT TESTS:** TestProbeBindBeforeConnect; TestProbeCancellation. **INTEGRATION TESTS:** A12/A27 in M5_ACCEPTANCE_MATRIX.

### F38 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func CompileNetworkServiceGuard(c domain.Config, r ReadinessView, uid uint32) (GuardPlan,error)`.
- **FILE:** `internal/networkservices/nftguard/render.go`.
- **RESPONSIBILITY:** Compile scoped local service/protocol admission and LB egress.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Typed sources/protocolTTL/tuple/UID; affected listeners closed until verified; no broad accept or M1 table edit.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** Guard.Apply.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestGuardAdmissionAndBackendEgress. **INTEGRATION TESTS:** A17/A29 in M5_ACCEPTANCE_MATRIX.

### F39 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (g *Guard) Apply(ctx context.Context, p GuardPlan) error; func (g *Guard) Snapshot(ctx context.Context) (GuardSnapshot,error); func (g *Guard) Restore(ctx context.Context, s GuardSnapshot) error`.
- **FILE:** `internal/networkservices/nftguard/apply.go`.
- **RESPONSIBILITY:** Atomic change of only inet ngfw_m5_services.
- **INPUT:** Hashed compiled guard / previous snapshot. **OUTPUT:** Verified result / typed error.
- **PRECONDITIONS:** Root NET_ADMIN; validated plan and journal before apply.
- **VALIDATION:** Table/name ownership and generation.
- **SIDE EFFECTS:** One nft transaction; only scoped M5 table.
- **ERROR CONDITIONS:** Syntax/apply/readback failed.
- **CALLS:** Runner fixed nft -c/-f/-j scoped table. **CALLED BY:** Coordinator before/after services.
- **ROLLBACK BEHAVIOR:** Exact previous scoped guard; never flush global ruleset.
- **TIMEOUT/CANCELLATION:** 5s native step with ctx.
- **CONCURRENCY NOTES:** M5 activation serialized.
- **UNIT TESTS:** TestGuardNeverTouchesM1Table. **INTEGRATION TESTS:** A17/A23/A27/A29 in M5_ACCEPTANCE_MATRIX.

### F40 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func Render(c domain.HAProxyConfig, b RenderBindings) (RenderedConfig,error)`.
- **FILE:** `internal/loadbalancer/haproxy/render.go`.
- **RESPONSIBILITY:** Render bounded TCP/HTTP delivery, algorithms, health checks/TLS/ACL delivery selection.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** Fixed grammar/ciphers; exact host/path matching escaped; backend TLS verification; no scripts; only delivery routing.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** HAProxyBackend.Prepare.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestHAProxyRenderModesTLSAndAccessSeparation. **INTEGRATION TESTS:** A14–A17 in M5_ACCEPTANCE_MATRIX.

### F41 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ReadStatus(ctx context.Context, socket RuntimeSocket, schema StatsSchema) (domain.LoadBalancerStatus,error)`.
- **FILE:** `internal/loadbalancer/haproxy/status.go`.
- **RESPONSIBILITY:** Read and normalize JSON schema/info/stats; distinguish disabled/down/draining.
- **INPUT:** Fixed socket; pinned schema. **OUTPUT:** Typed service/backend/server counters.
- **PRECONDITIONS:** Socket owner verified; per-call immutable view.
- **VALIDATION:** Max bytes, field names/type, worker generation, units.
- **SIDE EFFECTS:** Read-only Runtime API commands.
- **ERROR CONDITIONS:** Socket unavailable/schema mismatch/timeout.
- **CALLS:** Unix net.Conn; JSON decoder. **CALLED BY:** HAProxyBackend.Status/Verify.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** 2s total; disconnect on cancel.
- **CONCURRENCY NOTES:** Separate status connection per sample.
- **UNIT TESTS:** TestHAProxyJSONSchemaAndOldWorker. **INTEGRATION TESTS:** A14/A15/A19/A27 in M5_ACCEPTANCE_MATRIX.

### F42 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func Render(c domain.VRRPConfig, b RenderBindings) (RenderedConfig,error)`.
- **FILE:** `internal/ha/keepalived/render.go`.
- **RESPONSIBILITY:** Render unicast VRRPv3 groups with fixed readiness tracking.
- **INPUT:** Immutable domain config / arguments in signature. **OUTPUT:** Return value in signature; no borrowed mutable slices.
- **PRECONDITIONS:** Supported schema; do not assume caller validation.
- **VALIDATION:** BACKUP start; fixed safe helper path; nopreempt and delay semantics; no scripts/static resources/checker stanzas.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues with JSON path, or typed error if signature returns error.
- **CALLS:** domain helpers; no IO/vendor packages. **CALLED BY:** KeepalivedBackend.Prepare.
- **ROLLBACK BEHAVIOR:** Not required: pure operation.
- **TIMEOUT/CANCELLATION:** Bounded input sizes in CODE_CONTRACTS; no goroutines.
- **CONCURRENCY NOTES:** Reentrant; return deep-owned output.
- **UNIT TESTS:** TestVRRPRenderNoForeignWriters. **INTEGRATION TESTS:** A18/A19 in M5_ACCEPTANCE_MATRIX.

### F43 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (w *ReadinessWriter) Publish(ctx context.Context, r ReadyRecord) error; func EvaluateReadiness(r ReadyRecord, nowMonotonicNS int64, bootID string) bool`.
- **FILE:** `internal/ha/readiness.go`.
- **RESPONSIBILITY:** Bounded authenticated local readiness record.
- **INPUT:** Boot/generation, dependency health, fresh monotonic timestamp. **OUTPUT:** Atomic file / bool.
- **PRECONDITIONS:** Only engine writes, unpriv helper reads; ENGINE always tracked.
- **VALIDATION:** Age<=5s, current boot and accepted generation; fail closed on missing/invalid.
- **SIDE EFFECTS:** Publish file only; evaluate pure.
- **ERROR CONDITIONS:** Disk/permission/clock invalid => not ready.
- **CALLS:** Atomic IO; monotonic clock. **CALLED BY:** Coordinator periodic worker/finalize; health helper.
- **ROLLBACK BEHAVIOR:** On failure publish false if possible, else record expires.
- **TIMEOUT/CANCELLATION:** Publish1s interval, helper<=500ms.
- **CONCURRENCY NOTES:** Writer serial; atomic reads.
- **UNIT TESTS:** TestReadinessExpiresAcrossCrashAndBoot. **INTEGRATION TESTS:** A18/A19/A24 in M5_ACCEPTANCE_MATRIX.

### F44 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func main()`.
- **FILE:** `cmd/ngfw-ha-health/main.go`.
- **RESPONSIBILITY:** Keepalived fixed unprivileged health script entry point.
- **INPUT:** Fixed profile paths only; no Candidate argv. **OUTPUT:** Exit0 ready, exit1 otherwise; no secret/stdout dump.
- **PRECONDITIONS:** ngfw-ha user, no caps.
- **VALIDATION:** File owner/mode/size/no symlink; boot/age/gen verification.
- **SIDE EFFECTS:** Read-only.
- **ERROR CONDITIONS:** All unreadable/stale cases exit1.
- **CALLS:** ha.EvaluateReadiness. **CALLED BY:** Keepalived track_script.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** Hard500ms bound.
- **CONCURRENCY NOTES:** One short process, no child/goroutines left.
- **UNIT TESTS:** TestHealthCommandRejectsUnsafeRecord. **INTEGRATION TESTS:** A19/A27 in M5_ACCEPTANCE_MATRIX.

### F45 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ReadState(ctx context.Context, src StateSource) (domain.HAStatus,error); func DecodeEvent(line []byte) (VRRPTransition,error)`.
- **FILE:** `internal/ha/keepalived/status.go`.
- **RESPONSIBILITY:** Combine validated FIFO transitions with fresh JSON v2 role snapshot and kernel VIP presence.
- **INPUT:** Protected FIFO/JSON/PID signal provider. **OUTPUT:** State UNKNOWN on insufficient proof, last transition optional.
- **PRECONDITIONS:** Dedicated VRRP unit source; no checker cross-talk.
- **VALIDATION:** FIFO exact grammar; max4KiB event; allowlisted IDs/states; fresh JSON/correct owner.
- **SIDE EFFECTS:** Read; request allowed JSON snapshot signal.
- **ERROR CONDITIONS:** Malformed/stale/unit unavailable/PID changed.
- **CALLS:** ServiceManager; bounded JSON parser; NetlinkObserver. **CALLED BY:** KeepalivedBackend.Status/Verify; transition worker.
- **ROLLBACK BEHAVIOR:** Never force MASTER based on observer.
- **TIMEOUT/CANCELLATION:** 3s snapshot; event worker ctx stops.
- **CONCURRENCY NOTES:** FIFO drain one goroutine, immutable state cache; loss forces fresh JSON.
- **UNIT TESTS:** TestKeepalivedFIFOAndSnapshotResync. **INTEGRATION TESTS:** A18/A19/A22/A26 in M5_ACCEPTANCE_MATRIX.

### F46 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func UsesNetworkServices(c Config) bool`.
- **FILE:** `internal/domain/network_services.go`.
- **RESPONSIBILITY:** Effective enabled predicate.
- **INPUT:** Config. **OUTPUT:** bool.
- **PRECONDITIONS:** None.
- **VALIDATION:** Root enabled and at least one supported child enabled.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** None.
- **CALLS:** No IO. **CALLED BY:** Coordinator and validators.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** Constant bounded model traversal.
- **CONCURRENCY NOTES:** Pure.
- **UNIT TESTS:** TestUsesNetworkServicesAbsentDisabled. **INTEGRATION TESTS:** A00/A01 in M5_ACCEPTANCE_MATRIX.

### F47 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (s *RuntimeServiceAdapter) NetworkServicesCapabilities(ctx context.Context) (domain.NetworkServicesCapabilities,error); func (s *RuntimeServiceAdapter) NetworkServicesStatus(ctx context.Context, q domain.NetworkStatusQuery) (domain.NetworkStatusPage,error)`.
- **FILE:** `internal/engine/network_services_runtime.go`.
- **RESPONSIBILITY:** Expose engine-owned immutable status/capabilities.
- **INPUT:** Context/query. **OUTPUT:** Typed snapshots.
- **PRECONDITIONS:** Optional coordinator wired; no vendor calls on request path.
- **VALIDATION:** Query allowlist/cursor/limit.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Unavailable, cursor expired, invalid query.
- **CALLS:** Coordinator.Status; cached capabilities. **CALLED BY:** Optional engine IPC interface.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** 2s maximum, normally memory only.
- **CONCURRENCY NOTES:** No activation/session locks while serving.
- **UNIT TESTS:** TestNetworkServicesStatusDoesNotExecuteTools. **INTEGRATION TESTS:** A25/A27 in M5_ACCEPTANCE_MATRIX.

### F48 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (c *RuntimeClient) NetworkServicesCapabilities(ctx context.Context) (domain.NetworkServicesCapabilities,error); func (c *RuntimeClient) NetworkServicesStatus(ctx context.Context,q domain.NetworkStatusQuery) (domain.NetworkStatusPage,error)`.
- **FILE:** `internal/engineipc/network_services.go`.
- **RESPONSIBILITY:** Optional v3 methods and cached capability negotiation.
- **INPUT:** Bounded DTOs; existing IPC endpoint. **OUTPUT:** Typed result.
- **PRECONDITIONS:** Match response ID/version; no generic CLI method.
- **VALIDATION:** Limits/schema/protocol; old server unsupported is explicit.
- **SIDE EFFECTS:** IPC only.
- **ERROR CONDITIONS:** RemoteError preserves code; no plaintext diagnostics.
- **CALLS:** RuntimeClient.call. **CALLED BY:** Management API.
- **ROLLBACK BEHAVIOR:** No mutation; clear stale capability on reconnect.
- **TIMEOUT/CANCELLATION:** 2s query; cache per engine boot/profile.
- **CONCURRENCY NOTES:** Concurrent immutable cache refresh.
- **UNIT TESTS:** TestM5IPCOptionalOldServer. **INTEGRATION TESTS:** A25/A27 in M5_ACCEPTANCE_MATRIX.

### F49 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `func (s *RuntimeServer) dispatch(ctx context.Context, request runtimeRequest) (json.RawMessage,error); func (s *RuntimeServer) handle(parent context.Context, connection net.Conn); func (c *RuntimeClient) call(ctx context.Context, operation string, value any, out any, mutation bool) error; func (c *RuntimeClient) CommitConfig(ctx context.Context, config domain.Config, expected uint64, author, comment, operationID string) (domain.ConfigVersion,error)`.
- **FILE:** `internal/engineipc/runtime.go`.
- **RESPONSIBILITY:** Register optional methods; reject M5 against old engine; negotiate extended config-only deadline.
- **INPUT:** Existing operations plus two M5 operations. **OUTPUT:** Existing envelope.
- **PRECONDITIONS:** Do not change RuntimeProtocolVersion or legacy method DTOs.
- **VALIDATION:** Capability before nonnil subtree; max bytes/requestID/version unchanged.
- **SIDE EFFECTS:** IPC and existing delegated config mutation only.
- **ERROR CONDITIONS:** Unsupported capability/version, timeout, cancellation.
- **CALLS:** F48; optional RuntimeService type assertion; existing service methods. **CALLED BY:** API/runtime clients.
- **ROLLBACK BEHAVIOR:** Existing operation IDs/version guard; lost response does not imply rollback.
- **TIMEOUT/CANCELLATION:** 190s only negotiated commit/rollback; existing other bounds.
- **CONCURRENCY NOTES:** Keep existing pending limit16; no unbounded long-request queues.
- **UNIT TESTS:** TestM5ConfigCapabilityRequired; TestConfigMutationBudget. **INTEGRATION TESTS:** A01/A23/A25 in M5_ACCEPTANCE_MATRIX.

### F50 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (a *API) networkServicesCapabilities(w http.ResponseWriter,r *http.Request); func (a *API) networkServicesStatus(w http.ResponseWriter,r *http.Request)`.
- **FILE:** `internal/management/network_services.go`.
- **RESPONSIBILITY:** Authenticated read-only management views.
- **INPUT:** GET query and runtime client. **OUTPUT:** Existing success/data or error envelope.
- **PRECONDITIONS:** Existing auth middleware.
- **VALIDATION:** GET-only; allowlist view/subsystem; query bounds; no arbitrary peer CLI.
- **SIDE EFFECTS:** IPC only.
- **ERROR CONDITIONS:** 401/403 existing auth,400 query,503 unavailable,409 expired cursor.
- **CALLS:** Optional runtime client F48. **CALLED BY:** API.Handler.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** 2s status request.
- **CONCURRENCY NOTES:** Cancel with HTTP context; no daemon call.
- **UNIT TESTS:** TestM5StatusAuthAndBounds. **INTEGRATION TESTS:** A25/A27 in M5_ACCEPTANCE_MATRIX.

### F51 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `func (a *API) Handler() http.Handler; func (a *API) commit(w http.ResponseWriter,r *http.Request); func (a *API) rollback(w http.ResponseWriter,r *http.Request)`.
- **FILE:** `internal/management/api.go`.
- **RESPONSIBILITY:** Register status paths and adjust only negotiated config mutation response deadline.
- **INPUT:** Existing routes/bodies. **OUTPUT:** Existing version/error response.
- **PRECONDITIONS:** Reuse auth/Candidate/version/operation-ID path.
- **VALIDATION:** No new tool executor; capabilities from engine.
- **SIDE EFFECTS:** HTTP registration; response deadline only new side effect.
- **ERROR CONDITIONS:** Existing errors; unsupported long deadline reports failure before mutation.
- **CALLS:** F50; ResponseController.SetWriteDeadline; existing runtime.CommitConfig/RollbackConfig. **CALLED BY:** HTTP server.
- **ROLLBACK BEHAVIOR:** Existing lifecycle; observe Running after lost reply.
- **TIMEOUT/CANCELLATION:** 200s write deadline only when190s capability negotiated.
- **CONCURRENCY NOTES:** Existing HTTP concurrency; engine serializes mutations.
- **UNIT TESTS:** TestM5APIDeadlineAndNoExecDependency. **INTEGRATION TESTS:** A25/A27 in M5_ACCEPTANCE_MATRIX.

### F52 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func configureNetworkServices(d NetworkServiceDeps) (*engine.NetworkServicesCoordinator,error)`.
- **FILE:** `cmd/ngfw-engine/network_services.go`.
- **RESPONSIBILITY:** Composition factory: immutable profiles/adapters/callbacks; no external syntax in main.
- **INPUT:** Existing controller/config/inspection callbacks + profile. **OUTPUT:** Coordinator; error leaves legacy available.
- **PRECONDITIONS:** No M5 effective state -> disabled object, no tool/secret/filesystem reads.
- **VALIDATION:** Local profile; adapter deps; snapshot callback.
- **SIDE EFFECTS:** Constructor itself no runtime writes.
- **ERROR CONDITIONS:** Missing required configured capability; disabled is not error.
- **CALLS:** New backends; F20; F19. **CALLED BY:** main.
- **ROLLBACK BEHAVIOR:** Stop only workers it starts (startup is caller step).
- **TIMEOUT/CANCELLATION:** Construction bounded local memory; profile reading performed explicit startup preflight.
- **CONCURRENCY NOTES:** One initialization.
- **UNIT TESTS:** TestDisabledFactoryDoesNoIO. **INTEGRATION TESTS:** A00/A05 in M5_ACCEPTANCE_MATRIX.

### F53 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `func main()`.
- **FILE:** `cmd/ngfw-engine/main.go`.
- **RESPONSIBILITY:** Compose current Before/Apply/After/Finalize hooks and startup recovery.
- **INPUT:** Existing process env/config. **OUTPUT:** Existing engine lifetime.
- **PRECONDITIONS:** Preserve dirty M4 changes, epoch allocator and current M3 hook order.
- **VALIDATION:** M5 capability opt-in; legacy exact snapshot known.
- **SIDE EFFECTS:** Startup Recover; workers; existing IPC/dataplane startup.
- **ERROR CONDITIONS:** Log sanitized subsystem error; degraded M5 does not delete legacy state.
- **CALLS:** F52; Recover; existing applyDataplane/M3 hooks/runtime/GateService. **CALLED BY:** OS/systemd.
- **ROLLBACK BEHAVIOR:** No destructive fallback; pending WAL retained; graceful cancel workers.
- **TIMEOUT/CANCELLATION:** Existing lifecycle plus defined M5 budgets.
- **CONCURRENCY NOTES:** One coordinator; never hold lock across M3 lifecycle callback.
- **UNIT TESTS:** TestEngineHookCompositionOrder. **INTEGRATION TESTS:** A05/A23–A28 in M5_ACCEPTANCE_MATRIX.

### F54 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `export async function fetchNetworkServicesStatus(query: NetworkStatusQuery, signal?: AbortSignal): Promise<NetworkStatusPage>; export async function fetchNetworkServicesCapabilities(signal?: AbortSignal): Promise<NetworkServicesCapabilities>`.
- **FILE:** `web/src/networkServices/api.ts`.
- **RESPONSIBILITY:** Typed bounded GET wrappers.
- **INPUT:** Query/signal. **OUTPUT:** Validated API DTO.
- **PRECONDITIONS:** Existing auth token helper.
- **VALIDATION:** Reject unknown view locally; encode URLSearchParams.
- **SIDE EFFECTS:** HTTP reads only.
- **ERROR CONDITIONS:** Existing api error type; stale/unsupported distinct.
- **CALLS:** Existing api<T>. **CALLED BY:** M5 views.
- **ROLLBACK BEHAVIOR:** Abort on unmount.
- **TIMEOUT/CANCELLATION:** 2s request plus bounded UI retry.
- **CONCURRENCY NOTES:** One active poll per visible view; abort previous generation.
- **UNIT TESTS:** networkServices/api.test.ts. **INTEGRATION TESTS:** A25 in M5_ACCEPTANCE_MATRIX.

### F55 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `export function NetworkServicesEditor(props: NetworkServicesEditorProps): JSX.Element`.
- **FILE:** `web/src/networkServices/Editor.tsx`.
- **RESPONSIBILITY:** Typed Candidate editor with routing/OSPF/BGP/BFD, WAN, LB/TLS/backend and HA tabs.
- **INPUT:** Immutable Candidate+capabilities+onChange(Config). **OUTPUT:** Edited Candidate only; commit remains existing flow.
- **PRECONDITIONS:** No direct runtime mutations, no plaintext secret input.
- **VALIDATION:** Schema bounds/reference pickers; show unsupported modes and DELIVERY_ONLY.
- **SIDE EFFECTS:** Local state edits.
- **ERROR CONDITIONS:** Display server errors by JSON path without losing draft.
- **CALLS:** Typed forms; existing saveCandidate. **CALLED BY:** App network-services page.
- **ROLLBACK BEHAVIOR:** Cancel restores draft; existing API rollback for committed changes.
- **TIMEOUT/CANCELLATION:** No request timeout of own.
- **CONCURRENCY NOTES:** Preserve non-M5 fields and nil until explicit enable.
- **UNIT TESTS:** Editor.test.tsx round-trip legacy fields. **INTEGRATION TESTS:** A01/A17/A25 in M5_ACCEPTANCE_MATRIX.

### F56 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `export function NetworkServicesStatusView(props: NetworkServicesStatusProps): JSX.Element`.
- **FILE:** `web/src/networkServices/Status.tsx`.
- **RESPONSIBILITY:** Display applied/configured/reachable/operational, routes sources and HA/LB/WAN state.
- **INPUT:** Capabilities/status query. **OUTPUT:** Status view; no apply buttons.
- **PRECONDITIONS:** Feature may be disabled/unavailable/stale.
- **VALIDATION:** Counters vs role interpreted per DTO; no green healthy for stale data.
- **SIDE EFFECTS:** Bounded polling when visible.
- **ERROR CONDITIONS:** Display reason codes, no secret text.
- **CALLS:** F54. **CALLED BY:** App.
- **ROLLBACK BEHAVIOR:** None; stop polling on unmount.
- **TIMEOUT/CANCELLATION:** 5s poll, no overlapping request.
- **CONCURRENCY NOTES:** Generation-bound pages.
- **UNIT TESTS:** Status.test.tsx stale and cursor expiry. **INTEGRATION TESTS:** A06/A12/A18/A25 in M5_ACCEPTANCE_MATRIX.

### F57 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `function normalizeConfig(value: unknown): NGFWConfig | null; export function normalizeConfigExport(value: unknown): ConfigExport | null`.
- **FILE:** `web/src/runtimeData.ts`.
- **RESPONSIBILITY:** Preserve optional M5 subtree through existing whole-Candidate editors.
- **INPUT:** Existing unknown JSON. **OUTPUT:** Existing typed config + optional M5.
- **PRECONDITIONS:** Keep existing spread/default semantics.
- **VALIDATION:** Validate structure without dropping valid unknown-to-old-view M5 fields; never silently enable.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Existing null/validation path.
- **CALLS:** New typed decoder in networkServices/types.ts (type guards inline, no new exported function required). **CALLED BY:** App config load.
- **ROLLBACK BEHAVIOR:** No side effect.
- **TIMEOUT/CANCELLATION:** Bounded parse.
- **CONCURRENCY NOTES:** Pure.
- **UNIT TESTS:** runtimeData M5 round-trip tests. **INTEGRATION TESTS:** A00/A01/A25 in M5_ACCEPTANCE_MATRIX.

### F58 — MODIFY EXISTING

- **FUNCTION / SIGNATURE:** `existing saveCandidate: (candidate: NGFWConfig) => Promise<boolean>; existing App component`.
- **FILE:** `web/src/App.tsx`.
- **RESPONSIBILITY:** Wire new editor/status and preserve Candidate commit flow.
- **INPUT:** Existing config state. **OUTPUT:** Existing UI.
- **PRECONDITIONS:** No API tool/runtime configuration endpoint.
- **VALIDATION:** Capability/changed version display.
- **SIDE EFFECTS:** Same Candidate HTTP PUT; config mutation deadline option205s negotiated.
- **ERROR CONDITIONS:** Existing form errors.
- **CALLS:** F55/F56; existing saveCandidate/api. **CALLED BY:** React root.
- **ROLLBACK BEHAVIOR:** Existing Candidate reset/rollback.
- **TIMEOUT/CANCELLATION:** 205s commit/rollback only when capability present.
- **CONCURRENCY NOTES:** Avoid overwriting edits from status polls.
- **UNIT TESTS:** App navigation + whole Candidate tests. **INTEGRATION TESTS:** A01/A25 in M5_ACCEPTANCE_MATRIX.

### F59 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func ValidateIPVS(c domain.Config) []ValidationIssue`.
- **FILE:** `internal/config/ipvs.go`.
- **RESPONSIBILITY:** OPTIONAL T31 exact NAT virtual-server schema/conflicts.
- **INPUT:** Config. **OUTPUT:** Issues.
- **PRECONDITIONS:** ipvs_nat_v1 built/enabled only after optional acceptance.
- **VALIDATION:** No DR/TUN/fwmark/M4/overlapping DNAT/LB; backend return path documented.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Validation issues.
- **CALLS:** ResourceConflict validator. **CALLED BY:** ValidateNetworkServices optional delegate.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** Pure bounded.
- **CONCURRENCY NOTES:** Reentrant.
- **UNIT TESTS:** TestIPVSNATValidation. **INTEGRATION TESTS:** A30/A31 in M5_ACCEPTANCE_MATRIX.

### F60 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func Render(c domain.IPVSConfig,b RenderBindings) (RenderedConfig,error)`.
- **FILE:** `internal/loadbalancer/ipvs/render.go`.
- **RESPONSIBILITY:** OPTIONAL render checker-only Keepalived virtual servers.
- **INPUT:** Validated config. **OUTPUT:** Protected generated config.
- **PRECONDITIONS:** Single checker writer.
- **VALIDATION:** NAT only; allowed algorithms/check ports; no VRRP/static IP/routes/scripts.
- **SIDE EFFECTS:** None.
- **ERROR CONDITIONS:** Unsupported/collision.
- **CALLS:** Fixed grammar. **CALLED BY:** IPVSBackend.Prepare.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** Bounded pure.
- **CONCURRENCY NOTES:** Reentrant.
- **UNIT TESTS:** TestIPVSRenderCheckerOnly. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### F61 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (o *Observer) Snapshot(ctx context.Context) (domain.IPVSStatus,error)`.
- **FILE:** `internal/loadbalancer/ipvs/status_linux.go`.
- **RESPONSIBILITY:** OPTIONAL observe IPVS kernel generic-netlink services/destinations.
- **INPUT:** Fixed namespace/family. **OUTPUT:** Counters/health service view.
- **PRECONDITIONS:** T01 optional capability profile.
- **VALIDATION:** Bounded netlink attributes, no human CLI parse.
- **SIDE EFFECTS:** Read only.
- **ERROR CONDITIONS:** Unsupported family/schema/timeout.
- **CALLS:** Pinned netlink binding selected/tested in T32; no direct writer methods. **CALLED BY:** IPVSBackend.Status.
- **ROLLBACK BEHAVIOR:** None.
- **TIMEOUT/CANCELLATION:** 3s bounded dump.
- **CONCURRENCY NOTES:** Detached state.
- **UNIT TESTS:** TestIPVSNetlinkFixtures. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B1New — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func NewFRRBackend(o Options) (*FRRBackend,error)`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Validate immutable dependencies/profile; no IO.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Constructor: dependency/enum error only; generation/digest binding and bounded input.
- **SIDE EFFECTS:** No effect.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRNewContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B1Prepare — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Prepare(ctx context.Context,c domain.Config,g networkservices.Generation) (networkservices.Prepared,error)`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Render, resolve secrets, stage protected files, run native syntax validation.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Reject disabled mismatches, unsupported profile, secret or native syntax error before runtime mutation; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Staging files and syntax child process only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRPrepareContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B1Snapshot — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Snapshot(ctx context.Context) (networkservices.Snapshot,error)`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Capture previous accepted desired artifact references/enablement and installed generation, not transient sessions/RIB.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Missing/tampered artifact or foreign active config => conflict; do not adopt silently; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read manifest and bounded verification.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRSnapshotContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B1Apply — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Apply(ctx context.Context,p networkservices.Prepared) (networkservices.ApplyReceipt,error)`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Publish staged artifact; pinned frr-reload.py --reload; reservation guards must remain in target config.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** Native exit/timeout/partial apply => typed phase receipt/error; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only; WAL already durable.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Reload previous protocol configuration and reservations; do not reinstall saved learned routes.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRApplyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B1Verify — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Verify(ctx context.Context,p networkservices.Prepared) error`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Native bounded config-diff must show no permitted change; daemon reachability and owned static exclusions checked; adjacency is separate operational status.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Mismatch/unreachable/schema failure; no invented success from empty state; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only installed-state checks.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRVerifyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B1Restore — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Restore(ctx context.Context,s networkservices.Snapshot) error`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Reload previous protocol configuration and reservations; do not reinstall saved learned routes.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** CompensationFailed if old desired cannot be verified; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Failure retains journal and fence; do not loop indefinitely.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRRestoreContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B1Status — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Status(ctx context.Context, q domain.RoutingQuery) (domain.RoutingStatus,error)`.
- **FILE:** `internal/routing/frr/backend.go`.
- **RESPONSIBILITY:** Decode structured runtime observation and label applied/configured/operational independently.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Unreachable/stale/unsupported JSON; required fields must not default to healthy; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only vendor interface.
- **ERROR CONDITIONS:** AdapterError includes subsystem=routing, phase, stable code, retryability and sanitized cause.
- **CALLS:** F28–F32; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, status5s, reload30s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestFRRStatusContract + pinned no-secret fixture. **INTEGRATION TESTS:** A02–A09/A20/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2New — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func NewHAProxyBackend(o Options) (*HAProxyBackend,error)`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** Validate immutable dependencies/profile; no IO.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Constructor: dependency/enum error only; generation/digest binding and bounded input.
- **SIDE EFFECTS:** No effect.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxyNewContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2Prepare — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *HAProxyBackend) Prepare(ctx context.Context,c domain.Config,g networkservices.Generation) (networkservices.Prepared,error)`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** Render, resolve secrets, stage protected files, run native syntax validation.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Reject disabled mismatches, unsupported profile, secret or native syntax error before runtime mutation; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Staging files and syntax child process only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxyPrepareContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2Snapshot — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *HAProxyBackend) Snapshot(ctx context.Context) (networkservices.Snapshot,error)`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** Capture previous accepted desired artifact references/enablement and installed generation, not transient sessions/RIB.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Missing/tampered artifact or foreign active config => conflict; do not adopt silently; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read manifest and bounded verification.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxySnapshotContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2Apply — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *HAProxyBackend) Apply(ctx context.Context,p networkservices.Prepared) (networkservices.ApplyReceipt,error)`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** Publish config/key references; reload fixed master-worker unit with USR2; scoped admission stays closed for changed services.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** Native exit/timeout/partial apply => typed phase receipt/error; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only; WAL already durable.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Reload previous accepted artifact while changed listener admission remains closed; in-flight accepted connections cannot be reconstructed.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxyApplyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2Verify — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *HAProxyBackend) Verify(ctx context.Context,p networkservices.Prepared) error`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** New worker generation/config hash+schema, desired listeners/backends installed; DOWN backend is operational degradation, not false install failure.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Mismatch/unreachable/schema failure; no invented success from empty state; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only installed-state checks.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxyVerifyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2Restore — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *HAProxyBackend) Restore(ctx context.Context,s networkservices.Snapshot) error`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** Reload previous accepted artifact while changed listener admission remains closed; in-flight accepted connections cannot be reconstructed.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** CompensationFailed if old desired cannot be verified; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Failure retains journal and fence; do not loop indefinitely.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxyRestoreContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B2Status — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *HAProxyBackend) Status(ctx context.Context) (domain.LoadBalancerStatus,error)`.
- **FILE:** `internal/loadbalancer/haproxy/backend.go`.
- **RESPONSIBILITY:** Decode structured runtime observation and label applied/configured/operational independently.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Unreachable/stale/unsupported JSON; required fields must not default to healthy; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only vendor interface.
- **ERROR CONDITIONS:** AdapterError includes subsystem=load_balancer, phase, stable code, retryability and sanitized cause.
- **CALLS:** F40/F41; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, status2s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestHAProxyStatusContract + pinned no-secret fixture. **INTEGRATION TESTS:** A14–A17/A21/A23–A27 in M5_ACCEPTANCE_MATRIX.

### B3New — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func NewKeepalivedBackend(o Options) (*KeepalivedBackend,error)`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Validate immutable dependencies/profile; no IO.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Constructor: dependency/enum error only; generation/digest binding and bounded input.
- **SIDE EFFECTS:** No effect.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedNewContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B3Prepare — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *KeepalivedBackend) Prepare(ctx context.Context,c domain.Config,g networkservices.Generation) (networkservices.Prepared,error)`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Render, resolve secrets, stage protected files, run native syntax validation.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Reject disabled mismatches, unsupported profile, secret or native syntax error before runtime mutation; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Staging files and syntax child process only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedPrepareContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B3Snapshot — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *KeepalivedBackend) Snapshot(ctx context.Context) (networkservices.Snapshot,error)`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Capture previous accepted desired artifact references/enablement and installed generation, not transient sessions/RIB.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Missing/tampered artifact or foreign active config => conflict; do not adopt silently; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read manifest and bounded verification.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedSnapshotContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B3Apply — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *KeepalivedBackend) Apply(ctx context.Context,p networkservices.Prepared) (networkservices.ApplyReceipt,error)`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Publish VRRP-only artifact; reload fixed unit; readiness false for affected groups until finalization.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** Native exit/timeout/partial apply => typed phase receipt/error; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only; WAL already durable.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Reload previous group desired configuration; readiness fence; protocol elects role, engine never forces MASTER.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedApplyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B3Verify — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *KeepalivedBackend) Verify(ctx context.Context,p networkservices.Prepared) error`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Installed config/generation and tracked readiness checked; arbitrary MASTER role is not desired config; VIP matches actual role after convergence.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Mismatch/unreachable/schema failure; no invented success from empty state; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only installed-state checks.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedVerifyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B3Restore — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *KeepalivedBackend) Restore(ctx context.Context,s networkservices.Snapshot) error`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Reload previous group desired configuration; readiness fence; protocol elects role, engine never forces MASTER.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** CompensationFailed if old desired cannot be verified; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Failure retains journal and fence; do not loop indefinitely.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedRestoreContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B3Status — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *KeepalivedBackend) Status(ctx context.Context) (domain.HAStatus,error)`.
- **FILE:** `internal/ha/keepalived/backend.go`.
- **RESPONSIBILITY:** Decode structured runtime observation and label applied/configured/operational independently.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Unreachable/stale/unsupported JSON; required fields must not default to healthy; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only vendor interface.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ha, phase, stable code, retryability and sanitized cause.
- **CALLS:** F42/F45; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, snapshot3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestKeepalivedStatusContract + pinned no-secret fixture. **INTEGRATION TESTS:** A18/A19/A22–A27 in M5_ACCEPTANCE_MATRIX.

### B4New — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func NewIPVSBackend(o Options) (*IPVSBackend,error)`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Validate immutable dependencies/profile; no IO.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Constructor: dependency/enum error only; generation/digest binding and bounded input.
- **SIDE EFFECTS:** No effect.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSNewContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B4Prepare — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *IPVSBackend) Prepare(ctx context.Context,c domain.Config,g networkservices.Generation) (networkservices.Prepared,error)`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Render, resolve secrets, stage protected files, run native syntax validation.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Reject disabled mismatches, unsupported profile, secret or native syntax error before runtime mutation; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Staging files and syntax child process only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSPrepareContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B4Snapshot — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *IPVSBackend) Snapshot(ctx context.Context) (networkservices.Snapshot,error)`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Capture previous accepted desired artifact references/enablement and installed generation, not transient sessions/RIB.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Missing/tampered artifact or foreign active config => conflict; do not adopt silently; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read manifest and bounded verification.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSSnapshotContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B4Apply — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *IPVSBackend) Apply(ctx context.Context,p networkservices.Prepared) (networkservices.ApplyReceipt,error)`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Publish and reload dedicated checker-only Keepalived unit; do not program IPVS via a second writer.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** Native exit/timeout/partial apply => typed phase receipt/error; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only; WAL already durable.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Reload previous virtual-server desired configuration; no live connection-table replay.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSApplyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B4Verify — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *IPVSBackend) Verify(ctx context.Context,p networkservices.Prepared) error`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Exact configured service/real-server tuples present via netlink; backend health distinct.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Mismatch/unreachable/schema failure; no invented success from empty state; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only installed-state checks.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSVerifyContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B4Restore — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *IPVSBackend) Restore(ctx context.Context,s networkservices.Snapshot) error`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Reload previous virtual-server desired configuration; no live connection-table replay.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Coordinator owns activation; affected service scopes fenced; valid WAL.
- **VALIDATION:** CompensationFailed if old desired cannot be verified; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Selected daemon/artifact only.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** Failure retains journal and fence; do not loop indefinitely.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSRestoreContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B4Status — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *IPVSBackend) Status(ctx context.Context) (domain.IPVSStatus,error)`.
- **FILE:** `internal/loadbalancer/ipvs/backend.go`.
- **RESPONSIBILITY:** Decode structured runtime observation and label applied/configured/operational independently.
- **INPUT:** Typed arguments in signature; Options{Runner,ServiceManager,ArtifactStore,SecretResolver,KernelObserver,Clock,Profile}. **OUTPUT:** Typed signature output; no vendor types outside adapter.
- **PRECONDITIONS:** Supported profile; no mutable Config aliases.
- **VALIDATION:** Unreachable/stale/unsupported JSON; required fields must not default to healthy; generation/digest binding and bounded input.
- **SIDE EFFECTS:** Read-only vendor interface.
- **ERROR CONDITIONS:** AdapterError includes subsystem=ipvs (OPTIONAL T32), phase, stable code, retryability and sanitized cause.
- **CALLS:** F60/F61; netserviceexec Runner/ServiceManager; ArtifactStore; no Config.Manager/session mutation. **CALLED BY:** NetworkServicesCoordinator; no API direct calls.
- **ROLLBACK BEHAVIOR:** No authority to roll back Running; coordinator chooses old/target.
- **TIMEOUT/CANCELLATION:** syntax10s, reload20s, netlink3s; parent ctx wins; disabled no-op before IO.
- **CONCURRENCY NOTES:** Mutations serialized by coordinator; per-backend control mutex; status produces immutable copy without session lock.
- **UNIT TESTS:** TestIPVSStatusContract + pinned no-secret fixture. **INTEGRATION TESTS:** A30 in M5_ACCEPTANCE_MATRIX.

### B1Reserve — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (b *FRRBackend) Reserve(ctx context.Context, claims []resources.RouteClaim) error`.
- **FILE:** `internal/routing/frr/reservation.go`.
- **RESPONSIBILITY:** Publish union(old,target) exact-prefix ownership filter and confirm dynamic withdrawal before M1 route mutation.
- **INPUT:** Validated owned static claims plus protected/reachable prefix constraints. **OUTPUT:** Error or verified reservation generation.
- **PRECONDITIONS:** WAL durable; no M1 replace/delete yet; no competing manual vtysh writer.
- **VALIDATION:** Exact prefix union; default route exact /0 must not suppress all more-specific routes; same rule for OSPF/BGP.
- **SIDE EFFECTS:** Reload generated zebra filters; only daemon-owned routes may withdraw.
- **ERROR CONDITIONS:** Unsupported filter, timeout waiting withdrawal, foreign collision => stop before M1 change.
- **CALLS:** F27/F28; Runner; netlink observer. **CALLED BY:** Coordinator.Apply/compensation before legacy Reconcile.
- **ROLLBACK BEHAVIOR:** Apply prior union/reservation before reverse M1 plan, narrow only after old static restored.
- **TIMEOUT/CANCELLATION:** 30s upper bound within activation/compensation budget; targeted polling200ms.
- **CONCURRENCY NOTES:** Same FRR control mutex; background reconcile excluded by in-flight flag.
- **UNIT TESTS:** TestReservationUnionBeforeStaticWrite; TestExactDefaultReservation. **INTEGRATION TESTS:** A04/A05/A07/A23/A24 in M5_ACCEPTANCE_MATRIX.

### F62 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (s *ArtifactStore) Accepted(ctx context.Context, subsystem string) (networkservices.Snapshot,error); func (s *ArtifactStore) Accept(ctx context.Context,p networkservices.Prepared) error`.
- **FILE:** `internal/networkservices/state/artifacts.go`.
- **RESPONSIBILITY:** Separate last accepted artifact from active but not yet committed generation.
- **INPUT:** Fixed subsystem or Prepared with generation/digest. **OUTPUT:** Detached accepted Snapshot / error.
- **PRECONDITIONS:** Accept called only after Running+runtime generation verified in Finalize.
- **VALIDATION:** Hash-bound existing artifact; no invented file path.
- **SIDE EFFECTS:** Accepted read-only; Accept atomic manifest update.
- **ERROR CONDITIONS:** Disk/fsync/permission/hash mismatch; keep WAL.
- **CALLS:** Atomic file primitives. **CALLED BY:** Backend.Snapshot; Coordinator.Finalize.
- **ROLLBACK BEHAVIOR:** Restore previous accepted reference on compensated activation; recovery reads authoritative Running to disambiguate.
- **TIMEOUT/CANCELLATION:** 5s bound.
- **CONCURRENCY NOTES:** Serialized manifest writer; immutable read.
- **UNIT TESTS:** TestActiveArtifactIsNotAcceptedUntilFinalize. **INTEGRATION TESTS:** A23/A24/A26 in M5_ACCEPTANCE_MATRIX.

### F63 — PROPOSED NEW

- **FUNCTION / SIGNATURE:** `func (p *Probe) Inspect(ctx context.Context, profile Profile) (domain.NetworkServicesCapabilities,error)`.
- **FILE:** `internal/networkservices/capabilities/probe.go`.
- **RESPONSIBILITY:** Verify installed immutable tools/schema/paths and build a cached capability report before feature enablement.
- **INPUT:** Local administrator installed profile, fixed synthetic fixtures. **OUTPUT:** Per-feature capability flags, versions/profile digest, missing reasons; readiness false until acceptance.
- **PRECONDITIONS:** No Candidate-supplied program/path; no feature is enabled as a side effect.
- **VALIDATION:** Binary hashes/profile schema, native no-effect checks and required permissions; fresh socket bind-close; bounded samples only.
- **SIDE EFFECTS:** Read files; no-secret syntax subprocesses; bind then close an unconnected TCP socket; no routes/listeners/daemons started.
- **ERROR CONDITIONS:** Unsupported profile, missing binary/schema, permission, timeout; unavailable reason stays explicit.
- **CALLS:** Runner, ServiceManager.Inspect, KernelObserver; no Ensure(start). **CALLED BY:** Explicit engine startup preflight / Coordinator.Prepare for enabled feature; T01 script.
- **ROLLBACK BEHAVIOR:** None; staged test files removed by bounded own-path cleanup.
- **TIMEOUT/CANCELLATION:** 10s per component; aggregate30s at startup, activation shares120s total.
- **CONCURRENCY NOTES:** One refresh per profile hash; status reads immutable cached report.
- **UNIT TESTS:** TestProbeHasNoRuntimeMutation; TestProbeRejectsProfileDrift. **INTEGRATION TESTS:** A00/A20/A27 in M5_ACCEPTANCE_MATRIX.

## Script entry-point contracts

| FILE / function or action | Input/output | Preconditions / validation | Side effects / errors | Calls / caller | Rollback, timeout and concurrency | Tests |
|---|---|---|---|---|---|---|
| install-m5-linux.sh main | fixed flags --check/--install/--uninstall, local manifest | root on supported OS; no foreign service/config collision; profile hashes match | Install only explicitly selected packages/units; no feature auto-enable; fail before overwriting foreign files | packaging commands; local admin | Manifest restore; no recursive deletion outside verified own dirs; one flock; apt timeout300s | A00/A27/A32 |
| verify-m5-linux.sh main | output directory; JSON/text report and nonzero on failed proof | read-only profile/units/caps; bounded queries | No dataplane mutation, no package install | fixed tools; T01/operator | 60s aggregate; no repeated retry; safe concurrent read | A00/A27 |
| lab.sh save/apply/restore | baseline/case file/expected version; API response+hashes | explicit lab flag; known gateway; keep MGMT; auth not logged; refuse stale version | Candidate and normal commit only; API failure stops subsequent traffic test | curl/jq; run-case | trap uses saved baseline via new commit; 210s HTTP; serial per gateway | A01–A32 |
| run-case.sh Axx | one case ID, nodes env, artifact dir; PASS/FAIL/BLOCKED | prerequisite fixture/profile/disk/console check | only commands listed in Axx; no unbounded daemon logs | lab/collect/traffic; operator | trap scoped faults first then baseline restore; case bound in recipe; no parallel mutations | Self-test fake SSH/API + all applicable Axx |
| collect.sh snapshot | case phase and directory; UTC, boot/config/tool/route/service/pcap records | exclude keys/tokens/private artifacts | read-only bounded output, hash manifest after completion | ip/nft scoped table/journalctl units/since/status API | each command10s, pcap60s; no full ruleset/system journal | A00–A32 |
| traffic.py serve/http/tcp/hold/client | explicit address/port/mode/backend ID/count; JSONL sequence/result | lab endpoints only, bounded connections/body | test sockets/traffic only; health controlled through local process file | Python stdlib; run-case/operator | deadline, PID-specific stop, no killall; per-test process | A02/A10–A19/A30 |
| fault-runner.sh main | fixed underlying argv and root-owned one-shot fault marker | isolated VM + lab profile, no production service path | selected phase exits chosen status or delays; other commands exec real fixed tool | adapter Runner; lab harness | marker removed in trap; bound5s; no HTTP fault trigger; serialized | A20–A24/A27 |

## Planning checkpoint

FINDINGS: file/function manifest covers contract, orchestration, each adapter,
API/UI, packaging and test artifacts without modifying existing traffic algorithms.
DECISIONS: no production deletions; legacy edits limited to compatibility matrix;
new vendor syntax is isolated in adapter packages.
UNRESOLVED: T00/T01 measured baseline/capabilities; optional IPVS netlink binding
selection belongs to T32 and cannot block core.
FILES ALREADY INSPECTED: CURRENT_ARCHITECTURE_MAP plus exact signatures cited above.
SOURCES ALREADY INSPECTED: SOURCE_NOTES ledger; no repeated source discovery needed.
NEXT TARGETS: execute tasks in dependency order only after separate code instruction.
