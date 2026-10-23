# M5 coding tasks

**PROPOSED work only.** Task numbers are stable identifiers, not permission to
skip dependencies or implement optional work. A task is one reviewable contract
change; split into suffixes (e.g. T07a/T07b) if its diff becomes too large, keeping
all listed gates. Initial integration is disabled until required dependencies,
package capability proof and live acceptance are complete.

Every task inherits: preserve the T00 dirty baseline; run its new tests, tests of
directly affected modules, and selected M1–M4 regressions from the compatibility
matrix. For kernel/daemon claims run its Axx cases before calling the behavior
accepted. Unit-only intermediate work stays READY_FOR_VM. No tests or VM commands
were run while writing this plan.

Canonical field/default/adapter contract is [CODE_CONTRACTS](M5_CODE_CONTRACTS.md).
Function IDs and file classifications are [FILE_IMPLEMENTATION_PLAN](M5_FILE_IMPLEMENTATION_PLAN.md).
Timeout/privilege/installer details are [DEPENDENCY_AND_PACKAGING](M5_DEPENDENCY_AND_PACKAGING.md).
Axx command recipes and verdict rules are [ACCEPTANCE_MATRIX](M5_ACCEPTANCE_MATRIX.md).
Rxx mitigations are [RISK_REGISTER](M5_RISK_REGISTER.md).

## Dependency order

T00 -> T01/T02 -> T03/T04 -> T05 -> T06 -> T07.
Then T09 -> T10/T11 -> T12 -> T13; T14 is independent after T03;
T15 -> T16; T17 -> T18 -> T19 and T20 -> T21.
T22 -> T23 -> T24 supplies management views. T25 packages completed adapters.
**T08 is assembly after its adapter/packaging dependencies, not the eighth action.**
T26 -> T27 -> T28 -> T29 -> T30 is core live acceptance/release.
T31 -> T32 -> T33 is optional IPVS after core. VRF/PBR/conntrackd have no core coding task.

## Platform and packaging requirements

T25 creates `deploy/network-services/ngfw-engine.service.d/network-services.conf`
and leaves the base engine service unchanged. T04 includes lazy capability Probe F63 and process platform
helpers; T05/T15/T16/optional T32 include their non-Linux unsupported counterparts
from the file manifest. T16/T20 may promote existing x/sys to a direct dependency
for socket/CLOCK_BOOTTIME calls; no version upgrade is implied. T26's negative
control-packet generation adds python3-scapy only to the test sender VM.

## Task cards

### T00 — Freeze the existing working-tree baseline

- **TITLE / GOAL:** Freeze the existing working-tree baseline. Record current M1–M4 behavior and uncommitted M4 file hashes.
- **WHY:** A later agent must not confuse current unfinished M4 work with M5 regressions.
- **DEPENDENCIES:** None; specification approved scope only.
- **FILES:** `docs/m5/M5_EXECUTION_MAP.md` (planning/evidence document). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Record HEAD, git diff --stat and SHA-256 of already dirty files; preserve their contents.
  2. Record focused existing test names/status and acceptance evidence references.
  3. Mark baseline failures without changing source; select disposable Ubuntu lab clone.
- **UNIT TESTS:** Selected legacy tests from COMPATIBILITY_MATRIX; no new feature tests.
- **INTEGRATION TESTS:** No runtime changes.
- **VM TESTS:** A00 baseline only.
- **FAILURE TESTS:** Dirty file/unsupported environment => record blocker, do not reset.
- **DEFINITION OF DONE:** Baseline identifiable; no source reverted; execution map lists actual test baseline; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Documentation-only checkpoint; no runtime rollback.
- **RISKS:** R01.

### T01 — Verify package and sandbox capabilities

- **TITLE / GOAL:** Verify package and sandbox capabilities. Create a reproducible version/profile proof before enabling any feature.
- **WHY:** Tool syntax/JSON/permissions must not be inferred from marketing feature lists.
- **DEPENDENCIES:** T00.
- **FILES:** `deploy/network-services/profile.example.json` (NEW_M5_FILE); `scripts/verify-m5-linux.sh` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Script entry points only here; Go Probe F63 is implemented at T04 after its typed contracts and Runner exist.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement no-mutation profile probe and read-only verifier.
  2. Check tool family/hash, no-effect validators, structured status schemas and per-process caps on disposable lab.
  3. Prove fresh TCP device bind and private Keepalived JSON dump path; check protocol196 reservation.
- **UNIT TESTS:** Verifier script syntax, fixed tool allowlist and temporary-file cleanup checks; Go Probe tests are T04.
- **INTEGRATION TESTS:** Fake Runner returns truncated/malformed JSON; refuse unsupported capability.
- **VM TESTS:** A00/A27 capability phase.
- **FAILURE TESTS:** Missing FRR/HAPROXY/Keepalived, EPERM, unknown JSON => unavailable without starting units.
- **DEFINITION OF DONE:** Versioned manifest and required-key fixtures; no feature enabled when proof fails; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Remove only own temporary probe files; keep M1 service state.
- **RISKS:** R03/R04/R16.

### T02 — Add optional shared model, clone and interfaces

- **TITLE / GOAL:** Add optional shared model, clone and interfaces. Introduce exact versioned config/status/adapter contracts.
- **WHY:** Existing Config and clones need to carry M5 without changing legacy serialization.
- **DEPENDENCIES:** T00.
- **FILES:** `internal/domain/network_services.go` (NEW_M5_FILE); `internal/domain/types.go` (SHARED_CONTRACT); `internal/domain/routing.go` (NEW_M5_FILE); `internal/domain/routing_policy.go` (NEW_M5_FILE); `internal/domain/wan.go` (NEW_M5_FILE); `internal/domain/loadbalancer.go` (NEW_M5_FILE); `internal/domain/ha.go` (NEW_M5_FILE); `internal/domain/network_services_status.go` (NEW_M5_FILE); `internal/networkservices/contracts.go` (NEW_M5_FILE); `internal/networkservices/resources/types.go` (NEW_M5_FILE); `internal/routing/backend.go` (NEW_M5_FILE); `internal/loadbalancer/backend.go` (NEW_M5_FILE); `internal/ha/backend.go` (NEW_M5_FILE); `internal/wan/backend.go` (NEW_M5_FILE); `internal/config/manager.go` (M1_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F01, F02, F46.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Add optional root pointer and supported v1 fields only; future keys reject.
  2. Add deep clone delegate to cloneConfig; preserve nil.
  3. Define leaf DTO/interfaces and typed status union; no adapter construction or IO.
- **UNIT TESTS:** Strict decode, old JSON golden, deep pointer/slice isolation, nil disabled.
- **INTEGRATION TESTS:** Manager Candidate/rollback serialization using old fixtures.
- **VM TESTS:** A00/A01 schema phase.
- **FAILURE TESTS:** Unknown fields/schema/types rejected without Candidate change.
- **DEFINITION OF DONE:** All old configs still load; no vendor syntax or import cycle; no old Interface/Route field changes; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Revert only model changes while never enabled; no data migration.
- **RISKS:** R01/R05.

### T03 — Implement pure M5 validation and conflict checks

- **TITLE / GOAL:** Implement pure M5 validation and conflict checks. Reject unsupported/unsafe config before any tool invocation.
- **WHY:** Rendering cannot substitute for model and cross-resource validation.
- **DEPENDENCIES:** T02.
- **FILES:** `internal/config/network_services.go` (NEW_M5_FILE); `internal/config/manager.go` (M1_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F03, F04, F05, F06, F07, F08, F09, F10.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement exact field/default/cross-field constraints from CODE_CONTRACTS.
  2. Build interface/zone/ref indexes once per validation, deterministic path errors.
  3. Wire Validator.Validate delegate and preserve legacy error text/order.
- **UNIT TESTS:** Boundary/reference/property cases for every supported field family.
- **INTEGRATION TESTS:** Candidate reject is transactional; spy Runner remains unused.
- **VM TESTS:** A01/A13/A17.
- **FAILURE TESTS:** M4+LB both directions, overlap VIP/static IP/listeners/NAT, invalid routes/prefixes.
- **DEFINITION OF DONE:** Precise errors; no normalized Candidate side effect; direct config tests pass; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Remove delegate after feature remains disabled.
- **RISKS:** R02/R06/R07/R09.

### T04 — Build bounded execution, artifact and secret adapters

- **TITLE / GOAL:** Build bounded execution, artifact and secret adapters. Centralize command/service/file operations and secret handling.
- **WHY:** No vendor exec or unsafe writes can leak into core/API.
- **DEPENDENCIES:** T01, T02.
- **FILES:** `internal/netserviceexec/runner.go` (NEW_M5_FILE); `internal/netserviceexec/service.go` (NEW_M5_FILE); `internal/netserviceexec/secrets.go` (NEW_M5_FILE); `internal/networkservices/state/artifacts.go` (NEW_M5_FILE); `internal/networkservices/capabilities/probe.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F11, F12, F13, F14, F62, F63. Include `internal/networkservices/capabilities/probe.go` and its test from the file manifest.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement allowlisted profile ToolID/ServiceID with process-group cancellation and capped output.
  2. Implement atomic staged/active/accepted artifact manifests and retention.
  3. Resolve name@version secrets with owner/mode/no-symlink/purpose checks.
- **UNIT TESTS:** Runner cancellation/redaction; fsync/rename faults; X509 key mismatch; no path traversal.
- **INTEGRATION TESTS:** Fake daemon/profile and fault filesystem tests.
- **VM TESTS:** A20–A23/A27.
- **FAILURE TESTS:** Child hangs, command unavailable, disk full, permission denied, output overflow.
- **DEFINITION OF DONE:** No shell invocation/user command path; redacted errors; artifact accepted != active until finalize; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** No runtime enabled; remove own unreferenced staging only.
- **RISKS:** R03/R08/R11.

### T05 — Add kernel resource observation and provenance DTOs

- **TITLE / GOAL:** Add kernel resource observation and provenance DTOs. Classify exact static/dynamic/connected/foreign resources without mutation.
- **WHY:** Protocol labels alone do not prove ownership.
- **DEPENDENCIES:** T02, T04.
- **FILES:** `internal/networkservices/resources/observer_linux.go` (NEW_M5_FILE); `internal/networkservices/resources/types.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F16.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Decode pinned netlink route/address/link snapshots with full keys and multipath.
  2. Use manifest+exact kernel match for SENTINEL claims; label unknown as FOREIGN.
  3. Bound retries on interrupted dumps; expose observation timestamps.
- **UNIT TESTS:** Unknown protocol, duplicate prefix/different metric/table/nexthop, interrupted dump.
- **INTEGRATION TESTS:** Fake netlink snapshots covering FRR and VRRP VIP.
- **VM TESTS:** A04/A05.
- **FAILURE TESTS:** Partial dump must fail before apply; unsupported attrs never collapse identity.
- **DEFINITION OF DONE:** Observer read-only; no blanket route/address enumeration deletion; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Remove observer only, no kernel change.
- **RISKS:** R02/R04.

### T06 — Protect M1 mutations and expose exact rollback snapshot

- **TITLE / GOAL:** Protect M1 mutations and expose exact rollback snapshot. Add the minimal ownership hook and detached activation snapshot accessor.
- **WHY:** Current route replace/link deletion can affect external-owned resources.
- **DEPENDENCIES:** T03, T05.
- **FILES:** `internal/networkservices/ownership/guard.go` (NEW_M5_FILE); `internal/dataplane/linux.go` (M1_FILE); `internal/dataplane/controller_m5.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F17, F18, F19.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Attach typed RouteMutation to planned route operations; nil hook preserves existing argv/order.
  2. Guard forward and reverse plans, exact adopt/tag proto196, reject foreign key/link dependency.
  3. Add CurrentActivationSnapshot clone accessor without altering controller activation.
- **UNIT TESTS:** Existing Linux plan/reverse/snapshot tests plus ownership regressions.
- **INTEGRATION TESTS:** Injected route write failure restores only owned state.
- **VM TESTS:** A04/A05/A23.
- **FAILURE TESTS:** Ambiguous legacy adoption or missing reservation => zero commands.
- **DEFINITION OF DONE:** M1 old path identical when M5 off; no FRR import in dataplane; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Withdraw FRR deps, restore old static metadata via normal disable plan, then remove hook.
- **RISKS:** R02/R10.

### T07 — Compose the outer M5 activation journal

- **TITLE / GOAL:** Compose the outer M5 activation journal. Implement recoverable staged multi-daemon changes using existing manager callbacks.
- **WHY:** There is no atomic transaction across Linux and all daemons.
- **DEPENDENCIES:** T04, T06.
- **FILES:** `internal/networkservices/state/journal.go` (NEW_M5_FILE); `internal/engine/network_services.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F15, F20, F21, F22, F23, F24, F25, F26.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement WAL phases/digests/receipts, exact old inner snapshot, leases and active/accepted artifacts.
  2. Use fake backends to implement ordered apply/reverse compensation and manager repeated old-config callback.
  3. Use per-method mutex + in-flight flag; preserve existing Commit versus Rollback inspection-gate order.
  4. Implement startup Running old/target resolution and RECOVERY_REQUIRED fence.
- **UNIT TESTS:** Crash-at-each-phase, cancel, duplicate apply/finalize, post-publish recovery newer generation.
- **INTEGRATION TESTS:** Existing RuntimeServiceAdapter stage-order/rollback tests with coordinator fakes.
- **VM TESTS:** A23/A24 simulated first; live after T28.
- **FAILURE TESTS:** Apply/compensation/fsync failure and corrupt WAL.
- **DEFINITION OF DONE:** No hidden commit publisher; no recomputed old M2 epoch; recovery state stays observable; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Disable coordinator wiring; retain journal if any transaction pending; never delete it to force green.
- **RISKS:** R10/R11/R12.

### T08 — Wire engine construction and startup recovery

- **TITLE / GOAL:** Wire engine construction and startup recovery. Connect completed adapters to existing engine callbacks.
- **WHY:** The existing composition root owns initialization and authority.
- **DEPENDENCIES:** T07, T13, T14, T16, T17, T19, T21, T25, T22.
- **FILES:** `cmd/ngfw-engine/network_services.go` (NEW_M5_FILE); `cmd/ngfw-engine/main.go` (SHARED_CONTRACT). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F52, F53.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Construct disabled coordinator without IO for absent/steady-disabled M5.
  2. Run outer recovery before ordinary dataplane reconcile/workers; preserve existing epoch/M3/M4 wiring.
  3. Compose preflight/apply/finalize; add independent bounded reconcile/status/readiness workers.
  4. Keep existing AfterActivate M3 hook and status errors independent of API lifecycle.
- **UNIT TESTS:** Disabled factory no IO; existing activation order; worker shutdown.
- **INTEGRATION TESTS:** Subprocess startup old/target WAL fixtures, enabled/disabled configs.
- **VM TESTS:** A00/A05/A23–A28.
- **FAILURE TESTS:** Daemon unavailable degrades only relevant M5; startup must not flush unrelated state.
- **DEFINITION OF DONE:** Engine owns all coordination; no API privilege increase; existing M4 local changes preserved; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Normal disable and journal-free proof before reverting composition.
- **RISKS:** R01/R10/R12.

### T09 — Implement routing policy, FRR foundation and reservations

- **TITLE / GOAL:** Implement routing policy, FRR foundation and reservations. Render deterministic FRR integrated config and protect M1 static prefixes.
- **WHY:** Static/dynamic coordination must exist before live routing can be enabled.
- **DEPENDENCIES:** T03, T04, T06.
- **FILES:** `internal/routingpolicy/compile.go` (NEW_M5_FILE); `internal/routing/frr/render.go` (NEW_M5_FILE); `internal/routing/frr/backend.go` (NEW_M5_FILE); `internal/routing/frr/reservation.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F27, F28, B1New, B1Prepare, B1Snapshot, B1Apply, B1Verify, B1Restore, B1Reserve.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Compile user prefix/maps intersected with generated protected and ownership constraints.
  2. Implement staged syntax check/reload and config-diff verification.
  3. Install union(old,target) reservation before M1 mutations; wait targeted withdrawal; narrow after.
  4. No staticd, write memory, broad route flush or learned-route snapshot restore.
- **UNIT TESTS:** Renderer determinism, guard order, exact /0 reservation, partial reload rollback.
- **INTEGRATION TESTS:** Pinned FRR syntax fixtures; fake status/provenance sequencing.
- **VM TESTS:** A04/A07/A20.
- **FAILURE TESTS:** Native invalid generated config; routing daemon unavailable; dynamic collision.
- **DEFINITION OF DONE:** No static replacement races in VM ownership case; mutations hidden until foundation enabled; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Reload old FRR artifact/union and restore only M1 claims.
- **RISKS:** R02/R04/R10.

### T10 — Render OSPFv2 and filtered redistribution

- **TITLE / GOAL:** Render OSPFv2 and filtered redistribution. Support small explicit OSPF interface model.
- **WHY:** Reuse ospfd protocol runtime with passive-by-default interfaces.
- **DEPENDENCIES:** T09.
- **FILES:** `internal/routing/frr/ospf.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F29.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Render interface/area/cost/network-type/auth/timers.
  2. Bind router ID and optional BFD reference; default originate explicit.
  3. Filter redistribution to permitted owned static/connected prefixes.
- **UNIT TESTS:** OSPF golden syntax+negative auth/passive/default tests.
- **INTEGRATION TESTS:** FRR native syntax gate on each supported combination.
- **VM TESTS:** A02/A03/A07.
- **FAILURE TESTS:** Peer loss/restart and forbidden prefix advertisement.
- **DEFINITION OF DONE:** Full adjacency/route/withdraw/recovery proved after T26; no IPv6 claim; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Normal disable OSPF; retain baseline static/firewall.
- **RISKS:** R04/R06.

### T11 — Render BGP and AF routing policy

- **TITLE / GOAL:** Render BGP and AF routing policy. Support single-hop IPv4 BGP with mandatory policy.
- **WHY:** Prevent route leaks while demonstrating real advertisements and ECMP.
- **DEPENDENCIES:** T09.
- **FILES:** `internal/routing/frr/bgp.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F30.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Render ASN/router ID/neighbor/source/shutdown and IPv4 AF.
  2. Require import/export route maps and max-prefix; network origin requires exact valid route.
  3. Render localpref/MED/local AS prepend/max-paths without exposing arbitrary FRR grammar.
- **UNIT TESTS:** BGP/policy golden; import/export context misuse; duplicate neighbor.
- **INTEGRATION TESTS:** Native syntax/diff fixtures.
- **VM TESTS:** A06–A08.
- **FAILURE TESTS:** Max-prefix overrun, wrong ASN/auth, disallowed received/advertised routes.
- **DEFINITION OF DONE:** No automatic advertise-all; operational DOWN distinct from config-applied; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Reload previous BGP/policy config; reconverge.
- **RISKS:** R04/R06/R13.

### T12 — Normalize FRR operational status

- **TITLE / GOAL:** Normalize FRR operational status. Expose neighbors/routes/BFD in SENTINEL DTOs.
- **WHY:** Human CLI parsing and empty healthy defaults are unacceptable.
- **DEPENDENCIES:** T10, T11.
- **FILES:** `internal/routing/frr/status.go` (NEW_M5_FILE); `internal/routing/frr/backend.go` (NEW_M5_FILE); `internal/routing/frr/testdata/status.json` (NEW_M5_FILE); `internal/routing/frr/testdata/expected.conf` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F32, B1Status.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement pinned JSON field decoder and bounded query allowlist.
  2. Merge kernel installed route/provenance with FRR selected state; keep distinctions.
  3. Nullable received routes when not retained; no hidden soft-reconfiguration memory allocation.
- **UNIT TESTS:** Pinned JSON missing/additive/wrong-type/overflow fixtures.
- **INTEGRATION TESTS:** Status pagination/generation and daemon unavailable fixtures.
- **VM TESTS:** A02/A06/A09/A27.
- **FAILURE TESTS:** Schema drift => unavailable with reason, no false UP.
- **DEFINITION OF DONE:** No public endpoint triggers unrestricted vtysh output; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Revert status consumer only; forwarding unaffected.
- **RISKS:** R04/R16.

### T13 — Add FRR BFD profiles and peer binding

- **TITLE / GOAL:** Add FRR BFD profiles and peer binding. Measure fast failure detection driving routing reaction.
- **WHY:** Probe observer must not become another route writer.
- **DEPENDENCIES:** T10, T11, T12.
- **FILES:** `internal/routing/frr/bfd.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F31.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Render BFD timers/multiplier/local address and peer profile.
  2. Connect BGP/OSPF references; echo/multihop excluded.
  3. Expose negotiated timing/state via existing status decoder.
- **UNIT TESTS:** Timer bounds, dangling references, render golden.
- **INTEGRATION TESTS:** FRR syntax/profile integration.
- **VM TESTS:** A09.
- **FAILURE TESTS:** Drop peer traffic with carrier still up; verify BFD and route withdrawal.
- **DEFINITION OF DONE:** Configured timer is not labelled guaranteed convergence; VM records actual bound; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Disable BFD references/profiles using same transaction.
- **RISKS:** R13.

### T14 — Extend zone attribution for routed prefixes

- **TITLE / GOAL:** Extend zone attribution for routed prefixes. Keep M2/M3 inference explicit under dynamic routing.
- **WHY:** Current connectivity.Compile only knows connected/static destinations.
- **DEPENDENCIES:** T03.
- **FILES:** `internal/connectivity/network_services.go` (NEW_M5_FILE); `internal/connectivity/program.go` (M2_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F33, F34.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Compile only configured reachable-prefix to declared-zone mappings.
  2. Reject cross-zone/protected overlap; same-zone ECMP.
  3. Do not read live RIB or change session identity/ct marks.
- **UNIT TESTS:** Explicit/ambiguous/longest-prefix/disabled identical program.
- **INTEGRATION TESTS:** Existing M2 epoch and M3 original/NAT-alias resolver tests.
- **VM TESTS:** A02/A10/A28.
- **FAILURE TESTS:** Unknown/unapproved learned route cannot create a zone.
- **DEFINITION OF DONE:** No M3/M4 algorithm changes; existing generation logic retained; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Disable routes/M5 prefixes then remove helper call.
- **RISKS:** R06/R07.

### T15 — Add scoped ECMP sysctl leases

- **TITLE / GOAL:** Add scoped ECMP sysctl leases. Support Linux per-flow ECMP with reversible host settings.
- **WHY:** FRR path selection needs an explicit kernel/return-path contract.
- **DEPENDENCIES:** T07, T11, T14.
- **FILES:** `internal/wan/lease_linux.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F35.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Record hash/rp_filter old values in WAL before write.
  2. Apply only participant data-interface leases; protect MGMT and foreign changes.
  3. Verify readback and cleanup on disable/recovery.
- **UNIT TESTS:** Lease restoration and foreign-drift refusal.
- **INTEGRATION TESTS:** Crash after sysctl write fixture.
- **VM TESTS:** A10/A11/A23/A24.
- **FAILURE TESTS:** Permission denied/effective rp_filter incompatibility => reject without global workaround.
- **DEFINITION OF DONE:** No nft mark/ip rule writer; each sysctl has owner and restoration; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Compare-and-restore owned lease; retain conflict evidence.
- **RISKS:** R07/R10.

### T16 — Observe routed WAN failover and bounded health probes

- **TITLE / GOAL:** Observe routed WAN failover and bounded health probes. Combine FRR/BFD/FIB/probe data without selecting routes.
- **WHY:** Avoid reproducing VyOS WAN-LB custom table conflict.
- **DEPENDENCIES:** T12, T13, T15.
- **FILES:** `internal/wan/observer.go` (NEW_M5_FILE); `internal/wan/health/tcp.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F36, F37.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement read-only WANBackend and device/source-bound TCP probe.
  2. Debounce rise/fall counters and stop old-generation probes.
  3. Label FRR selection versus diagnostic probe result; no routing action on probe timeout.
- **UNIT TESTS:** Socket bind/cancel/timeout; no route/mark writes.
- **INTEGRATION TESTS:** Synthetic FRR/kernel snapshots plus real source-bound TCP service.
- **VM TESTS:** A10–A13.
- **FAILURE TESTS:** EPERM stops unsupported probe; DOWN does not remove routes.
- **DEFINITION OF DONE:** New/established session effects exposed honestly; no NAT stickiness claim; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Stop workers and restore owned ECMP leases via coordinator.
- **RISKS:** R07/R13.

### T17 — Add scoped engine admission for local services/protocols

- **TITLE / GOAL:** Add scoped engine admission for local services/protocols. Protect control-plane and HAProxy local packet paths.
- **WHY:** Legacy forwarded security policies are not local-socket authorization.
- **DEPENDENCIES:** T03, T04, T07.
- **FILES:** `internal/networkservices/nftguard/render.go` (NEW_M5_FILE); `internal/networkservices/nftguard/apply.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F38, F39.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Render exact M5 INPUT scopes for BGP/OSPF/BFD/VRRP and LB listeners.
  2. Render dedicated LB UID backend/check/reply OUTPUT constraints.
  3. Atomically replace only inet ngfw_m5_services; close changed scopes until verification.
  4. Permit no bypass of other base chains and preserve unrelated traffic.
- **UNIT TESTS:** Unauthorized source, TTL, port, reply direction, disabled scope tests.
- **INTEGRATION TESTS:** nft native syntax and scoped table rollback fixtures.
- **VM TESTS:** A17/A23/A27/A29.
- **FAILURE TESTS:** Guard apply failure prevents listener/daemon exposure; other table hash unchanged.
- **DEFINITION OF DONE:** No broad accept/flush; no modifications to existing M1 compiler; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Restore previous guard atomically after stopping newly introduced listeners.
- **RISKS:** R06/R09/R10.

### T18 — Render HAProxy delivery, algorithms and TLS

- **TITLE / GOAL:** Render HAProxy delivery, algorithms and TLS. Implement bounded service/backend model with verified TLS.
- **WHY:** Use mature delivery engine while keeping policy in SENTINEL.
- **DEPENDENCIES:** T03, T04, T17.
- **FILES:** `internal/loadbalancer/haproxy/render.go` (NEW_M5_FILE); `internal/loadbalancer/haproxy/backend.go` (NEW_M5_FILE); `internal/loadbalancer/haproxy/testdata/expected.cfg` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F40, B2New, B2Prepare.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Render TCP/HTTP and matching-mode pools/rr/leastconn/source.
  2. Render host/SNI/path-prefix backend selection and fixed same-host redirect.
  3. Resolve versioned certificate/CA refs; enforce backend hostname/CA verification and fixed TLS floor.
- **UNIT TESTS:** Golden modes/algorithm/rule order/escape; no verify-none; M4 conflict.
- **INTEGRATION TESTS:** HAProxy native -c for supported fixtures.
- **VM TESTS:** A14–A17.
- **FAILURE TESTS:** Invalid certificate/backend reference/generated config => no reload.
- **DEFINITION OF DONE:** No security ALLOW directives; no wildcard listener; no plaintext secrets in status; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Discard staged artifacts; existing accepted HAProxy continues.
- **RISKS:** R08/R09.

### T19 — Apply and observe HAProxy lifecycle

- **TITLE / GOAL:** Apply and observe HAProxy lifecycle. Implement bounded reload/drain/verification and JSON status.
- **WHY:** Reload success needs worker/listener evidence, not just exit0.
- **DEPENDENCIES:** T18.
- **FILES:** `internal/loadbalancer/haproxy/backend.go` (NEW_M5_FILE); `internal/loadbalancer/haproxy/status.go` (NEW_M5_FILE); `internal/loadbalancer/haproxy/testdata/stats.json` (NEW_M5_FILE); `internal/loadbalancer/haproxy/testdata/schema.json` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** B2Snapshot, B2Apply, B2Verify, B2Restore, B2Status, F41.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Publish target artifact then fixed unit soft reload with closed affected admission.
  2. Identify worker generation and bound drain at30s via fixed hard-stop-after profile.
  3. Decode per-service/backend/server state and counters; no generic socket passthrough.
- **UNIT TESTS:** Old/new worker fixtures, reload timeout, empty/malformed stats.
- **INTEGRATION TESTS:** Socket fake + master-worker integration on VM.
- **VM TESTS:** A14/A15/A16/A21.
- **FAILURE TESTS:** Reload partial failure, backend down, socket stale, old worker cannot drain.
- **DEFINITION OF DONE:** Accepted config and running worker agree; unavailability distinct from installation; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Reload previous artifact, preserve unrelated routing; cannot reconstruct ended client streams.
- **RISKS:** R08/R09/R10.

### T20 — Render VRRP and fixed unprivileged readiness helper

- **TITLE / GOAL:** Render VRRP and fixed unprivileged readiness helper. Make Keepalived sole VIP writer with engine readiness tracking.
- **WHY:** A stale engine process must not retain appliance MASTER indefinitely.
- **DEPENDENCIES:** T03, T04, T17.
- **FILES:** `internal/ha/keepalived/render.go` (NEW_M5_FILE); `internal/ha/readiness.go` (NEW_M5_FILE); `cmd/ngfw-ha-health/main.go` (NEW_M5_FILE); `internal/ha/keepalived/backend.go` (NEW_M5_FILE); `internal/ha/keepalived/testdata/expected.conf` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F42, F43, F44, B3New, B3Prepare.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Render unicast IPv4 groups/sync groups/BACKUP start/preempt options.
  2. Write boot/gen/age-bounded readiness and fixed script_user helper.
  3. Reject arbitrary scripts/static addresses/routes and collisions with M1.
- **UNIT TESTS:** Readiness age/boot/owner errors; VRRP syntax/passive preempt mapping.
- **INTEGRATION TESTS:** Native config-test; helper executed as ngfw-ha no capabilities.
- **VM TESTS:** A18/A19/A27.
- **FAILURE TESTS:** Engine crash freezes record; missing/unreadable helper fails closed.
- **DEFINITION OF DONE:** VIP never appears in M1 ordinary arrays; API is not readiness dependency; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Keep readiness false, restore previous desired groups, protocol elects.
- **RISKS:** R10/R14.

### T21 — Apply and observe Keepalived role/VIPs

- **TITLE / GOAL:** Apply and observe Keepalived role/VIPs. Add reload/status/FIFO snapshot reconciliation.
- **WHY:** Role is legitimate runtime state and cannot be reconciled to always-MASTER.
- **DEPENDENCIES:** T20.
- **FILES:** `internal/ha/keepalived/backend.go` (NEW_M5_FILE); `internal/ha/keepalived/status.go` (NEW_M5_FILE); `internal/ha/keepalived/testdata/state-v2.json` (NEW_M5_FILE); `internal/ha/keepalived/testdata/events.txt` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** B3Snapshot, B3Apply, B3Verify, B3Restore, B3Status, F45.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Use dedicated VRRP unit and protected structured FIFO+JSON v2 snapshot.
  2. Recover event loss through fresh bounded snapshot, correlate VIP kernel presence.
  3. Track last_transition only when known; stale source UNKNOWN.
- **UNIT TESTS:** FIFO/JSON cases, dropped event recovery, PID/file race.
- **INTEGRATION TESTS:** Private dump mount under exact package profile.
- **VM TESTS:** A18/A19/A22/A26.
- **FAILURE TESTS:** Daemon unavailable/stale dump/permission failure; no forced VIP ip addr commands.
- **DEFINITION OF DONE:** No duplicate address writer; MASTER/BACKUP proves observed state; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Reload accepted artifact; do not force role or touch ordinary addresses.
- **RISKS:** R04/R14.

### T22 — Expose optional IPC and read-only API status

- **TITLE / GOAL:** Expose optional IPC and read-only API status. Carry M5 capabilities/status without privileged API behavior.
- **WHY:** Existing IPC v3 and request budget need a narrow extension.
- **DEPENDENCIES:** T02, T07.
- **FILES:** `internal/engine/network_services_runtime.go` (NEW_M5_FILE); `internal/engineipc/network_services.go` (NEW_M5_FILE); `internal/engineipc/runtime.go` (SHARED_CONTRACT); `internal/management/network_services.go` (NEW_M5_FILE); `internal/management/api.go` (SHARED_CONTRACT); `internal/engine/runtime_service.go` (M2_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F47, F48, F49, F50, F51.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Add optional interface/status dispatch and cached capability negotiation.
  2. Reject nonnil M5 config to old engine; pair releases; retain legacy DTOs.
  3. Negotiate config-only190s IPC/200s HTTP deadline; auth/limit/cursor checks.
  4. Serve cache, not a new tool per poll; keep existing Candidate/commit/rollback.
- **UNIT TESTS:** Old engine, missing capability, auth, response limit/deadline, lost IPC reply.
- **INTEGRATION TESTS:** Existing IPC round-trip and API dependency audit.
- **VM TESTS:** A01/A25/A27.
- **FAILURE TESTS:** API restart/disconnect leaves engine transaction recoverable; no blind resubmit new ID.
- **DEFINITION OF DONE:** API remains no caps/no ip/nft exec; no second configuration authority; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Paired release revert after normal M5 disabled/config omitted.
- **RISKS:** R05/R12/R16.

### T23 — Add lossless typed Candidate editor

- **TITLE / GOAL:** Add lossless typed Candidate editor. Expose selected feature subset in existing management workflow.
- **WHY:** Operators should not need raw JSON for every new object.
- **DEPENDENCIES:** T03, T22.
- **FILES:** `web/src/networkServices/Editor.tsx` (NEW_M5_FILE); `web/src/runtimeData.ts` (SHARED_CONTRACT); `web/src/App.tsx` (SHARED_CONTRACT); `web/src/types.ts` (SHARED_CONTRACT); `web/src/navigation.ts` (SHARED_CONTRACT); `web/src/networkServices/types.ts` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F55, F57, F58.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Mirror supported DTOs and edit nested routing/WAN/LB/HA models.
  2. Use reference pickers and opaque secret ref strings, show DELIVERY_ONLY limitation.
  3. Preserve M1–M4 fields/unknown optional subtree through old editors; save Candidate then existing validate/commit.
- **UNIT TESTS:** UI field bounds/ref errors; full Candidate round-trip; old JSON nil state.
- **INTEGRATION TESTS:** Existing frontend build and targeted form tests.
- **VM TESTS:** A01/A17/A25 UI steps.
- **FAILURE TESTS:** Unsupported feature/capability cannot become silently enabled.
- **DEFINITION OF DONE:** No runtime vendor text in user fields; unsaved edits not overwritten by status poll; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Revert UI with read-only incompatible config if old backend is used.
- **RISKS:** R05/R09.

### T24 — Add typed live status views

- **TITLE / GOAL:** Add typed live status views. Make operational/configured/applied/stale visible separately.
- **WHY:** A green process alone does not prove route or backend availability.
- **DEPENDENCIES:** T12, T16, T19, T21, T22, T23.
- **FILES:** `web/src/networkServices/api.ts` (NEW_M5_FILE); `web/src/networkServices/Status.tsx` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F54, F56.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Add bounded routing/WAN/LB/HA tables and generation/source indicators.
  2. Abort old polling on unmount/gen change; handle cursor expiry.
  3. Show disabled/unavailable/DEGRADED reasons and no secret-bearing config.
- **UNIT TESTS:** Stale/disabled/empty/error/cursor/page tests.
- **INTEGRATION TESTS:** API fixture integration.
- **VM TESTS:** A06/A12/A18/A25.
- **FAILURE TESTS:** Daemon down and API timeout cannot remain green.
- **DEFINITION OF DONE:** One bounded poll per visible view; no direct admin socket access; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** UI revert only; engine unaffected.
- **RISKS:** R16.

### T25 — Package isolated units and manifests

- **TITLE / GOAL:** Package isolated units and manifests. Install a disabled, privilege-audited M5 appliance profile.
- **WHY:** Correct code cannot compensate for competing distro daemons or unsafe permissions.
- **DEPENDENCIES:** T01, T04, T19, T21.
- **FILES:** `deploy/network-services/ngfw-engine.service.d/network-services.conf` (NEW_M5_FILE); `deploy/network-services/frr.service.d/ngfw.conf` (NEW_M5_FILE); `deploy/network-services/frr-daemons.conf` (NEW_M5_FILE); `deploy/network-services/ngfw-haproxy.service` (NEW_M5_FILE); `deploy/network-services/ngfw-keepalived.service` (NEW_M5_FILE); `deploy/network-services/tmpfiles.conf` (NEW_M5_FILE); `deploy/network-services/profile.example.json` (NEW_M5_FILE); `scripts/install-m5-linux.sh` (NEW_M5_FILE); `scripts/verify-m5-linux.sh` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Implement collision-aware installer manifest/uninstall and disabled-by-default units.
  2. Audit FRR separate capability request; keep engine NET_ADMIN and API none.
  3. Install protected artifact/runtime/secret paths and Keepalived dump mount.
  4. Test rollback package pairing and no M5 unit autonomous boot.
- **UNIT TESTS:** Installer dry-run/path/collision and unit syntax checks.
- **INTEGRATION TESTS:** systemd-analyze verify; isolated unit privilege probes.
- **VM TESTS:** A00/A27/A32.
- **FAILURE TESTS:** Foreign service/config => refuse; incomplete package install => manifest recovery.
- **DEFINITION OF DONE:** Installed profile matches manifest; no secrets readable by API; reboot disabled no extra daemons; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Use installer manifest after normal disable; do not delete foreign package state.
- **RISKS:** R03/R08/R14.

### T26 — Implement and run routing/WAN VM acceptance

- **TITLE / GOAL:** Implement and run routing/WAN VM acceptance. Produce raw Ubuntu evidence for dynamic routing and ownership.
- **WHY:** Renderer tests cannot prove real kernel/FIB traffic behavior.
- **DEPENDENCIES:** T08, T22, T25.
- **FILES:** `tests/integration/m5/README.md` (NEW_M5_FILE); `tests/integration/m5/lab.sh` (NEW_M5_FILE); `tests/integration/m5/run-case.sh` (NEW_M5_FILE); `tests/integration/m5/collect.sh` (NEW_M5_FILE); `tests/integration/m5/traffic.py` (NEW_M5_FILE); `tests/integration/m5/peers/r1.conf` (NEW_M5_FILE); `tests/integration/m5/peers/r2.conf` (NEW_M5_FILE); `tests/integration/m5/fixtures/ospf.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/ospf-off.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/bgp.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/bgp-policy.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/bgp-max-prefix.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/bfd.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/ecmp.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/failover.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/wan-probe.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/invalid-m5.json` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Build sparse fixtures preserving saved baseline and MGMT.
  2. Run A02–A13/A29 in documented routed topology with return routes.
  3. Capture interface-specific pcaps/status/kernel hashes and exact failure timers.
  4. Restore original Candidate/Running config via commits and prove cleanup.
- **UNIT TESTS:** Harness fake API/SSH validation; traffic generator self-check.
- **INTEGRATION TESTS:** Pinned peer configurations.
- **VM TESTS:** A02–A13/A29.
- **FAILURE TESTS:** Link down, BFD traffic loss, neighbor crash, unsupported modes, foreign route collision.
- **DEFINITION OF DONE:** Each required case raw hashes/steps/verdict; no unit-only PASS promoted to VM acceptance; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Stop exact test PIDs/remove fault tables/restore peer and gateway baseline.
- **RISKS:** R02/R06/R07/R13.

### T27 — Implement and run LB/VRRP acceptance

- **TITLE / GOAL:** Implement and run LB/VRRP acceptance. Prove local admission, distribution/TLS and VIP failover.
- **WHY:** HAProxy and VRRP need packet and role evidence in addition to syntax.
- **DEPENDENCIES:** T26, T24.
- **FILES:** `tests/integration/m5/fixtures/haproxy-tcp.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/haproxy-http.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/haproxy-tls.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/ha-g1.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/ha-g2.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/ha-preempt.json` (NEW_M5_FILE); `tests/integration/m5/fixtures/combined.json` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Run identifiable backend servers and scoped approved/denied clients.
  2. Test delivery algorithms/health/recovery/TLS verification and M4 rejection.
  3. Add G2 with distinct node/boot/config identity; run takeover/preempt/sync/readiness cases.
  4. Capture both nodes' roles/VIPs and new versus established flow results.
- **UNIT TESTS:** Harness case assertions/data redaction.
- **INTEGRATION TESTS:** Scoped guard + adapters on VM.
- **VM TESTS:** A14–A19.
- **FAILURE TESTS:** Backend outage, bad CA, engine/API/master crash, asymmetric VRRP partition.
- **DEFINITION OF DONE:** No inspection claim for DELIVERY_ONLY; no seamless existing-session claim; both nodes cleaned; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Restore client default gateway, stop node test services, normal commits on each node.
- **RISKS:** R08/R09/R14/R15.

### T28 — Run transaction and daemon failure injection

- **TITLE / GOAL:** Run transaction and daemon failure injection. Verify compensation/recovery under every required failure.
- **WHY:** Happy-path M5 is insufficient for an authoritative firewall.
- **DEPENDENCIES:** T26, T27.
- **FILES:** `tests/integration/m5/fault-runner.sh` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Use disposable lab-only service profile/wrapper and one-shot phase faults.
  2. Run syntax/unavailable/reload/permission/stale file/partial apply failures.
  3. SIGKILL engine at WAL/phase barriers; restart and verify old/target Running decision.
  4. Record failure phase, journal, config generations and unrelated dataplane continuity.
- **UNIT TESTS:** All coordinator crash/cancel/idempotence tests plus touched modules.
- **INTEGRATION TESTS:** Fault wrapper never compiled/installed in production.
- **VM TESTS:** A20–A27.
- **FAILURE TESTS:** Every named injection in matrix including compensation failure.
- **DEFINITION OF DONE:** No false PASS on skipped fault; RECOVERY_REQUIRED retained when restoration fails; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Remove one-shot faults first; recover via engine; restore baseline, not git reset/runtime flush.
- **RISKS:** R10/R11/R12.

### T29 — Run M1–M4 compatibility and downgrade gate

- **TITLE / GOAL:** Run M1–M4 compatibility and downgrade gate. Prove new behavior did not regress accepted legacy behavior.
- **WHY:** Legacy correctness outranks optional new features.
- **DEPENDENCIES:** T28.
- **FILES:** `tests/integration/m5/README.md` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Run selected existing tests and directly affected packages, including M4 baseline.
  2. Repeat legacy live cases with M5 absent and supported enabled combinations.
  3. Verify ct marks/session IDs/NAT alias correlation and no M4/LB bypass.
  4. Test clean reboot, engine/API restarts and old-compatible paired downgrade.
- **UNIT TESTS:** Compatibility test list; go test selected packages; Linux cross-build; frontend targeted tests/build.
- **INTEGRATION TESTS:** Existing M1–M4 procedures plus M5 disabled spies.
- **VM TESTS:** A28/A32.
- **FAILURE TESTS:** Existing failure or unsupported M4 combination is explicit blocking result.
- **DEFINITION OF DONE:** All new regressions resolved; unrelated pre-existing failures recorded with evidence, not hidden; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Keep previous validated release and its config/artifact manifest.
- **RISKS:** R01/R05/R07/R09.

### T30 — Publish core readiness and evidence index

- **TITLE / GOAL:** Publish core readiness and evidence index. Close the specification-to-code acceptance loop.
- **WHY:** Implementation readiness and VM acceptance are different states.
- **DEPENDENCIES:** T29.
- **FILES:** `docs/m5/M5_EXECUTION_MAP.md` (planning/evidence document); `docs/m5/M5_ACCEPTANCE_MATRIX.md` (planning/evidence document); `docs/m5/M5_RISK_REGISTER.md` (planning/evidence document). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Record per-case status/time/git+dirty hash/package manifest and relative evidence paths.
  2. Verify hashes, cleanup, rejected scope and unresolved limitations.
  3. Mark core complete only with all required VM+regression gates; optional/future separate.
- **UNIT TESTS:** Evidence manifest/link consistency checks.
- **INTEGRATION TESTS:** Review acceptance record against raw assertions.
- **VM TESTS:** Required A00–A29/A32.
- **FAILURE TESTS:** Any missing raw evidence remains NOT_RUN/BLOCKED, never inherited PASS.
- **DEFINITION OF DONE:** Audit trail reproducible; architecture risk dispositions recorded; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Docs corrected by append/revision without editing raw evidence.
- **RISKS:** R01/R16.

### T31 — OPTIONAL: add IPVS NAT model/validation

- **TITLE / GOAL:** OPTIONAL: add IPVS NAT model/validation. Introduce explicitly gated kernel L4 virtual-server model.
- **WHY:** IPVS is distinct from HAProxy and not required for core sign-off.
- **DEPENDENCIES:** T30.
- **FILES:** `internal/config/ipvs.go` (NEW_M5_FILE); `internal/domain/ipvs.go` (NEW_M5_FILE); `internal/loadbalancer/virtualserver.go` (NEW_M5_FILE); `internal/domain/network_services.go` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F59.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Add optional IPVS pointer/capability and exact supported NAT fields.
  2. Validate tuple collisions, backend return path/M4 restrictions.
  3. Extend clone and UI only for supported accepted capability.
- **UNIT TESTS:** Optional schema/clone/NAT conflict tests.
- **INTEGRATION TESTS:** Disabled unknown-field behavior before optional release.
- **VM TESTS:** A30/A31.
- **FAILURE TESTS:** DR/TUN/fwmark/duplicate writer rejected.
- **DEFINITION OF DONE:** Core remains unaffected with optional capability absent; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Disable optional virtual servers, remove config field before old core binary.
- **RISKS:** R17.

### T32 — OPTIONAL: checker-only IPVS adapter

- **TITLE / GOAL:** OPTIONAL: checker-only IPVS adapter. Use one Keepalived checker writer and structured read-only IPVS observer.
- **WHY:** Avoid a race between direct Go IPVS writes and health daemon writes.
- **DEPENDENCIES:** T31.
- **FILES:** `internal/loadbalancer/ipvs/render.go` (NEW_M5_FILE); `internal/loadbalancer/ipvs/status_linux.go` (NEW_M5_FILE); `internal/loadbalancer/ipvs/backend.go` (NEW_M5_FILE); `deploy/network-services/ngfw-ipvs.service` (NEW_M5_FILE); `internal/loadbalancer/ipvs/testdata/netlink.json` (NEW_M5_FILE). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** F60, F61, B4New, B4Prepare, B4Snapshot, B4Apply, B4Verify, B4Restore, B4Status.
- **CONTRACTS:** Function cards above; CODE_CONTRACTS types/validation and ARCHITECTURE phase order; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Select/pin a small maintained generic-netlink binding by required attrs; use existing dependency only if proven capable.
  2. Render NAT rr/wrr/lc/sh/persistence and TCP health; separate unit/PID/FIFO from VRRP.
  3. Compose optional backend into coordinator ordered before final HA readiness; no direct IPVS programming.
- **UNIT TESTS:** Netlink attributes and checker-only config fixtures.
- **INTEGRATION TESTS:** Optional modules/service capabilities on disposable VM.
- **VM TESTS:** A30.
- **FAILURE TESTS:** Missing modules, backend down, checker restart, partial apply.
- **DEFINITION OF DONE:** Exclusive writer proven, no conntrack/session authority added; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Reload prior checker config and verify only owned virtual services removed.
- **RISKS:** R17/R07.

### T33 — OPTIONAL: IPVS VM and legacy regression

- **TITLE / GOAL:** OPTIONAL: IPVS VM and legacy regression. Accept kernel virtual services only after concrete packet/session evidence.
- **WHY:** NAT return path and persistence need real traffic.
- **DEPENDENCIES:** T32.
- **FILES:** `tests/integration/m5/fixtures/ipvs.json` (NEW_M5_FILE); `tests/integration/m5/README.md` (NEW_M5_FILE); `docs/m5/M5_ACCEPTANCE_MATRIX.md` (planning/evidence document). Corresponding owning test/fixture files in the file manifest are included.
- **FUNCTIONS:** Documented script entry-point/actions or data/unit templates; no new production function in this task.
- **CONTRACTS:** Packaging / Axx recipe contracts; compatibility gate always applies.
- **IMPLEMENTATION STEPS:**
  1. Run distribution/persistence/health removal/re-add and cleanup.
  2. Verify backend traffic returns through active gateway and NAT aliases correlate.
  3. Repeat M1 NAT/M2/M3 regressions; record separate optional verdict.
- **UNIT TESTS:** Affected optional tests + legacy alias tests.
- **INTEGRATION TESTS:** IPVS checker/netlink integration.
- **VM TESTS:** A30.
- **FAILURE TESTS:** Health timeout, checker crash, no return route.
- **DEFINITION OF DONE:** Raw optional evidence and no core regression; no DR/TUN or HA seamless claim; directly touched tests + selected legacy gate pass. A required live behavior is not accepted until its Axx evidence exists.
- **ROLLBACK PLAN:** Disable optional instance and revert only its manifest/files.
- **RISKS:** R17/R07.

## Planning checkpoint

FINDINGS: all core changes map to specific audited integration points or proposed
files/functions; protocol runtime algorithms remain upstream-owned.
DECISIONS: package capability proof precedes enablement; frontend work uses existing
Candidate lifecycle; live acceptance follows assembly, not renderer completion.
UNRESOLVED: measured T00/T01 gates and optional T32 binding choice, no hidden core
architecture choice left to the coding agent.
FILES ALREADY INSPECTED: CURRENT_ARCHITECTURE_MAP; file/function manifest is the cache.
SOURCES ALREADY INSPECTED: SOURCE_NOTES ledger.
NEXT TARGETS: future agent starts T00 only after a separate instruction to implement.
