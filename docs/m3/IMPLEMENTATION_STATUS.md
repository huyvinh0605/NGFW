# M3 implementation status

Last updated: 2026-10-26

Published source HEAD: `d7a7291f2c2811abef0272ee8b3d13c61cc1ca8b` on host, GitHub and VM. The running engine preserves the archived M2 conntrack recovery source and adds the EVE reader fix; see the deployment report below. Unrelated local/VM worktree changes remain uncommitted.

Test host: Windows NT 10.0.26200.0, Go 1.27.0 windows/amd64, Node 22.19.0,
npm 10.9.3.

## Current status

| Scope | Status | Evidence |
|---|---|---|
| M3 production source and deployment artifacts | **IMPLEMENTED** | T02–T28 source, scripts, services and configuration are present. |
| M3 package behavior | **UNIT TESTED** | M3 race command and full Go suite below passed. |
| Local adapters, runtime wiring and fixture paths | **INTEGRATION TESTED** | In-process/fake-adapter and fixture integration included in the passing Go suite. |
| Ubuntu kernel, NFLOG, NFQUEUE and live Suricata paths | **PARTIALLY ACCEPTED** | Six matrix rows PASS (M3-00/01/02/03/04/35); four PARTIAL (M3-05/21/29/30); 28 NOT_RUN. Sensor ACL and unprivileged syntax pass, but IDS/IPS services are inactive and M3-05 traffic remains pending. [Latest evidence](../../artifacts/m3-rbac-20261026T163657Z/RESULTS.md). |

This status means the M3 implementation is ready for Ubuntu acceptance. It does
not mean M3 has passed live appliance acceptance.

## Readiness commands run on 2026-09-28

```text
go test -race -count=1 ./internal/inspection/... ./internal/engine/... ./internal/session/...
PASS

go test -count=1 ./...
PASS
```

Race-tested packages: `internal/inspection`, `internal/inspection/correlation`,
`internal/inspection/eve`, `internal/inspection/sensor`, `internal/engine` and
`internal/session`. No data race was reported.

## Gates rerun on 2026-10-25

Ubuntu Go 1.22.2 with umask 0022: full test, vet, full race, CGO=0 Linux
command builds and both 30-second parser fuzz targets passed. The worker/socket
packages also passed 20 race repetitions. Windows full Go test/vet and a clean
web `npm ci`, all 38 tests and production build passed. See
[commands and raw output](../../artifacts/m3-blockers-fix-20261025T091814Z/RESULTS.md).

The probe was corrected to use production schema 2; actual NFQUEUE drop,
saturation fail-open, NFLOG capture and guard lifecycle passed in isolated
namespaces. The runtime socket timeout fix was deployed to ngfw-proxy with a
backup. Running remained version 92 in that run with M3/M4 disabled; production inspection
traffic rows are still pending.

## M3-02 and conntrack recovery on 2026-10-26

M3-02 passed on Running v93 with Suricata stopped: persistent HTTP through
MASQUERADE, verified TLS 1.3 through DNAT, stable CT/SessionID and translated
aliases, current kernel cache marks and cache ACCEPT traces, and an unmatched
WAN-to-LAN probe reaching the kernel default DROP while its server passed a
positive control. The old unrestricted lab policy was replaced by scoped
forwarding rules; the original Candidate draft was preserved.

A real M2 receive-loop bug was also fixed: ENOBUFS previously terminated the
conntrack subscriber permanently. An isolated Linux kernel test reproduced
506 multicast drops and the old fatal exit. The fixed receiver reported the
gap without terminating, observed a new flow on the same subscription, and
completed a 514-flow dump. Full Linux test/vet/race passed; the new engine was
built, backed up and deployed. See [raw evidence and scope](../../artifacts/m3-02-repair-20261026T085256Z/RESULTS.md).

## Task status

| Tasks | Implementation status | Verification status |
|---|---|---|
| T00 | **IMPLEMENTED** | Ubuntu baseline M3-00 PASS on 2026-10-25 after network ownership/reconciliation repair. |
| T01 | **IMPLEMENTED** | **CAPABILITY ACCEPTED**: M3-01 isolated kernel/Suricata probe PASS; [VM report](../../artifacts/m3-blockers-fix-20261025T091814Z/RESULTS.md). |
| T02–T15 | **IMPLEMENTED** | **UNIT TESTED**; relevant concurrent packages passed race detection. |
| T16–T22 | **IMPLEMENTED** | **INTEGRATION TESTED** locally with adapters/fixtures; live kernel and sensor acceptance pending. |
| T23–T28 | **IMPLEMENTED** | **UNIT TESTED** by the full Go suite; live management/deployment acceptance pending. |
| T29 | **IMPLEMENTED** | M3-00 and M3-02 OFF traffic passed; the repeatable OFF runner rejects invalid policy preconditions before traffic. Enabled inspection traffic scenarios remain **ACCEPTANCE PENDING**. |
| T30 | **IMPLEMENTED** | Linux full test/vet/race and CGO=0 engine build rerun PASS on 2026-10-26. Prior Windows/web and parser fuzz gates passed on 2026-10-25. Soak, resource-pressure and OFF/IDS/IPS performance acceptance remain pending. |
| T31 | **IMPLEMENTED** | Documentation reflects implementation versus acceptance status. |

## Remaining acceptance work

- Finish four PARTIAL M3 rows and run the other 28 NOT_RUN rows with real production sensor/traffic or browser evidence as specified by each row.
- Run the resource-pressure/soak test and OFF/IDS/IPS benchmark.
- Keep every unexecuted row in the acceptance matrix as `NOT_RUN` until real
  evidence exists.

Unrelated pre-existing worktree change `GiaiThich/~$AT&DNAT.docx` was not
modified as part of M3 readiness.

## M3-03 runner correction

The alleged null Running/version failure came from reading the outer API envelope instead of data. The corrected REST workflow passed 25 VM assertions with no activation or Running changes. See [root cause and scope](M3_03_CANDIDATE_ACCEPTANCE.md).

## 2026-10-26 M3-05 and API/EVE continuation

[M3-05 permission repair](../../artifacts/m3-05-repair-20261026T145604Z/RESULTS.md), [API/WS follow-up](../../artifacts/m3-api-followup-20261026T151100Z/RESULTS.md), and [RBAC/EVE deployment with final gates](../../artifacts/m3-rbac-20261026T163657Z/RESULTS.md) contain the raw Ubuntu results and explicit pending scope. Production API/engine binaries were updated; Running v93 and the operator Candidate remain unchanged. Web 39/39 tests and production build pass, while browser acceptance and IDS/IPS traffic remain pending.

## 2026-10-27 live IDS/IPS continuation

[Raw evidence and repairs](../../artifacts/m3-continuation-20261027/RESULTS.md) accept M3-05/06/07/08/10/11/12/13/14/15/16/17/20. The matrix currently records 19 PASS, 4 PARTIAL and 15 NOT_RUN; full M3 acceptance is still pending. Published commits 2c2bdae, d30d6e4, fd1592a, 6342e11 and 8cad477 have been pushed, pulled and applied on NGFW. Real sensors run Suricata 7.0.3. The current engine is rebuilt from its recorded source archive plus these published repairs; earlier M4 checkout differences remain outside this deployment.
