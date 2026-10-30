# M1 acceptance matrix

Last updated: **2026-10-30**.

**PASS: all 22 requirements have Ubuntu VM evidence within the recorded scopes.**
The original row 20 failure (an orphan LAN address after a failed activation)
was repaired in the shared network/controller recovery path. Its exact address,
route and MTU regression was replayed successfully on the NGFW appliance on
2026-10-30. The original FAIL evidence is retained in [R]; its closure is [F].

The evidence spans multiple runs and binary versions from October 5 through
October 30. This is an aggregate functional acceptance record, not a claim that
all 22 requirements were rerun on one binary. Each report records its scope and
binary identity. Local unit/build success alone does not count as VM evidence.

| # | Acceptance item | Implementation | Ubuntu VM evidence | Status |
|---:|---|---|---|---|
| 1 | API has no `ip`/`nft` execution path | `cmd/ngfw-api`, `internal/engineipc` | Dependency/IPC checks; unprivileged API process and IPC socket before/after reboot [P] | PASS |
| 2 | Engine owns privileged apply | `cmd/ngfw-engine`, `internal/dataplane/controller.go` | Engine has only effective `CAP_NET_ADMIN`; real kernel apply and reconciliation [P], [V] | PASS |
| 3 | Running config loads on engine startup | `internal/config/manager.go`, engine startup | Remove managed WAN address/default route/nft table, restart only engine, verify restoration [V] | PASS |
| 4 | IPv4 forwarding is enabled at runtime | `internal/dataplane/forwarding.go` | Runtime sysctl is 1 before and after reboot [P] | PASS |
| 5 | IPv4 forwarding persists across reboot | `deploy/90-ngfw-ip-forward.conf`, installer | Real VM reboot; persisted sysctl, enabled services and restored dataplane [P] | PASS |
| 6 | Physical interface existence and admin state | `internal/dataplane/linux.go` | Interface/UP assertions and restored baseline [V]; live admin-state drift repair [D] | PASS |
| 7 | VLAN parent/ID is created correctly | `domain.Interface`, network reconciler | `ens38.120@ens38`, 802.1Q ID 120, correct addresses/route [V] | PASS |
| 8 | Removed/changed VLAN is deleted | network plan/reconciler | VLAN interface, addresses, routes and nft reference absent after deletion [V] | PASS |
| 9 | MTU is applied and bounds are validated | config validator and network reconciler | MTU 1400 applied; MTU 575 rejected without mutation; baseline restored [V] | PASS |
| 10 | IPv4/IPv6 address syntax and route family validate | config validator | Invalid address/family requests rejected without Candidate/Running/kernel mutation [N] | PASS |
| 11 | Routes apply with gateway, interface and metric | network reconciler | Actual address/route replacement and exact kernel attributes [N] | PASS |
| 12 | Stale addresses/routes are removed | network reconciler | Old managed objects disappear on replacement/removal [N]; failed-target cleanup [F] | PASS |
| 13 | Stateful default deny/allow policy compiles | nft compiler | TCP/ICMP with conntrack/NAT; denied SYNs traced to default drop with no WAN delivery [N] | PASS |
| 14 | Multiple addresses have OR semantics | nft compiler | Independent source/destination members pass; nonmembers denied [R] | PASS |
| 15 | Multiple services have OR semantics | nft compiler | TCP/80 and UDP/53 alternatives exercised [R] | PASS |
| 16 | NAT source/destination zones are honored | nft compiler | Real matching/nonmatching SNAT/MASQUERADE/DNAT zone controls [A], [R] | PASS |
| 17 | NAT networks/protocol/ports are honored | nft compiler | Real network/protocol/port match and mismatch controls [A], [R] | PASS |
| 18 | NAT priority is deterministic | nft compiler and validator | Specific fixed SNAT wins over lower-priority MASQUERADE fallback [A], [R] | PASS |
| 19 | DNAT destination zone is enforced after routing | DNAT guard chain | Routed DNAT zone guard and real WAN/DMZ controls [R] | PASS |
| 20 | Interface/route/nft failure restores kernel snapshot | controller, manager | Original LAN `.99`/invalid gateway/MTU replay: actual add/delete observed, Running unchanged, network/nft restored [F]; broader Linux fault suite [H] | PASS after fix |
| 21 | API rollback applies previous config to kernel | management API + IPC | Previous network/NAT/policy restored through rollback API, including API restart persistence [R] | PASS |
| 22 | Interrupted activation recovers on restart | activation journal and applied snapshot | Engine interrupted-activation recovery [R]; real controller SIGKILL/journal replay and stale-object cleanup [H] | PASS |

Row 10 establishes validation, not IPv6 packet-path acceptance. Reboot persistence
and interrupted-activation recovery have separate evidence; the Linux SIGKILL
probe in [H] is not a whole-appliance power loss during activation. M2 session
capacity, DPI, IDS, TLS, ML and session decision features are outside this matrix.

[A]: ../artifacts/m1-nat-acceptance-20261005T0905Z/RESULTS.md
[P]: ../artifacts/m1-preflight-reboot-20261005T110434Z/RESULTS.md
[V]: ../artifacts/m1-startup-vlan-20261005T140631Z/RESULTS.md
[N]: ../artifacts/m1-network-policy-20261007T074203Z/RESULTS.md
[R]: ../artifacts/m1-remaining-20261007T082100Z/RESULTS.md
[D]: ../artifacts/m1-network-drift-fix-20261025/RESULTS.md
[H]: ../artifacts/m3-recovery-repair-20261028/RESULTS.md
[F]: ../artifacts/m1-row20-20261030/RESULTS.md
