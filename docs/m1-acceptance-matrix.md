# M1 acceptance matrix

This matrix records code readiness separately from Ubuntu VM evidence. “Ready
for VM” means the implementation and a repeatable test procedure exist; it does
not mean that a privileged VM run has already passed.

| # | Acceptance item | Implementation | Test/evidence | Status |
|---:|---|---|---|---|
| 1 | API has no `ip`/`nft` execution path | `cmd/ngfw-api`, `internal/engineipc` | API dependency audit and IPC round-trip unit test | Ready for VM |
| 2 | Engine owns privileged apply | `cmd/ngfw-engine`, `internal/dataplane/controller.go` | Linux cross-build; service capability unit files | Ready for VM |
| 3 | Running config loads on engine startup | `internal/config/manager.go`, engine startup | `TestControllerLoadsSnapshotAndReconcilesOnStartup` | Ready for VM |
| 4 | IPv4 forwarding is enabled at runtime | `internal/dataplane/forwarding.go` | `TestSysctlForwardingPersistsEnablesAndVerifies` | Ready for VM |
| 5 | IPv4 forwarding persists across reboot | `deploy/90-ngfw-ip-forward.conf`, install script | `scripts/verify-m1-linux.sh` | Ready for VM |
| 6 | Physical interface existence and admin state | `internal/dataplane/linux.go` | Network plan/reconciler unit tests | Ready for VM |
| 7 | VLAN parent/ID is created correctly | `domain.Interface`, network reconciler | `TestReconcilerCreatesMissingVLAN` | Ready for VM |
| 8 | Removed/changed VLAN is deleted | network plan/reconciler | `TestPlanNetworkRemovesStaleStateAndBuildsVLAN` | Ready for VM |
| 9 | MTU is applied and bounds are validated | config validator and network reconciler | validator and plan assertions | Ready for VM |
| 10 | IPv4/IPv6 address syntax and route family validate | config validator | config validator unit tests | Ready for VM |
| 11 | Routes apply with gateway, interface and metric | network reconciler | route plan unit test | Ready for VM |
| 12 | Stale addresses/routes are removed | network reconciler | stale-state plan and rollback tests | Ready for VM |
| 13 | Stateful default deny/allow policy compiles | nft compiler | compiler default-policy unit test | Ready for VM |
| 14 | Multiple addresses have OR semantics | nft compiler | `TestCompilePolicyUsesORSemantics` | Ready for VM |
| 15 | Multiple services have OR semantics | nft compiler | separate service-rule assertions | Ready for VM |
| 16 | NAT source/destination zones are honored | nft compiler | NAT matcher assertions | Ready for VM |
| 17 | NAT networks/protocol/ports are honored | nft compiler | NAT matcher assertions | Ready for VM |
| 18 | NAT priority is deterministic | nft compiler and validator | sorted priority assertions | Ready for VM |
| 19 | DNAT destination zone is enforced after routing | DNAT guard chain | guard-rule compiler assertion | Ready for VM |
| 20 | Interface/route/nft failure restores kernel snapshot | controller, manager | injected network/nft and manager rollback tests | Ready for VM |
| 21 | API rollback applies previous config to kernel | management API + IPC | `TestAPIRollbackAppliesPreviousConfiguration` | Ready for VM |
| 22 | Interrupted activation recovers on restart | activation journal and applied snapshot | `TestControllerUsesInterruptedTargetAsRecoverySource` and VM restart scenario | Ready for VM |

The rows become accepted only after the traffic, restart, capability, and
failure-injection procedures in `tests/integration/m1/README.md` produce raw
Ubuntu VM evidence. M2+ detectors, DPI, IDS, TLS, ML and session decision
features are deliberately not part of this matrix.
