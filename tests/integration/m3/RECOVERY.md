# M3 activation recovery regression

Build the production dataplane test package on Ubuntu, then run the opt-in
suite as root in a disposable network namespace:

```sh
go test -c -o /tmp/ngfw-network-recovery.test ./internal/dataplane
sudo unshare --net env NGFW_NETWORK_NETNS_TEST=1 \
  NGFW_NETWORK_EVIDENCE_DIR=/tmp/ngfw-network-recovery-evidence \
  /tmp/ngfw-network-recovery.test -test.v \
  -test.run '^TestLinuxNetworkRecovery' -test.count=1
```

The test refuses the appliance network namespace. It uses real dummy/VLAN
links, IPv4/IPv6 addresses, routes and nftables through production adapters.
The forwarding sysctl and sensor processes are outside this test's scope.
Injected failures interrupt operations before/after partial kernel mutation;
the persistent recovery case keeps the activation journal until a new
Controller successfully restores the baseline.

The suite checks VLAN creation, MTU, IPv4/IPv6 changes, route changes,
cancellation, a real nft syntax rejection and a persistent restore failure.
Each operation-failure case repeats the completed restoration three times.
Assertions require the baseline network/nft snapshot, no stale managed
objects, unchanged applied generation and correct journal lifecycle.
Unmanaged addresses/routes are allowed.

The process-crash probe reproduces the original invalid-next-hop failure and
kills a child process after `ApplyRuntimePrepared` has applied the target and
retained its journal. A new Controller then recovers the previous snapshot
and finalizes the activation:

```sh
go build -o /tmp/ngfw-m3-recovery-probe ./tests/integration/m3/isolated_source
sudo unshare --net /tmp/ngfw-m3-recovery-probe \
  --activation-phase=parent \
  --evidence-dir=/tmp/ngfw-m3-activation-UNIQUE_RUN_ID
```

Use a fresh evidence directory for each probe run. This exercises the real
production controller and Linux adapters inside the VM; it does not reboot
the appliance or substitute a Suricata process. The probe's default EVE-source
mode is separate and intentionally uses synthetic EVE with real conntrack,
runtime, IPC and API libraries.
