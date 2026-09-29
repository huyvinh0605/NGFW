# Runtime boundaries

> M2 running-configuration/session ownership is in `ngfw-engine`, as recorded
> in [ADR 0002](adr/0002-m2-runtime-and-cache.md). M3 inspection is implemented
> according to [ADR 0003](adr/0003-m3-inspection-pipeline.md); Ubuntu capability
> and traffic acceptance remain pending until the matrix has live evidence.

For M1, `ngfw-engine` is the only process that may invoke `ip` or `nft` and the
only process that needs `CAP_NET_ADMIN`. The Linux adapters and transaction
coordinator live in `internal/dataplane`. `ngfw-api` runs as the unprivileged
`ngfw` user with no capabilities.

The API edits and validates a candidate snapshot. Commit and rollback send the
complete target configuration over the versioned Unix socket
`/run/ngfw/engine.sock`. The engine validates again and executes this sequence:

```text
persist activation journal
  -> verify/persist net.ipv4.ip_forward=1
  -> reconcile interfaces, VLANs, addresses and routes
  -> validate and atomically replace the inet ngfw nftables table
  -> persist applied-dataplane snapshot
  -> remove activation journal
```

An error restores the previous nftables and network snapshots before it is
returned to the API. The API publishes `running.json` only after engine success.
If the API cannot persist its running snapshot, it issues a compensating engine
apply for the old config. On engine startup, `running.json` is always reconciled
to the kernel. A leftover activation journal makes startup remove state that an
interrupted candidate could have introduced.

The previous running configuration is persisted with `running.json`, so API
rollback after an API restart still activates the correct kernel state.

The M1 firewall compiler emits a complete isolated `inet ngfw` table. Policy
rules are ordered by ascending priority. Address lists become nftables sets and
each service becomes a separate rule, which gives OR behavior within each
field. Stateful return traffic is accepted after invalid packets and the DNAT
destination-zone guard have run. NAT rules are also sorted by priority and
include configured zone interfaces, networks, protocol and ports.

## Linux M1 bring-up sequence

1. Create the four-NIC Ubuntu 24.04 VM and identify WAN/LAN/DMZ/MGMT names.
2. Install nftables and iproute2.
3. Build `ngfw-engine` and `ngfw-api`, then run `scripts/install-linux.sh`.
4. Set `/etc/ngfw/ngfw.env`, adapt `configs/examples/m2-lab.json`, and start the
   engine before the API.
5. Run `scripts/verify-m1-linux.sh`, then execute every traffic and rollback row
   in `tests/integration/m1/README.md` while keeping raw kernel and packet
   evidence.

UI, M2 sessions and M3 inspection have their own gates and do not change the M1
bring-up criteria. ML, DPI/nDPI and TLS interception remain outside M3.

## M3 inspection runtime

The engine creates EVE readers and sensor monitors only when the effective
Running configuration uses an M3 inspection profile. The readers preserve
Suricata flow IDs as strings, bind every record to a sensor epoch and source
position, checkpoint complete lines, and survive rename/copytruncate within
bounded catch-up limits. A new sensor epoch invalidates old Suricata flow
bindings without deleting retained security history.

```text
NFLOG/NFQUEUE -> Suricata EVE readers -> bounded observation queue
              -> NAT/session resolver -> inspection reducer
              -> SessionInspection + SecurityEventStore
              -> optional application-guard intent -> nftables readback
```

The resolver queries the existing M2 `RuntimeStore`; M3 has no second session
database. It checks complete original/reply/translated tuples, conntrack zone and
identity, observation time, closed-session bounds and ambiguity. An event is
stored before correlation. Late correlation updates the same event revision and
publishes `SecurityEventUpdated`, while a replayed physical record does not
increment the session threat count again.

The nftables inspection table has early selection and later enforcement chains.
IDS-selected traffic logs to NFLOG group 100. IPS-selected traffic queues to
NFQUEUE 100 only while the short-lived `ips_ready` lease is present. Queue
bypass plus Suricata fail-open preserve the base M1/M2 connectivity result when
inspection is unavailable. Hard block/revocation chains remain later and win
over cached allow and an IPS allow verdict. Flowtable offload is disabled.

Application restriction uses `RESTRICT_L3_ALLOW`: the first L3/L4 ALLOW policy
selects a profile and optional whitelist. Strong App-ID outside that list in IPS
mode installs a timeout guard scoped to conntrack zone, ID and full original
IPv4 TCP/UDP tuple. The coordinator verifies identity before and after kernel IO,
serializes guard mutation with activation, reads back the exact set element and
updates the session only after success. Removing application guards never clears
M2 manual/source blocks.

Activation persists an `ActivationSnapshot` with exact compiler options,
inspection plan and hashes for both target and previous state. Immutable sensor
artifacts are validated before apply. Network/nft apply, runtime generation,
sensor lifecycle and journal finalization are staged; compensation applies the
previous snapshot. A failure after generation publication restores through a
newer generation so generation numbers never move backward.

Runtime IPC protocol v3 exposes sessions with inspection context, bounded
security-event cursor pages, inspection health/capabilities and typed runtime
notifications. WebSocket messages carry stream ID, sequence, schema version,
kind and event class. A gap or engine restart is explicit so clients perform a
REST catch-up instead of silently treating missing history as complete.
