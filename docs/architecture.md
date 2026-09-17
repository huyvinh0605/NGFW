# Runtime boundaries

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

UI, ML, DPI, IDS, TLS interception and M2 session features are outside the M1
bring-up and acceptance scope.
