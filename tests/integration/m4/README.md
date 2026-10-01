# M4 T01 capability probe

Run on the target Ubuntu appliance VM before enabling the M4 proxy selector:

```bash
sudo bash tests/integration/m4/probe-capabilities.sh --evidence-dir /tmp/ngfw-m4-probe
```

Requires `ip`, `nft`, `ss`, `sysctl`, `python3`, `openssl`, `suricata`, and `timeout`, plus root for temporary network namespaces. It creates three temporary namespaces, two veth pairs, a private nftables table **inside the router namespace**, a temporary CA, and a separate Suricata Unix-socket worker. It does not modify the host ruleset or production NGFW services. The temporary CA private key is removed and is not copied into the evidence directory.

Exit `0` means all probes passed. Exit `1` means a capability or behavior failed. Exit `2` means a prerequisite is missing. Preserve `original-dst.jsonl`, `client.jsonl`, `backend.jsonl`, `nft-ruleset.txt`, `suricata-control.json`, and error logs from the evidence directory. In particular, the public DNAT test must yield `10.251.0.2:443` as the **post-DNAT** upstream destination. If it yields `198.51.100.20:443`, or the request does not reach the backend, REDIRECT is unsuitable for the required DNAT path; record the failure and update ADR 0004 to TPROXY before implementing T06.

The script is only a capability probe. Passing it does not mark M4 VM acceptance complete, and syntax checks on Windows do not count as a Linux probe result. Suricata control behavior is checked against the [Suricata 8 Unix-socket command documentation](https://docs.suricata.io/en/suricata-8.0.0/unix-socket.html).

## T29 deployment and evidence collection

The M4 request-worker Suricata configuration, rules and hardened proxy units
are staged with `sudo bash scripts/install-m4-assets.sh`. The script runs
`suricata -T` as the dedicated `ngfw-proxy` account but **does not enable or
start the proxy**, install the legacy proxy binary, or change nftables. The
production proxy and selector depend on the T01 result and T06/T07/T28.

The proxy account belongs to supplementary group `ngfw` only for engine IPC.
The CA directory/key belong to `ngfw-proxy:ngfw-proxy` at `0700`/`0600`; the
API account `ngfw` must fail to read the key. Request-worker processes are
bounded child processes started by the proxy's `requestworker.ProductionFactory`.
`ngfw-request-worker-preflight.service` validates their common config before
the proxy starts; starting separate systemd Suricata worker instances would
compete for the same per-worker Unix sockets and is intentionally avoided.

On Ubuntu, collect a read-only baseline:

```bash
sudo bash scripts/verify-m4-linux.sh --evidence-dir /tmp/ngfw-m4-evidence
cat /tmp/ngfw-m4-evidence/summary.json
```

Exit `0` means collection completed and the CA permission preflight did not
find a violation. `summary.json` deliberately says `acceptance_status: PENDING`.
Exit `1` means the API can read the CA key or the proxy cannot read it; exit
`2` means missing prerequisites. The collector saves kernel/Suricata versions,
service hardening fields, nftables/conntrack snapshots and M4
health/capabilities. Request evidence requires an authenticated management
query and must be saved separately with its bearer token redacted. The
collector never copies private keys or environment secrets.

For each traffic scenario in [the M4 acceptance matrix](../../../docs/m4-acceptance-matrix.md),
copy [the evidence template](EVIDENCE_TEMPLATE.md) into a scenario directory,
record exact commands and UTC timestamps, and compare the proxy/engine verdict
with the upstream access log. A `BLOCK` needs a matching request ID and proof
that the upstream saw no application request. Keep every VM row `NOT_RUN`
until that evidence has been captured.
