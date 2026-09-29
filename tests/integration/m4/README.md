# M4 T01 capability probe

Run on the target Ubuntu appliance VM before enabling the M4 proxy selector:

```bash
sudo bash tests/integration/m4/probe-capabilities.sh --evidence-dir /tmp/ngfw-m4-probe
```

Requires `ip`, `nft`, `ss`, `sysctl`, `python3`, `openssl`, `suricata`, and `timeout`, plus root for temporary network namespaces. It creates three temporary namespaces, two veth pairs, a private nftables table **inside the router namespace**, a temporary CA, and a separate Suricata Unix-socket worker. It does not modify the host ruleset or production NGFW services. The temporary CA private key is removed and is not copied into the evidence directory.

Exit `0` means all probes passed. Exit `1` means a capability or behavior failed. Exit `2` means a prerequisite is missing. Preserve `original-dst.jsonl`, `client.jsonl`, `backend.jsonl`, `nft-ruleset.txt`, `suricata-control.json`, and error logs from the evidence directory. In particular, the public DNAT test must yield `10.251.0.2:443` as the **post-DNAT** upstream destination. If it yields `198.51.100.20:443`, or the request does not reach the backend, REDIRECT is unsuitable for the required DNAT path; record the failure and update ADR 0004 to TPROXY before implementing T06.

The script is only a capability probe. Passing it does not mark M4 VM acceptance complete, and syntax checks on Windows do not count as a Linux probe result. Suricata control behavior is checked against the [Suricata 8 Unix-socket command documentation](https://docs.suricata.io/en/suricata-8.0.0/unix-socket.html).
