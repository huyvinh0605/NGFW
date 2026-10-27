# Suricata EVE fixtures

`ssh-suricata7.jsonl` contains the discovery alert and SSH record emitted by
Suricata 7.0.3 during offline replay of synthetic LAN-to-WAN SSH traffic captured
on the Ubuntu appliance on 2026-10-27. The client sends only its test banner to
the lab WAN OpenSSH server; the capture contains no login credentials.

Source PCAP SHA-256:
`ef526d7e06ad4d715d9e83b616905a2e3f45f1f56cf4a01fd6e2e09a082bdac4`.

Both records use object-valued `ssh.client` and `ssh.server` with
`proto_version` and `software_version`. `ssh.jsonl` retains the older synthetic
string representation as a compatibility fixture. Offline replay verifies the
EVE ingestion contract; live IDS/NFQUEUE acceptance remains separate.
