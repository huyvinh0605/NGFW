# M3 deterministic Suricata fixture

`marker-http.pcap` contains one synthetic HTTP connection from
`192.168.10.10:50000` to `192.0.2.10:8080`. The harmless marker
`NGFW_M3_TEST_fixture` is split across two TCP segments. It must only be used
inside the isolated M3 lab.

Regenerate it deterministically:

```bash
go run ./tests/fixtures/m3/build_pcap.go ./tests/fixtures/m3/marker-http.pcap
sha256sum -c ./tests/fixtures/m3/SHA256SUMS
```

An offline IPS replay proves parsing and signature output only. It does not
prove the Linux NFQUEUE packet-drop path; that remains a separate VM scenario.
