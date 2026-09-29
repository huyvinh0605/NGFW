# M4 — Ubuntu Acceptance Matrix

Each row requires the source hash, configuration generation/hash, kernel/nftables/Suricata/Go versions, commands, exit codes, and evidence path. `NOT_RUN` is never PASS.

| ID | Mandatory criterion | Minimum evidence | VM |
|---|---|---|---|
| M4-00 | Required M1/M2 baseline and M3 OFF/IDS/IPS behavior still works before M4 | prior matrices + current run IDs | NOT_RUN |
| M4-01 | Capability probe: redirect/original-dst/DNAT ordering/Suricata socket/ALPN | probe raw output + nft JSON | NOT_RUN |
| M4-02 | M4 OFF does not change forwarding/NAT/M3 behavior | nft diff, traffic baseline | NOT_RUN |
| M4-03 | Invalid gate/TLS/exclusion config is rejected and kernel state is unchanged | API400 + hashes before/after | NOT_RUN |
| M4-04 | Clean HTTP/1.1 request reaches upstream | client output + upstream nonce log | NOT_RUN |
| M4-05 | HTTP/1.1 SQLi is blocked before upstream | 403 + EVE SID + upstream absence | NOT_RUN |
| M4-06 | HTTP/1.1 XSS is blocked before upstream | 403 + EVE SID + upstream absence | NOT_RUN |
| M4-07 | HTTPS DECRYPT clean path: client trusts CA, upstream is verified, request reaches server | TLS states + upstream log | NOT_RUN |
| M4-08 | HTTPS DECRYPT SQLi/XSS never reaches upstream | proxy decision + EVE + server absence | NOT_RUN |
| M4-09 | BYPASS TLS preserves end-to-end certificate/upstream bytes | capture + client cert observation | NOT_RUN |
| M4-10 | TLS exclusion correctly matches domain/CIDR/port; non-matches still decrypt/gate | config + decision events | NOT_RUN |
| M4-11 | ClientHello split across multiple TCP reads still parses/tunnels correctly | pcap + logs | NOT_RUN |
| M4-12 | Unavailable SNI/ECH-like case is not falsely reported as decrypted/clean | health/event limitation | NOT_RUN |
| M4-13 | Invalid upstream certificate/hostname mismatch returns 502; no InsecureSkipVerify | TLS error + upstream evidence | NOT_RUN |
| M4-14 | Client CA distrust/pinning-like failure does not silently bypass | handshake fail + no upstream request | NOT_RUN |
| M4-15 | Upstream mTLS requirement reports unsupported/failure correctly | reason code + no false clean | NOT_RUN |
| M4-16 | Clean HTTP/2 request passes on the same TLS connection | h2 evidence + upstream log | NOT_RUN |
| M4-17 | One H2 connection: concurrent clean + malicious requests; only malicious request is blocked | same connection ID, distinct request IDs, upstream only clean | NOT_RUN |
| M4-18 | 20+ concurrent H2 requests show no cross-request verdict/body contamination | decision map + upstream nonces | NOT_RUN |
| M4-19 | Attack in chunked body is inspected and blocked | client + EVE + upstream absence | NOT_RUN |
| M4-20 | gzip/deflate attack is blocked after decompression | decoded-size evidence + EVE | NOT_RUN |
| M4-21 | Decompression bomb above limit follows configured policy | 413/allow-partial + counters | NOT_RUN |
| M4-22 | Body above max follows BLOCK or ALLOW_PARTIAL profile behavior without silent bypass | response + coverage event | NOT_RUN |
| M4-23 | Malformed framing/header overflow is never forwarded upstream | 400/431 + server absence | NOT_RUN |
| M4-24 | Suricata request-worker timeout under fail-open | request passes + coverage unavailable + counter | NOT_RUN |
| M4-25 | Suricata request-worker timeout under fail-close | 503 + server absence + reason | NOT_RUN |
| M4-26 | Request-worker crash/socket down produces degraded health and correct policy behavior | health + open/close tests | NOT_RUN |
| M4-27 | Worker queue full remains bounded with no unbounded memory growth | queue counters + RSS/soak | NOT_RUN |
| M4-28 | Proxy capacity/per-client limit remains bounded | 429/503 + counters + recovery | NOT_RUN |
| M4-29 | DNAT public HTTPS -> DMZ: original destination/session is correct and gate still blocks | conntrack + API + proxy + server log | NOT_RUN |
| M4-30 | MASQUERADE outbound HTTPS gate preserves correct session/NAT alias identity | CT/API/request IDs | NOT_RUN |
| M4-31 | API/UI outage does not stop proxy/engine request enforcement | stop API + repeat malicious/clean | NOT_RUN |
| M4-32 | Proxy restart has explicit behavior for existing connections and recovers for new connections | logs/health/client behavior | NOT_RUN |
| M4-33 | Engine restart does not reuse stale request decisions; selector/gate resyncs | generation IDs + nft + new decisions | NOT_RUN |
| M4-34 | Commit OFF→DECRYPT/gate→rollback changes nft/proxy behavior correctly | generations + rules + traffic | NOT_RUN |
| M4-35 | Activation failure/reboot journal restores previous M1/M3/M4 state | induced failure + restart evidence | NOT_RUN |
| M4-36 | CA key permissions are correct and API cannot read the private key | stat/getfacl + API negative test | NOT_RUN |
| M4-37 | Logs/events redact Authorization/Cookie/body/token query data | synthetic secret test + grep evidence | NOT_RUN |
| M4-38 | WebSocket upgrade records handshake coverage only and never claims frame inspection | event limitation + traffic | NOT_RUN |
| M4-39 | UDP/443 follows explicit profile behavior: block or unsupported, never falsely reported as decrypted | QUIC client/counter/event | NOT_RUN |
| M4-40 | Race/fuzz/full Go/vet/web gates PASS on Linux | raw command outputs | NOT_RUN |
| M4-41 | Request-gate soak keeps memory/temp-file/queue growth bounded | RSS, file count, counters | NOT_RUN |
| M4-42 | Benchmark HTTP1/H2 plaintext/TLS gate across 3 runs and report p50/p95/p99 | raw results + config hashes | NOT_RUN |

## Evidence layout

```text
docs/evidence/M4/<UTC-run-id>/
  manifest.json
  summary.json
  commands.jsonl
  baseline/
  M4-17/
    before/ after/
    client.out
    proxy.log
    engine.log
    request-worker.log
    eve.jsonl
    upstream.log
    lan.pcap
    dmz.pcap
```

Never commit the CA private key, bearer tokens, or raw real-user payloads.
