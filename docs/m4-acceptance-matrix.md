# M4 — Ubuntu Acceptance Matrix

Each row requires the source hash, configuration generation/hash, kernel/nftables/Suricata/Go versions, commands, exit codes, and evidence path. `NOT_RUN` is never PASS.

| ID | Mandatory criterion | Minimum evidence | VM |
|---|---|---|---|
| M4-00 | Required M1/M2 baseline and M3 OFF/IDS/IPS behavior still works before M4 | prior matrices + current run IDs | NOT_RUN |
| M4-01 | Capability probe: redirect/original-dst/DNAT ordering/Suricata socket/ALPN | probe raw output + nft JSON | NOT_RUN |
| M4-02 | M4 OFF does not change forwarding/NAT/M3 behavior | nft diff, traffic baseline | NOT_RUN |
| M4-03 | Invalid gate/TLS/exclusion config is rejected and kernel state is unchanged | API400 + hashes before/after | PARTIAL: worker-count rejection on VM; TLS/exclusion cases pending |
| M4-04 | Clean HTTP/1.1 request reaches upstream | client output + upstream nonce log | PASS: [2026-10-24](../artifacts/m4-fix-20261024/http-final/result.json) |
| M4-05 | HTTP/1.1 SQLi is blocked before upstream | 403 + EVE SID + upstream absence | PASS: [2026-10-24](../artifacts/m4-fix-20261024/http-final/result.json), SID 9904003 |
| M4-06 | HTTP/1.1 XSS is blocked before upstream | 403 + EVE SID + upstream absence | PASS: [2026-10-24](../artifacts/m4-fix-20261024/http-final/result.json), SID 9904004 |
| M4-07 | HTTPS DECRYPT clean path: client trusts CA, upstream is verified, request reaches server | TLS states + upstream log | PASS: [2026-10-24 recheck](../artifacts/m4-health-recheck-20261024T0558Z/RESULTS.md); CA/SAN verified, upstream nonce and complete HTTPS inspection, counters observed after heartbeat |
| M4-08 | HTTPS DECRYPT SQLi/XSS never reaches upstream | proxy decision + EVE + server absence | PASS: [2026-10-24](../artifacts/m4-health-recheck-20261024T0558Z/RESULTS.md); 403, SIDs 9904003/9904004, no upstream request, block counters advance |
| M4-09 | BYPASS TLS preserves end-to-end certificate/upstream bytes | capture + client cert observation | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); origin leaf/body hashes and reassembled TLS bytes identical in both directions |
| M4-10 | TLS exclusion correctly matches domain/CIDR/port; non-matches still decrypt/gate | config + decision events | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); 11 selector variants, generation-bound engine decisions, non-matching SQLi blocked before origin |
| M4-11 | ClientHello split across multiple TCP reads still parses/tunnels correctly | pcap + logs | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); 7 writes, captured TCP segments, BYPASS byte identity and DECRYPT SQLi block |
| M4-12 | Unavailable SNI/ECH-like case is not falsely reported as decrypted/clean | health/event limitation | PARTIAL: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); no-SNI CLOSE/OPEN and explicit ECH capability limitation pass; ECH traffic not exercised |
| M4-13 | Invalid upstream certificate/hostname mismatch returns 502; no InsecureSkipVerify | TLS error + upstream evidence | PARTIAL: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); hostname mismatch returns 502/no origin and upstream_verify_fail increments; independent untrusted-chain case pending |
| M4-14 | Client CA distrust/pinning-like failure does not silently bypass | handshake fail + no upstream request | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); both clients reject MITM, handshake-fail counters increment, no bypass/origin request |
| M4-15 | Upstream mTLS requirement reports unsupported/failure correctly | reason code + no false clean | PASS after fix: [2026-10-24 recheck](../artifacts/m4-mtls-fix-20261024T113924Z/RESULTS.md); TLS 1.2/1.3 require client cert: 502, no origin request, correlated TLS_UPSTREAM_MTLS_UNSUPPORTED; optional auth and negative controls pass. Earlier FAIL evidence retained |
| M4-16 | Clean HTTP/2 request passes on the same TLS connection | h2 evidence + upstream log | PASS after API DTO fix: [live recheck](../artifacts/m4-forward-fix-20261030/h2-recheck/result.json), verified TLS 1.3/h2, exact origin, COMPLETE ALLOW and successful `forward` preserved through API; [earlier FAIL retained](../artifacts/m4-continuation-20261030/RESULTS.md) |
| M4-17 | One H2 connection: concurrent clean + malicious requests; only malicious request is blocked | same connection ID, distinct request IDs, upstream only clean | PASS: [live 2-request batch](../artifacts/m4-forward-fix-20261030/h2-isolation/M4-17/assessment.json), one TCP/TLS connection, clean 200, SQLi 403, distinct request/decision/ordinal identities, zero attack at origin |
| M4-18 | 20+ concurrent H2 requests show no cross-request verdict/body contamination | decision map + upstream nonces | PASS: [24 concurrent requests](../artifacts/m4-forward-fix-20261030/h2-isolation/M4-18/assessment.json), 16 clean/8 SQLi-XSS, one socket/session, matching origin body hashes; 2 workers and configured 10-second inspection deadline, not a throughput/overload claim |
| M4-19 | Attack in chunked body is inspected and blocked | client + EVE + upstream absence | PASS: [live body run](../artifacts/m4-forward-fix-20261030/body-limits-run2/result.json), clean dechunked body hash preserved, SQLi split across chunks blocked with SID 9904003 and no origin request |
| M4-20 | gzip/deflate attack is blocked after decompression | decoded-size evidence + EVE | PASS: [live body run](../artifacts/m4-forward-fix-20261030/body-limits-run2/result.json), gzip and zlib-deflate clean/SQLi controls; original compressed clean bytes preserved, decoded attacks blocked before origin |
| M4-21 | Decompression bomb above limit follows configured policy | 413/allow-partial + counters | FAIL: [live diagnosis](../artifacts/m4-forward-fix-20261030/M4-21-DIAGNOSIS.json), 424-byte gzip expands to 400,000 bytes; CLOSE/BLOCK returns 503/UNAVAILABLE instead of 413/PARTIAL coverage-limit contract; zero origin requests. Testing stopped |
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
| M4-38 | Unsupported WebSocket Upgrade is rejected before upstream forwarding and never claims frame inspection | 400 + upstream absence + explicit limitation | NOT_RUN |
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

The HTTP VM run and the isolated kernel guard lifecycle check are described in
[the 2026-10-24 report](../artifacts/m4-fix-20261024/RESULTS.md). Only rows 04–06
are accepted by that traffic run. OFF→HTTP activation, restoring Running and
recovering the earlier interrupted activation also worked; these observations
do not complete rows 00, 02, 34 or 35 in their broader mandatory scope.

The HTTPS recheck accepts rows 07 and 08 with the existing NGFW binaries. The
earlier counter failure was a premature test assertion against a heartbeat
older than the request. The corrected runner requires a healthy same-generation
heartbeat newer than request evidence and the expected counter increments
within eight seconds. VM clocks remain skewed, so the strict verified Linux
client uses NGFW UTC plus five minutes for certificate validation; it still
checks the CA chain and DNS SAN. See the linked report for these test conditions.

The next TLS run used synchronized VM OS clocks and normal client certificate
verification. It accepts rows 09, 10, 11 and 14, leaves 12 and 13 partial, and
stops at row 15's missing per-request upstream mTLS failure reason. Inspection
ALLOW/COMPLETE is a pre-forward content decision, not proof of delivery. The
origin received no HTTP request and the client got 502; the missing diagnostic
is the failed requirement. Running was restored at version 88 and the separate
Candidate draft was preserved. Installed NGFW binary hashes did not change.
Use the linked ACCEPTANCE_ASSESSMENT.json as the final verdict; the raw runner
result retained its initial partial classification pending specification review.

The M4-15 fix/recheck at 12:32 UTC now closes that failed requirement with 14
real-VM controls and the matched engine/API/proxy build. Its report preserves
the original inspection verdict and records the upstream result separately.
Mandatory mTLS returns 502/no origin with an explicit request-correlated reason;
optional auth returns 200, and certificate/network faults keep their own codes.
Running was restored at version 92, M4 OFF. Rows 12/13 remain partial and the
remaining unrun rows are unchanged; this is not complete M4 sign-off.
