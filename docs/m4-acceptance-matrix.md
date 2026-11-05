# M4 — Ubuntu Acceptance Matrix

Each row requires the source hash, configuration generation/hash, kernel/nftables/Suricata/Go versions, commands, exit codes, and evidence path. `NOT_RUN` is never PASS.

| ID | Mandatory criterion | Minimum evidence | VM |
|---|---|---|---|
| M4-00 | Required M1/M2 baseline and M3 OFF/IDS/IPS behavior still works before M4 | prior matrices + current run IDs | PASS: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-00-baseline-assessment.json). Prior M1/M2/M3 baseline evidence plus current OFF/IDS/IPS and NAT controls; not a full rerun of those milestones. |
| M4-01 | Capability probe: redirect/original-dst/DNAT ordering/Suricata socket/ALPN | probe raw output + nft JSON | PASS: [m4-continuation-20261105T024055Z](../artifacts/m4-continuation-20261105T024055Z/M4-01-capability-probe/assertions.json), real TPROXY/original destination/TLS/ALPN and Suricata socket probe in isolated namespaces. |
| M4-02 | M4 OFF does not change forwarding/NAT/M3 behavior | nft diff, traffic baseline | PASS: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-02-comparison/assertions.json). Four valid global M3/M4 ON/OFF combinations: IDS marker, IPS clean/marker, verified HTTPS MASQUERADE and DNAT. M3 OFF temporarily detaches policy profile references; registry objects are preserved and restored. |
| M4-03 | Invalid gate/TLS/exclusion config is rejected and kernel state is unchanged | API400 + hashes before/after | PASS: [nine invalid configs](../artifacts/m4-continuation-20261105T024055Z/M4-03-invalid-config/assertions.json), API400 and Candidate/Running/kernel unchanged. |
| M4-04 | Clean HTTP/1.1 request reaches upstream | client output + upstream nonce log | PASS: [2026-10-24](../artifacts/m4-fix-20261024/http-final/result.json) |
| M4-05 | HTTP/1.1 SQLi is blocked before upstream | 403 + EVE SID + upstream absence | PASS: [2026-10-24](../artifacts/m4-fix-20261024/http-final/result.json), SID 9904003 |
| M4-06 | HTTP/1.1 XSS is blocked before upstream | 403 + EVE SID + upstream absence | PASS: [2026-10-24](../artifacts/m4-fix-20261024/http-final/result.json), SID 9904004 |
| M4-07 | HTTPS DECRYPT clean path: client trusts CA, upstream is verified, request reaches server | TLS states + upstream log | PASS: [2026-10-24 recheck](../artifacts/m4-health-recheck-20261024T0558Z/RESULTS.md); CA/SAN verified, upstream nonce and complete HTTPS inspection, counters observed after heartbeat |
| M4-08 | HTTPS DECRYPT SQLi/XSS never reaches upstream | proxy decision + EVE + server absence | PASS: [2026-10-24](../artifacts/m4-health-recheck-20261024T0558Z/RESULTS.md); 403, SIDs 9904003/9904004, no upstream request, block counters advance |
| M4-09 | BYPASS TLS preserves end-to-end certificate/upstream bytes | capture + client cert observation | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); origin leaf/body hashes and reassembled TLS bytes identical in both directions |
| M4-10 | TLS exclusion correctly matches domain/CIDR/port; non-matches still decrypt/gate | config + decision events | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); 11 selector variants, generation-bound engine decisions, non-matching SQLi blocked before origin |
| M4-11 | ClientHello split across multiple TCP reads still parses/tunnels correctly | pcap + logs | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); 7 writes, captured TCP segments, BYPASS byte identity and DECRYPT SQLi block |
| M4-12 | Unavailable SNI/ECH-like case is not falsely reported as decrypted/clean | health/event limitation | PARTIAL: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); no-SNI CLOSE/OPEN and explicit ECH capability limitation pass; ECH traffic not exercised |
| M4-13 | Invalid upstream certificate/hostname mismatch returns 502; no InsecureSkipVerify | TLS error + upstream evidence | PASS: [independent untrusted chain](../artifacts/m4-continuation-20261105T024055Z/M4-13-untrusted-chain/assertions.json) and [hostname mismatch](../artifacts/m4-continuation-20261105T024055Z/M4-13-hostname-mismatch/assertions.json), verified client TLS, upstream 502/reason/counter, no origin HTTP. |
| M4-14 | Client CA distrust/pinning-like failure does not silently bypass | handshake fail + no upstream request | PASS: [2026-10-24](../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md); both clients reject MITM, handshake-fail counters increment, no bypass/origin request |
| M4-15 | Upstream mTLS requirement reports unsupported/failure correctly | reason code + no false clean | PASS after fix: [2026-10-24 recheck](../artifacts/m4-mtls-fix-20261024T113924Z/RESULTS.md); TLS 1.2/1.3 require client cert: 502, no origin request, correlated TLS_UPSTREAM_MTLS_UNSUPPORTED; optional auth and negative controls pass. Earlier FAIL evidence retained |
| M4-16 | Clean HTTP/2 request passes on the same TLS connection | h2 evidence + upstream log | PASS after API DTO fix: [live recheck](../artifacts/m4-forward-fix-20261030/h2-recheck/result.json), verified TLS 1.3/h2, exact origin, COMPLETE ALLOW and successful `forward` preserved through API; [earlier FAIL retained](../artifacts/m4-continuation-20261030/RESULTS.md) |
| M4-17 | One H2 connection: concurrent clean + malicious requests; only malicious request is blocked | same connection ID, distinct request IDs, upstream only clean | PASS: [live 2-request batch](../artifacts/m4-forward-fix-20261030/h2-isolation/M4-17/assessment.json), one TCP/TLS connection, clean 200, SQLi 403, distinct request/decision/ordinal identities, zero attack at origin |
| M4-18 | 20+ concurrent H2 requests show no cross-request verdict/body contamination | decision map + upstream nonces | PASS: [24 concurrent requests](../artifacts/m4-forward-fix-20261030/h2-isolation/M4-18/assessment.json), 16 clean/8 SQLi-XSS, one socket/session, matching origin body hashes; 2 workers and configured 10-second inspection deadline, not a throughput/overload claim |
| M4-19 | Attack in chunked body is inspected and blocked | client + EVE + upstream absence | PASS: [live body run](../artifacts/m4-forward-fix-20261030/body-limits-run2/result.json), clean dechunked body hash preserved, SQLi split across chunks blocked with SID 9904003 and no origin request |
| M4-20 | gzip/deflate attack is blocked after decompression | decoded-size evidence + EVE | PASS: [live body run](../artifacts/m4-forward-fix-20261030/body-limits-run2/result.json), gzip and zlib-deflate clean/SQLi controls; original compressed clean bytes preserved, decoded attacks blocked before origin |
| M4-21 | Decompression bomb above limit follows configured policy | 413/allow-partial + counters | PASS after fix `62d6e0e`: [2026-11-04 LIVE](../artifacts/m4-acceptance-20261104T085259Z/RESULTS.md), all four fail-mode/oversize combinations, independent decoded-byte/ratio limits, PARTIAL coverage and original gzip replay only for OPEN+ALLOW_PARTIAL. [Earlier FAIL retained](../artifacts/m4-forward-fix-20261030/M4-21-DIAGNOSIS.json) |
| M4-22 | Body above max follows BLOCK or ALLOW_PARTIAL profile behavior without silent bypass | response + coverage event | PASS: [2026-11-04](../artifacts/m4-acceptance-20261104T085259Z/CASE_LEDGER.json), BLOCK at 64 KiB; OPEN+ALLOW_PARTIAL at 4 KiB forwards all 8,200 original bytes with PARTIAL coverage |
| M4-23 | Malformed framing/header overflow is never forwarded upstream | 400/431 + server absence | PASS: [2026-11-04](../artifacts/m4-acceptance-20261104T085259Z/CASE_LEDGER.json), malformed header/chunk return 400, 40,000-byte header returns 431; no upstream packets or false inspection result |
| M4-24 | Suricata request-worker timeout under fail-open | request passes + coverage unavailable + counter | PASS: [monitored LIVE case](../artifacts/m4-acceptance-20261104T085259Z/M4-24-timeout-open-monitored/evidence.json), verified TLS 1.3, 200/original body at origin, ALLOW/UNAVAILABLE, GATE_INSPECTION_TIMEOUT and counter increment before pool recovery; initial missed-sample assertion retained |
| M4-25 | Suricata request-worker timeout under fail-close | 503 + server absence + reason | PASS: [2026-11-04](../artifacts/m4-acceptance-20261104T085259Z/M4-25-timeout-close/evidence.json), 503/BLOCK/UNAVAILABLE with timeout reason/counter, zero upstream packets |
| M4-26 | Request-worker crash/socket down produces degraded health and correct policy behavior | health + open/close tests | PASS: [2026-11-04](../artifacts/m4-acceptance-20261104T085259Z/CASE_LEDGER.json), real worker crash under OPEN/CLOSE gives 200/503 with GATE_SENSOR_UNAVAILABLE, degraded health then recovery; subsequent clean 200 and SQLi 403 |
| M4-27 | Worker queue full remains bounded with no unbounded memory growth | queue counters + RSS/soak | PASS for bounded overload: [2026-11-05 LIVE](../artifacts/m4-continuation-20261105T005325Z/RESULTS.md), 1-item queue yields 3 allowed/5 rejected; independent 64 KiB byte cap with 40,000-byte bodies yields 1 allowed/7 rejected; GATE_QUEUE_FULL/UNAVAILABLE, exact origin correlation, zero residual job directories and measured proxy/worker RSS. The scoped 20-minute soak is recorded at M4-41 |
| M4-28 | Proxy capacity/per-client limit remains bounded | 429/503 + counters + recovery | PASS: [2026-11-05 LIVE](../artifacts/m4-continuation-20261105T005325Z/CASE_LEDGER.json), per-client 2 with global 4 and independent global 2 across two client IPs; each batch 2×200/6×503, capacity counter increments, no upstream request or false inspection for rejected requests. Cold-start RSS diagnostic guard failure retained; steady-state recheck and recovery controls pass |
| M4-29 | DNAT public HTTPS -> DMZ: original destination/session is correct and gate still blocks | conntrack + API + proxy + server log | PASS: [real public8443 DNAT](../artifacts/m4-continuation-20261105T024055Z/M4-29-assessment.json), original/translated tuple and CT/session/request linkage, clean200 and SQLi403/no origin. |
| M4-30 | MASQUERADE outbound HTTPS gate preserves correct session/NAT alias identity | CT/API/request IDs | PARTIAL: [gated outbound and real MASQUERADE control](../artifacts/m4-continuation-20261105T024055Z/M4-30-assessment.json); proxy has independent client/upstream TCP legs, gated client leg snat=false; simultaneous gated-session SNAT alias unproven. |
| M4-31 | API/UI outage does not stop proxy/engine request enforcement | stop API + repeat malicious/clean | PASS: [2026-11-05](../artifacts/m4-continuation-20261105T005325Z/M4-31-api-outage-assessment.json), API stopped/8080 connection refused; clean 200 and SQLi 403/zero upstream packets, correlated engine verdicts after API recovery; engine/proxy PIDs unchanged |
| M4-32 | Proxy restart has explicit behavior for existing connections and recovers for new connections | logs/health/client behavior | PASS: [real proxy restart](../artifacts/m4-continuation-20261105T024055Z/M4-32-proxy-restart/assertions.json), existing verified TLS closes, outage has no origin/false inspection; recovery clean200/SQLi403. |
| M4-33 | Engine restart does not reuse stale request decisions; selector/gate resyncs | generation IDs + nft + new decisions | PASS: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-33-engine-restart/assertions.json). Real engine restart at unchanged generation; stale engine-instance replay rejected, existing TLS closed, selector/route resynced, recovery clean200/SQLi403. |
| M4-34 | Commit OFF→DECRYPT/gate→rollback changes nft/proxy behavior correctly | generations + rules + traffic | PASS: [real OFF/ON/Rollback](../artifacts/m4-continuation-20261105T024055Z/M4-34-activation-cycle/assertions.json), kernel hook and 200/403/origin behavior; original ON content restored. |
| M4-35 | Activation failure/reboot journal restores previous M1/M3/M4 state | induced failure + restart evidence | NOT_RUN |
| M4-36 | CA key permissions are correct and API cannot read the private key | stat/getfacl + API negative test | PASS: [real UID open tests](../artifacts/m4-acceptance-20261104T085259Z/M4-36-ca-permissions/evidence.json), CA directory 0700/key 0600 owned by proxy, no additional ACL; API UID gets PermissionError, proxy UID can open; no key bytes exported |
| M4-37 | Logs/events redact Authorization/Cookie/body/token query data | synthetic secret test + grep evidence | PASS in tested log paths: [2026-11-05](../artifacts/m4-continuation-20261105T005325Z/M4-37-redaction-assessment.json), synthetic Authorization/Cookie/query/body values in clean and SQLi requests; 200/403 with positive input/origin proof, zero occurrences in request evidence, correlated session detail, new runtime events and API/engine/proxy journal. Input/client/origin fixtures intentionally retain dummy values |
| M4-38 | Unsupported WebSocket Upgrade is rejected before upstream forwarding and never claims frame inspection | 400 + upstream absence + explicit limitation | PASS: [2026-11-04 LIVE](../artifacts/m4-acceptance-20261104T085259Z/M4-38-websocket-upgrade/evidence.json), 400/no upstream packets; [capability](../artifacts/m4-acceptance-20261104T085259Z/prechecks-36-38.json) explicitly rejects Upgrade and disclaims WebSocket frame inspection |
| M4-39 | UDP/443 follows explicit profile behavior: block or unsupported, never falsely reported as decrypted | QUIC client/counter/event | PASS: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-39-quic/assertions.json). Real verified HTTP3/QUIC: forward200, explicit block_quic yields LAN Initial/no DMZ/no origin, recovery200. No HTTP3 decryption or automatic TCP fallback claimed. |
| M4-40 | Race/fuzz/full Go/vet/web gates PASS on Linux | raw command outputs | PASS: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-40-overflow-diagnostic/assertions.json). Full Linux Go/race/vet/fuzz/web gates and ten privileged overflow runs pass after test-only receive-drain/timestamp-presence repair 6198fcc; production binaries unchanged. |
| M4-41 | Request-gate soak keeps memory/temp-file/queue growth bounded | RSS, file count, counters | PASS: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-41-soak/assertions.json). 20-minute finite soak, 600 verified TLS1.3/h2 requests, 450 clean200/150 SQLi403; sampled RSS/FD/thread/temp-file bounds and final drain verified. No multi-day or throughput claim. |
| M4-42 | Benchmark HTTP1/H2 plaintext/TLS gate across 3 runs and report p50/p95/p99 | raw results + config hashes | PARTIAL: [2026-11-05 evidence](../artifacts/m4-continuation-20261105T152913Z/M4-42-benchmark/assertions.json). Three runs of supported HTTP1 plaintext/TLS and H2-over-TLS, OFF/ON, 100 measured +5 warmup per cell. Initial run3 curl56/reset remains unresolved despite separate successful recheck. |

## Current checkpoint — 2026-11-05

Cumulative: **39 PASS, 3 PARTIAL, 0 FAIL, 1 NOT_RUN** across 43 rows. This combines historical
evidence with the current run; it is not a complete one-build rerun or full M4
sign-off. [Latest report](../artifacts/m4-continuation-20261105T152913Z/RESULTS.md), [case ledger](../artifacts/m4-continuation-20261105T152913Z/CASE_LEDGER.json)
and [VM screenshots](../artifacts/m4-continuation-20261105T152913Z/SCREENSHOTS.md) record the scopes and retained failures.

Running/Candidate content is restored at v284. The overflow failure was
caused by test synchronization/timestamp assumptions; only that test changed
in commit 6198fcc. Production binaries and the dirty appliance checkout remain
unchanged. The 20-minute soak is finite; benchmark has an unresolved initial
connection reset and stays PARTIAL despite a separate successful recheck.

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

## Historical observations

The following checkpoints retain their original scopes; current row statuses above supersede earlier pending labels.

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
