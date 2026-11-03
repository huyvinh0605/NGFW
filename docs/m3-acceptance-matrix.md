# M3 acceptance matrix

M3 acceptance status 2026-10-28: **31 PASS, 1 FAIL (M3-29), 3 PARTIAL (M3-19/23/37), 3 NOT_RUN (M3-33/34/36)**. [Latest UI results, timeout failure and remaining scope](../artifacts/m3-continuation-20261028/RESULTS.md). Status is based on the recorded scopes below; whole M3 is not yet accepted.
M3-01 là capability/packet probe trong namespace cô lập; M3-35 là code gate.
Xem [M3-02 PASS và bản sửa conntrack overflow](../artifacts/m3-02-repair-20261026T085256Z/RESULTS.md), [đính chính setup của lượt cũ](../artifacts/m3-02-20261026T083043Z/CORRECTION.md) và [bản sửa M3-01/M3-35](../artifacts/m3-blockers-fix-20261025T091814Z/RESULTS.md).
Source đã được triển khai và các gate cục bộ được ghi riêng trong
[implementation status](m3/IMPLEMENTATION_STATUS.md). Tài liệu này không phải
bằng chứng M3 đã chạy trên appliance. Xem [master spec](M3_IMPLEMENTATION_PLAN.md),
[coding tasks](m3/CODING_TASKS.md), [Linux runbook](../tests/integration/m3/README.md).

Mỗi row khi thực thi phải thêm: git/worktree hash, config generation/hash,
sensor package/build/rules hash, thời gian, command, exit code và evidence path.
PASS cần kết quả expected cụ thể; SKIP/NOT_RUN không tính PASS. Unit/fake
integration và live network evidence ghi ở hai cột trạng thái khác nhau.

## Ma trận bắt buộc

| ID | Tiêu chí và kết quả phải thấy | Code/task | Unit/fake regression | Ubuntu traffic/evidence | Local | VM |
|---|---|---|---|---|---|---|
| M3-00 | M1/M2 baseline trên cùng topology hoạt động trước khi bật M3 | T00/T29 | Existing suites | [Initial failure](../artifacts/m3-acceptance-20261025T0809Z/RESULTS.md); [network repair and live retest](../artifacts/m1-network-drift-fix-20261025/RESULTS.md), TCP/HTTP/NAT/CT/API evidence | NOT_RUN | PASS (VM retest, Running v92) |
| M3-01 | Suricata có NFLOG/NFQ/socket và nft support đúng schema | T01/T16/T17 | Fake capability failure; production/probe schema contract | [Probe PASS and raw evidence](../artifacts/m3-blockers-fix-20261025T091814Z/RESULTS.md); [historical failed attempt](../artifacts/m3-acceptance-20261025T090114Z/M3-01/RESULTS.md) | PASS (schema contract) | PASS (schema 2 readback, real NFQ/NFLOG/socket, saturation and bypass in isolated namespace) |
| M3-02 | M3 OFF giữ L3 routing/firewall/NAT/cache M2; không cần sensor | T03/T18/T21 | Policy setup preconditions; full Linux regression | LAN/WAN, DNAT, established, default deny khi không Suricata | PASS (5 runner setup checks) | PASS (v93: real MASQUERADE, verified TLS DNAT, same socket/CT/SessionID, kernel cache ACCEPT and default DROP trace; [evidence](../artifacts/m3-02-repair-20261026T085256Z/RESULTS.md)) |
| M3-03 | Candidate save/load/validate không apply/version increment | T03/T26 | No-side-effect + revision tests | Running hash/nft hash trước-sau; audit không COMMIT | PASS (7 runner regressions; management no-activation/revision tests) | PASS (25 VM assertions; IDS Candidate save/load/validate/edit; no activation; [analysis](m3/M3_03_CANDIDATE_ACCEPTANCE.md), [raw evidence](../artifacts/m3-03-repair-20261026T104615Z/RESULTS.md)) |
| M3-04 | Bad profile/mode/fail mode/risk/TLS/app config bị từ chối backend | T03/T04/T05 | Table-driven validation | API400, kernel/running unchanged | NOT_RUN | PASS (34 invalid variants, 216 assertions; valid IPS positive control; Candidate restored, no commit; [evidence](../artifacts/m3-04-20261026T112034Z/RESULTS.md)) |
| M3-05 | Early App-ID before long-lived flow closes | T10/T16 | Permission fixture and unprivileged real Suricata syntax PASS; App-ID unit coverage remains separate | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ids-final/result.json): HTTP/TLS/DNS/SSH detected within 5s before socket close | PASS | PASS |
| M3-06 | HTTP nhận diện bằng evidence, có source/confidence | T10/T15 | Request/response + wrong-port fixtures | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ids-final/result.json): HTTP on TCP18083 with strong sensor evidence | NOT_RUN | PASS |
| M3-07 | TLS chỉ báo TLS/metadata quan sát được; không claim decrypted HTTP | T10/T25 | ClientHello/missing cert tests | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ids-final/result.json): Verified TLS remains TLS; actual EVE has SNI/version, no decryption claim | NOT_RUN | PASS |
| M3-08 | DNS/SSH nhận diện; TCP ngẫu nhiên port443 không VERIFIED HTTPS | T10/T16 | Protocol/random/empty/malformed | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ids-final/result.json): Real DNS/SSH plus random TCP443 negative control | NOT_RUN | PASS |
| M3-09 | App-ID/helper parse sai không panic và không thành CLEAN | T06/T10 | Fuzz/truncated/invalid enum | [Isolated malformed-EVE reader/reducer ? real IPC/API on Ubuntu](../artifacts/m3-continuation-20261027/ngfw-m3-source-20261027-run4/M3-09-result.json); synthetic input, real Linux conntrack source | NOT_RUN | PASS (isolated source integration) |
| M3-10 | IDS signature cảnh báo; traffic marker vẫn đến server | T14/T16/T18 | IDS cannot create deny intent | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ids-final/result.json): IDS marker delivered with correlated ALERT and no enforcement | NOT_RUN | PASS |
| M3-11 | IPS signature chặn packet marker trực tiếp bằng NFQUEUE | T16/T18 | Correct mode/action mapping | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ips-final/result.json): Two-side PCAP and upstream log prove real NFQUEUE marker drop | NOT_RUN | PASS |
| M3-12 | Attack xuất hiện muộn trên cached established connection vẫn bị IPS | T18/T20 | Chain/mark regression | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ips-final/result.json): Late attack on same socket and verified cached connection | NOT_RUN | PASS |
| M3-13 | Source block/manual revoke thắng cached allow và IPS allow | T18/T19 | Precedence tests | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/guards-final/result.json): Source block and manual revoke override cached IPS ALLOW | NOT_RUN | PASS |
| M3-14 | IDS/IPS selection first-match, không queue unrelated/MGMT | T05/T18 | Terminal no-profile match; OR semantics | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/selection-final/result.json): IDS/IPS first match, no-profile termination and real MGMT exclusion | NOT_RUN | PASS |
| M3-15 | MASQUERADE EVE và API original/translated cùng SessionID | T11/T12 | O/R/T/P aliases | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/ids-final/result.json): Real MASQUERADE EVE/CT/API aliases retain one SessionID | NOT_RUN | PASS |
| M3-16 | DNAT public8443→private443 correlate cùng session | T11/T12 | Translated service/reverse tests | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/nat-live-2/result.json): Verified TLS public8443 to DMZ443; EVE policy-view correlation | NOT_RUN | PASS |
| M3-17 | Reply/response không tạo session thứ hai; double NAT mapping đúng | T11/T12 | Both directions+double NAT | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/nat-live-2/result.json): Repeated replies retain one session; real double NAT aliases | NOT_RUN | PASS |
| M3-18 | Event đến trước CT/recently closed vẫn giữ alert đúng trạng thái | T08/T12/T13 | Retry/closed event tests | [Event-before-CT and delayed event on closed history](../artifacts/m3-continuation-20261027/ngfw-m3-source-20261027-run4/M3-18-result.json); same event ID, no reopen | NOT_RUN | PASS (isolated source, real kernel CT) |
| M3-19 | Tuple/CT ID/Suricata flow ID reuse không block nhầm connection | T12/T19 | Delayed event+new incarnation+sensor epoch | [Tuple/flow reuse probe](../artifacts/m3-continuation-20261027/source-run5.json) passes real tuple reuse/new epoch/ambiguous delayed-event handling; actual kernel CT ID collision not forced | NOT_RUN | PARTIAL (CT ID reuse evidence pending) |
| M3-20 | Application restriction chỉ trên matched ALLOW+IPS; unknown fail-open hiển thị rõ | T04/T14/T19 | Decision table + timeout | [2026-10-27 live evidence](../artifacts/m3-continuation-20261027/app-live-2/result.json): HTTP allowed, SSH APPLIED/SESSION guard, unknown fail-open, base DROP retained | PASS | PASS |
| M3-21 | Same-L3 policies with different apps are rejected as shadowed | T04/T26 | Backend validator tests PASS | [Real VM browser form](../artifacts/m3-continuation-20261028/vm-browser/ui-pending-run3/result.json): HTTP and TLS policies share L3 scope; second returns HTTP 400, warning names earlier policy; Candidate unchanged | PASS (backend) | PASS |
| M3-22 | Suricata stop: forwarding base tiếp tục, inspection unavailable | T09/T20 | No listener/health tests | [Final service recovery run](../artifacts/m3-continuation-20261027/recovery-final/result.json): stop IDS/IPS separately, base ALLOW/DROP preserved, unavailable is explicit | NOT_RUN | PASS |
| M3-23 | Suricata treo/queue đầy: không nhầm với no-listener; fail-open có giới hạn đo | T20 | Stall/lease/timeout tests | [Real SIGSTOP/lease run](../artifacts/m3-continuation-20261027/recovery-final/result.json): listener stall, bypass after 1.766s; saturation/loss/recovery metrics still incomplete | NOT_RUN | PARTIAL |
| M3-24 | Sensor restart/EVE rotation hồi phục, không replay nhân đôi threat | T07/T08/T09 | Rename/copytruncate/epoch/checkpoint | [Live rotation/restart run](../artifacts/m3-continuation-20261027/rotation-live-1/result.json): rename/HUP, copytruncate, sensor restart; four distinct markers without replay, visible reader gap | NOT_RUN | PASS |
| M3-25 | Engine restart resync M2, old mark/app evidence không blindly trusted | T15/T21/T22 | Recovery/current gen tests | [Final restart run](../artifacts/m3-continuation-20261027/recovery-final/result.json): same live kernel identity, runtime resync, old app evidence not blindly reused | NOT_RUN | PASS |
| M3-26 | Commit/rollback thay inspection thật và generation luôn tăng | T21 | Fault every stage/idempotency | [Live commit/rollback run](../artifacts/m3-continuation-20261027/recovery-final/result.json): generations 146/147/148/149 and actual OFF?IDS?IPS?IDS selection | NOT_RUN | PASS |
| M3-27 | Fail activation/reboot journal khôi phục previous network+inspection | T21 | Controller recovery tests | [Linux faults/SIGKILL journal recovery and live appliance API failures](../artifacts/m3-recovery-repair-20261028/RESULTS.md): baseline restored, repeated failure and valid next commit verified. Whole-appliance reboot mid-activation not performed | NOT_RUN | PASS (recorded recovery scope) |
| M3-28 | API/UI chết không dừng M1/M2/IPS sensor | T22/T24 | IPC outage/WS cancel tests | [API outage run](../artifacts/m3-continuation-20261027/recovery-final/result.json): benign traffic and real IPS marker drop continue with engine/sensor PID unchanged | NOT_RUN | PASS |
| M3-29 | Event/session pagination, filters, NAT fields, RBAC and timeouts | T22/T23 | Auth/filter tests and logout regression PASS | [Real IDS/NAT pagination and filters](../artifacts/m3-continuation-20261028/api-pages-live-2/result.json), [VM RBAC](../artifacts/m3-rbac-20261026T163657Z/role-probe-new-binary.json); [actual API + stalled Unix IPC](../artifacts/m3-continuation-20261028/vm-browser/api-timeout-run1/result.json) FAIL: transport timeout returns 503 ENGINE_UNAVAILABLE instead of 504 ENGINE_TIMEOUT | PASS (covered scope) | FAIL (IPC transport timeout classification) |
| M3-30 | WS authentication, lifecycle, reconnect and browser proxy | T24/T25 | WS and web reconnect tests PASS | [Direct API WS auth](../artifacts/m3-api-followup-20261026T151100Z/live-ws-go-result.json) and [Chromium via Vite](../artifacts/m3-continuation-20261028/vm-browser/live-m3-ui-result-run-6.json): authenticated frames, reconnect, logout closes sockets and prevents reconnect | PASS (unit) | PASS |
| M3-31 | UI bad record không crash, thiếu field không fake confidence/Blocked/Clean | T25 | React tests invalid/missing fields | [VM Chromium UI assertions/screenshots](../artifacts/m3-continuation-20261028/vm-browser/ui-pending-run3/result.json): malformed/missing fields, IDS ALERT, REPORTED/PACKET and APPLIED/SESSION; browser-only response fixtures, no fake engine events | NOT_RUN | PASS (UI fixtures; live enforcement covered separately) |
| M3-32 | Form→candidate→GET→edit roundtrip; load Running/save không commit | T26 | Policy/JSON workflow regressions | [Form create/GET/edit/Validate/JSON/Back](../artifacts/m3-continuation-20261028/vm-browser/ui-pending-run3/result.json) plus [JSON load Running/save Candidate](../artifacts/m3-continuation-20261028/vm-browser/live-m3-ui-result-run-6.json); Running v164 unchanged, original Candidate restored, no Commit/Rollback | NOT_RUN | PASS |
| M3-33 | Queues/history/cache/retention bounded và overload có counters | T08/T12/T13/T15/T30 | Count+byte+TTL saturation | Soak memory/disk/event loss + M1 traffic continuity | NOT_RUN | NOT_RUN |
| M3-34 | Installer lặp lại giữ config, script chạy khi copy Windows, quyền đúng | T27/T28 | Fake install/script tests | Clean/reinstall logs, modes0755, API no privileges/EVE read | NOT_RUN | NOT_RUN |
| M3-35 | Full Go test/vet/race and web test/build gates without losing M1/M2 regression | T30 | [Windows web 39/39 and build](../artifacts/m3-rbac-20261026T163657Z/RESULTS.md); Windows focused reader 30 runs | [Linux full Go test](../artifacts/m3-rbac-20261026T163657Z/go-test-all-final.txt), [vet](../artifacts/m3-rbac-20261026T163657Z/go-vet-final.txt), [race](../artifacts/m3-rbac-20261026T163657Z/go-race-final.txt) PASS on final source; [M1/M2/M3-02 after deployment](../artifacts/m3-rbac-20261026T163657Z/RESULTS.md) PASS | PASS | PASS |
| M3-36 | Có đo OFF/IDS/IPS cùng workload 3 lần, không tự đặt số hiệu năng | T30 | Harness aggregation test | raw throughput/p50/p95/p99/loss/CPU/RAM/lag/version | NOT_RUN | NOT_RUN |
| M3-37 | Output mode/action/scope trung thực khi correlation/enforcement thiếu | T06/T14/T19/T25 | Source action/verdict and guard operation race regressions PASS | [Real REPORTED/PACKET and APPLIED/SESSION](../artifacts/m3-continuation-20261027/RESULTS.md); uncorrelated and failed-adapter VM variants pending | PASS (covered regressions) | PARTIAL |

## Baseline test commands

```bash
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./internal/engine/... ./internal/session/... \
  ./internal/inspection/... ./internal/dataplane/... ./internal/config/... \
  ./internal/engineipc/... ./internal/management/...
```

Trong thư mục `web`: `npm ci`, `npm test`, `npm run build`.
Các script M3 trong runbook đã được tạo. Chỉ đổi trạng thái từng hàng sau khi
script tương ứng chạy và evidence thật đã được lưu.

## Evidence index bắt buộc cho mỗi lần chạy

```text
docs/evidence/M3/<UTC-run-id>/
  manifest.json              # source/config/version/topology/tool versions
  summary.json               # ID -> PASS/FAIL/NOT_RUN + reason + evidence refs
  commands.jsonl             # sanitized argv/start/end/exit_code
  baseline/                  # M1/M2 before enabling M3
  M3-11/
    before/ after/           # nft JSON, CT dump, API JSON, health
    eve.jsonl journal.log
    client.out upstream.log
    lan.pcap dmz.pcap        # optional per scenario, hashes recorded
```

Không commit token/secret/raw user traffic. Chỉ dùng traffic lab tổng hợp.
Evidence path tồn tại thật mới được link. Raw data quá lớn lưu ngoài git và
ghi SHA-256/location trong manifest. Báo cáo cuối phải giữ các row chưa chạy.

## Quy tắc kết luận

- Local tests pass + production adapters/config/script đủ: xét checklist
  code-complete trong master. Thiếu race hoặc capability probe bắt buộc vẫn là blocker.
- VMware lab chưa chạy: **ACCEPTANCE PENDING**, không “M3 completed”.
- VM row fail liên quan M1/M2: giữ fail và link blocker; không bỏ row khỏi mẫu.
- Coverage limitation hợp lệ (TLS encrypted, event ambiguous) pass khi hệ thống
  thể hiện đúng unavailable và không tự enforce nhầm, không cần bịa dữ liệu đầy đủ.
