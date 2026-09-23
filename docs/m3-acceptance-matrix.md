# M3 acceptance matrix

Trạng thái khởi tạo 2026-09-22: **tất cả tiêu chí dưới đây NOT_RUN**.
Tài liệu này chuẩn bị tiêu chí cho implementation; không phải bằng chứng M3 đã
chạy. Xem [master spec](M3_IMPLEMENTATION_PLAN.md),
[coding tasks](m3/CODING_TASKS.md), [Linux runbook](../tests/integration/m3/README.md).

Mỗi row khi thực thi phải thêm: git/worktree hash, config generation/hash,
sensor package/build/rules hash, thời gian, command, exit code và evidence path.
PASS cần kết quả expected cụ thể; SKIP/NOT_RUN không tính PASS. Unit/fake
integration và live network evidence ghi ở hai cột trạng thái khác nhau.

## Ma trận bắt buộc

| ID | Tiêu chí và kết quả phải thấy | Code/task | Unit/fake regression | Ubuntu traffic/evidence | Local | VM |
|---|---|---|---|---|---|---|
| M3-00 | M1/M2 baseline trên cùng topology hoạt động trước khi bật M3 | T00/T29 | Existing suites | M1/M2 matrices, original configs, versions | NOT_RUN | NOT_RUN |
| M3-01 | Suricata có NFLOG/NFQ/socket và nft support đúng schema | T01/T16/T17 | Fake capability failure | build-info, nft syntax, namespace capture/queue probe | NOT_RUN | NOT_RUN |
| M3-02 | M3 OFF giữ L3 routing/firewall/NAT/cache M2; không cần sensor | T03/T18/T21 | OFF compile equivalence | LAN/WAN, DNAT, established, default deny khi không Suricata | NOT_RUN | NOT_RUN |
| M3-03 | Candidate save/load/validate không apply/version increment | T03/T26 | No-side-effect + revision tests | Running hash/nft hash trước-sau; audit không COMMIT | NOT_RUN | NOT_RUN |
| M3-04 | Bad profile/mode/fail mode/risk/TLS/app config bị từ chối backend | T03/T04/T05 | Table-driven validation | API400, kernel/running unchanged | NOT_RUN | NOT_RUN |
| M3-05 | Rules early-App-ID chạy trước khi long-lived flow đóng | T10/T16 | EVE parser + real PCAP replay | HTTP/TLS/DNS/SSH observation khi connection còn active | NOT_RUN | NOT_RUN |
| M3-06 | HTTP nhận diện bằng evidence, có source/confidence | T10/T15 | Request/response + wrong-port fixtures | API context+EVE cùng session; HTTP cổng khác80 vẫn đúng nếu parser hỗ trợ | NOT_RUN | NOT_RUN |
| M3-07 | TLS chỉ báo TLS/metadata quan sát được; không claim decrypted HTTP | T10/T25 | ClientHello/missing cert tests | HTTPS traffic + SNI/version nếu sensor thấy; decrypted không true | NOT_RUN | NOT_RUN |
| M3-08 | DNS/SSH nhận diện; TCP ngẫu nhiên port443 không VERIFIED HTTPS | T10/T16 | Protocol/random/empty/malformed | UDP DNS + SSH banner + random443, API honest identity | NOT_RUN | NOT_RUN |
| M3-09 | App-ID/helper parse sai không panic và không thành CLEAN | T06/T10 | Fuzz/truncated/invalid enum | Inject malformed EVE test source isolated; runtime vẫn chạy | NOT_RUN | NOT_RUN |
| M3-10 | IDS signature cảnh báo; traffic marker vẫn đến server | T14/T16/T18 | IDS cannot create deny intent | Client response + server nonce log + correlated ALERT | NOT_RUN | NOT_RUN |
| M3-11 | IPS signature chặn packet marker trực tiếp bằng NFQUEUE | T16/T18 | Correct mode/action mapping | NFQUEUE/drop counter + EVE verdict + two-side pcap; marker không đến destination | NOT_RUN | NOT_RUN |
| M3-12 | Attack xuất hiện muộn trên cached established connection vẫn bị IPS | T18/T20 | Chain/mark regression | Cùng CT ID, current cache mark, benign trước rồi marker; drop thật | NOT_RUN | NOT_RUN |
| M3-13 | Source block/manual revoke thắng cached allow và IPS allow | T18/T19 | Precedence tests | Add block while established, packet sau bị drop tại guard | NOT_RUN | NOT_RUN |
| M3-14 | IDS/IPS selection first-match, không queue unrelated/MGMT | T05/T18 | Terminal no-profile match; OR semantics | Per-branch nft counters, MGMT SSH/API vẫn truy cập | NOT_RUN | NOT_RUN |
| M3-15 | MASQUERADE EVE và API original/translated cùng SessionID | T11/T12 | O/R/T/P aliases | CT dump + EVE + API JSON + WAN capture | NOT_RUN | NOT_RUN |
| M3-16 | DNAT public8443→private443 correlate cùng session | T11/T12 | Translated service/reverse tests | WAN request/DMZ log + CT/EVE/API tuples | NOT_RUN | NOT_RUN |
| M3-17 | Reply/response không tạo session thứ hai; double NAT mapping đúng | T11/T12 | Both directions+double NAT | Active IDs/index stats + original/reply pcaps | NOT_RUN | NOT_RUN |
| M3-18 | Event đến trước CT/recently closed vẫn giữ alert đúng trạng thái | T08/T12/T13 | Retry/closed event tests | Short flows+bounded replay; event updates same ID, không reopen | NOT_RUN | NOT_RUN |
| M3-19 | Tuple/CT ID/Suricata flow ID reuse không block nhầm connection | T12/T19 | Delayed event+new incarnation+sensor epoch | Recreate flows, epoch restart, ambiguous record stays unenforced | NOT_RUN | NOT_RUN |
| M3-20 | Application restriction chỉ trên matched ALLOW+IPS; unknown fail-open hiển thị rõ | T04/T14/T19 | Decision table + timeout | Known forbidden app→session guard; unknown→UNKNOWN_ALLOWED; L3 deny luôn deny | NOT_RUN | NOT_RUN |
| M3-21 | Hai policy cùng L3 khác apps bị báo shadow theo semantics M3 | T04/T26 | Duplicate/profile hash/priority tests | API Validate/Commit reject, UI thông báo đúng rule che phủ | NOT_RUN | NOT_RUN |
| M3-22 | Suricata stop: forwarding base tiếp tục, inspection unavailable | T09/T20 | No listener/health tests | stop IDS/IPS riêng; base allow+deny và API health/lease/counters | NOT_RUN | NOT_RUN |
| M3-23 | Suricata treo/queue đầy: không nhầm với no-listener; fail-open có giới hạn đo | T20 | Stall/lease/timeout tests | SIGSTOP/overload, recovery time, lost queued packets, base deny giữ | NOT_RUN | NOT_RUN |
| M3-24 | Sensor restart/EVE rotation hồi phục, không replay nhân đôi threat | T07/T08/T09 | Rename/copytruncate/epoch/checkpoint | IDs+counts trước/sau rotate/restart, coverage gap nếu mất data | NOT_RUN | NOT_RUN |
| M3-25 | Engine restart resync M2, old mark/app evidence không blindly trusted | T15/T21/T22 | Recovery/current gen tests | Same live CT, sessions resync, lease expires/renews, coverage PARTIAL | NOT_RUN | NOT_RUN |
| M3-26 | Commit/rollback thay inspection thật và generation luôn tăng | T21 | Fault every stage/idempotency | OFF→IDS→IPS→rollback, nft+Running+sensor selection actual | NOT_RUN | NOT_RUN |
| M3-27 | Fail activation/reboot journal khôi phục previous network+inspection | T21 | Controller recovery tests | Induced nft/route/verify failure, restart journal; baseline restored | NOT_RUN | NOT_RUN |
| M3-28 | API/UI chết không dừng M1/M2/IPS sensor | T22/T24 | IPC outage/WS cancel tests | Stop API, keep flows/marker test, restart API reconnect same runtime | NOT_RUN | NOT_RUN |
| M3-29 | Events/session APIs pagination, filters, NAT fields, RBAC và timeout đúng | T22/T23 | Handler/IPC contract tests | Curl authenticated/forbidden/query/error outputs bounded | NOT_RUN | NOT_RUN |
| M3-30 | WS lifecycle/security phân biệt, reconnect/new stream không mất state im lặng | T24/T25 | StrictMode/reconnect/gap tests | Vite proxy/browser+API log, no sustained EPIPE reconnect loop | NOT_RUN | NOT_RUN |
| M3-31 | UI bad record không crash, thiếu field không fake confidence/Blocked/Clean | T25 | React tests invalid/missing fields | Browser error console+screens, IDS vs packet drop vs session guard | NOT_RUN | NOT_RUN |
| M3-32 | Form→candidate→GET→edit roundtrip; load Running/save không commit | T26 | Policy/JSON workflow regressions | Candidate revision/status/navigation actual in browser | NOT_RUN | NOT_RUN |
| M3-33 | Queues/history/cache/retention bounded và overload có counters | T08/T12/T13/T15/T30 | Count+byte+TTL saturation | Soak memory/disk/event loss + M1 traffic continuity | NOT_RUN | NOT_RUN |
| M3-34 | Installer lặp lại giữ config, script chạy khi copy Windows, quyền đúng | T27/T28 | Fake install/script tests | Clean/reinstall logs, modes0755, API no privileges/EVE read | NOT_RUN | NOT_RUN |
| M3-35 | Build/test/vet/race pass, không xóa regression M1/M2 | T30 | Full commands master17 | Linux race/raw outputs, binary hashes, no mock-only claim | NOT_RUN | NOT_RUN |
| M3-36 | Có đo OFF/IDS/IPS cùng workload 3 lần, không tự đặt số hiệu năng | T30 | Harness aggregation test | raw throughput/p50/p95/p99/loss/CPU/RAM/lag/version | NOT_RUN | NOT_RUN |
| M3-37 | Output mode/action/scope trung thực khi correlation/enforcement thiếu | T06/T14/T19/T25 | allowed vs verdict.drop, missing CT ID, failed nft | Event REPORTED/PACKET khác APPLIED/SESSION; uncorrelated vẫn thấy | NOT_RUN | NOT_RUN |

## Baseline test commands

```bash
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./internal/engine/... ./internal/session/... \
  ./internal/inspection/... ./internal/dataplane/... ./internal/config/... \
  ./internal/engineipc/... ./internal/management/...
```

Trong thư mục `web`: `npm ci`, `npm test`, `npm run build`.
Các script M3 ghi trong runbook **chưa được tạo ở bước viết specification**;
agent tạo chúng tại T01/T29 rồi mới ghi kết quả chạy.

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
