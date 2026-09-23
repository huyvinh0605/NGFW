# M3 Linux integration runbook — đặc tả cho test runner

Đây là runbook chuẩn bị cho agent viết M3. Chưa có kết quả traffic test.
`scripts/verify-m3-linux.sh` và `probe-capabilities.sh` là sản phẩm T29/T01,
**chưa có ở thời điểm tài liệu này được tạo**. Không chạy command của các script
chưa implement rồi báo sản phẩm lỗi cài đặt.

Đọc [master](../../../docs/M3_IMPLEMENTATION_PLAN.md),
[task list](../../../docs/m3/CODING_TASKS.md),
[acceptance matrix](../../../docs/m3-acceptance-matrix.md) trước khi chạy.

## 1. Topology và điều kiện

Giữ topology WAN/LAN/DMZ/MGMT M1. Ví dụ documentation IPs:

| Node | Address | Vai trò |
|---|---|---|
| Appliance LAN | 192.168.10.1/24 | Default gateway LAN |
| LAN client | 192.168.10.10/24 | HTTP/TLS/DNS/SSH traffic |
| Appliance WAN | 192.0.2.2/24 | MASQUERADE/public DNAT |
| WAN server/client | 192.0.2.10/24 | Upstream test server/traffic source |
| Appliance DMZ | 10.20.0.1/24 | DMZ gateway |
| DMZ server | 10.20.0.10/24 | HTTPS443 và benign-marker TCP/HTTP server |
| MGMT | Theo VM M1 hiện tại | Windows browser/SSH quản trị |

Không thay địa chỉ host thật theo bảng nếu VM dùng subnet khác; runner nhận
topology file và kiểm tra nhất quán routes/interfaces trước khi mutate.
Giữ console VM truy cập được khi kiểm thử rollback/network fault.

Prerequisites: baseline M1/M2 acceptance, binaries build cùng commit/IPC version,
nft/ip/conntrack/curl/jq/tcpdump/Suricata, test client/server, token quản trị qua
environment. Metadata traffic phải qua gateway thực, không curl từ chính
appliance rồi suy ra forwarding được inspect.

## 2. CLI bắt buộc mà agent phải implement

```bash
# Read-only probe; no traffic/config mutations.
sudo bash scripts/verify-m3-linux.sh --preflight --evidence-dir /tmp/ngfw-m3-run

# Isolated namespace capability test (T01).
sudo bash tests/integration/m3/probe-capabilities.sh --isolated \
  --evidence-dir /tmp/ngfw-m3-probe

# Explicit lab run. Scenario names correspond to matrix IDs.
sudo --preserve-env=NGFW_API_TOKEN bash scripts/verify-m3-linux.sh \
  --traffic --lab --topology /etc/ngfw/m3-lab-topology.json \
  --scenario M3-11 --evidence-dir /tmp/ngfw-m3-run
```

Arguments: --preflight (default), --traffic, --lab, --topology, --scenario
(`all` chỉ khi explicit), --evidence-dir, --api-base, --help.
No topology/client ability → exit2 NOT_RUN; never emit success for merely
checking `systemctl is-active`.

Runner doesn't log auth header; jq extracts success/error envelope explicitly.
`curl --fail-with-body` hoặc equivalent, request timeout; don't count HTTP200
health as proof policy activation. Response body phải được assert.

## 3. Before/after collection helpers

Runner phải implement `collect_evidence(stage,scenario)` để ghi:

```bash
uname -a
nft --version
suricata --build-info
sudo nft -j list ruleset
sudo conntrack -L -o extended,id
sudo systemctl status ngfw-engine ngfw-api --no-pager
sudo journalctl -u ngfw-engine --since '<run-start>' --no-pager
```

Sau implementation, thêm health/capabilities/running/session/security REST và
sensor journal/epoch manifests. nft/conntrack output giữ đầy đủ để đối chiếu,
tránh `grep` làm mất tuple/mark/counter quan trọng. Không export secret config.

Mỗi test ghi assertion file: expected, observed, PASS/FAIL/NOT_RUN, reason.
Trap recovery báo kết quả riêng; failure cleanup không che lỗi test chính.

## 4. Scenario theo thứ tự chạy

### A — Baseline OFF và App-ID

1. Chạy M3-00/01/02 trước; lưu NAT/firewall/cache M2 hoạt động.
2. Commit IDS profile chỉ trên rule LAN→WAN cần inspect. Không queue MGMT.
3. Từ LAN tạo HTTP connection keepalive, đợi trong tối đa5s rồi GET API session
   khi connection vẫn mở. Assert app HTTP và source HIGH; EVE SID discovery
   không xuất hiện như threat. Đóng sau khi đã thu evidence.
4. Lặp TLS, UDP DNS và SSH. TLS chỉ yêu cầu TLS/metadata nhìn thấy; không đòi
   decrypted content/certificate field không quan sát được.
5. Random bytes qua TCP443 phải UNKNOWN/OTHER phù hợp, không verified HTTPS.

### B — IDS alert

1. Dùng marker chứa run nonce, signature fixture an toàn của ruleset.
2. Send marker qua gateway trong IDS. Upstream ghi nonce, client nhận response.
3. Assert security event đúng SID/mode IDS/ALERT, cùng session tuple/zones.
4. Assert không có guard application được tạo; discovery không cộng threat.
5. Có thể sensor emit nhiều physical alerts; expected occurrence theo fixture
   manifest, dedup replay không được nuốt lần tấn công mới. Không assert vô lý
   “mọi packet luôn chỉ một alert”.

### C — Inline IPS drop và late attack

1. Commit IPS profile, xác nhận NFQUEUE listener/lease và rules checksum.
2. Dùng test TCP server ghi bytes nhận theo nonce. Tạo long-lived TCP connection.
3. Gửi benign payload, xác nhận đi được, chụp conntrack ID/cache mark.
4. Gửi marker bằng **cùng socket**, không curl một connection mới.
5. Assert marker packet/bytes bị signature chặn, server không nhận marker,
   Suricata EVE báo drop và kernel queue path counters tăng.
6. Chụp pcap ở hai phía. Có thể bytes benign trước marker đã tới; đó không phải
   lỗi. Không gọi test này là chặn nguyên HTTP request trước server/WAF.
7. Assert UI/APIs phân biệt REPORTED/PACKET với APPLIED/SESSION.

### D — NAT và bidirectional

1. LAN→WAN MASQUERADE: giữ O, R, P, T từ CT, original/translated từ API, tuple EVE.
2. WAN→public8443 DNAT DMZ443: TLS App-ID/alert test phù hợp với fixture plaintext
   hoặc signature metadata, không mong Suricata đọc body HTTPS mã hóa.
3. Có fixture HTTP publication separate nếu test marker HTTP ở DMZ; không gửi
   cleartext HTTP vào HTTPS443 rồi gọi đó là normal successful connection.
4. Request/reply phải cùng NGFW SessionID. DoubleNAT isolated scenario nếu baseline
   hỗ trợ; nếu chưa setup đánh dấu NOT_RUN, không coi giả fixture là VM pass.
5. Đóng ngắn/mở lại tuple, restart sensor để thử event delayed/epoch. Replay
   input dành test adapter không được trộn vào production EVE của người dùng.

### E — Application restriction

1. ALLOW L3 ports TCP test + IPS profile + allowed_apps HTTP (RESTRICT_L3_ALLOW).
2. HTTP known passes. SSH trên allowed L3 port nhận diện xong tạo session guard.
3. Packet sau ACK guard bị chặn; lấy nft guard key/timeout/API state. Việc bytes
   trước classification đã đi qua phải được ghi đúng, không che khỏi báo cáo.
4. Unknown/random payload timeout→UNKNOWN_ALLOWED vì fail-open, có reason.
5. Change policy/app list then commit: generation tăng, app guard reconcile,
   manual block nếu có vẫn còn. L3 DROP không bao giờ được app allow mở lại.
6. Submit same L3 scope with different app list as later rule: backend shadow
   error, không lách duplicate bằng name/ID/priority khác.

### F — Service failures

1. Stop IDS: traffic base hoạt động, inspection unavailable, API không báo clean.
2. Stop IPS: queue bypass đảm bảo base allow, base deny giữ. Observe dropped
   already-queued packets nếu có.
3. SIGSTOP IPS để listener vẫn tồn tại: kiểm chứng lease hết và bounded recovery,
   khác no-listener case. Always SIGCONT/restore bằng trap.
4. Saturate queue có giới hạn trong isolated lab; kiểm chứng fail-open flag và
   record loss/latency. Không chạy flood vào hệ thống ngoài lab.
5. Stop API/UI: sensor/forwarding vẫn hoạt động, mở API lại đọc runtime qua IPC.
6. Restart engine khi connection còn kernel: no duplicate session, new epoch
   policy marks, context PARTIAL until new evidence, queued lease recovery.

### G — Reader, rotation, disk/event pressure

1. Rename EVE và reopen sensor log; gửi marker mới. Count physical source IDs,
   không duplicate after reader reopen.
2. Long line/malformed/partial dùng isolated test source; next good event vẫn tới.
3. Stop event consumer/full queue: forwarding không block, health/loss counters.
4. Disk đầy dùng filesystem giới hạn riêng cho test log; không lấp root disk
   của appliance. Observe logging degraded; restore log mount/path.
5. Soak30min: record memory/disk/session/queue curves, check limits/cleanup.

### H — Commit/rollback/recovery

1. Snapshot running/config/epoch/nft/routes/interfaces trước test.
2. OFF→IDS→IPS→rollback, assert actual chain selection mỗi lần, generation tăng.
3. Inject fail mỗi stage bằng test adapter hoặc isolated namespace failure;
   ghi rõ fake vs Linux fault. Verify old network+inspection restored.
4. Restart khi journal pending, assert target/previous recovery deterministic.
5. Repeat same operation_id after API timeout không tạo second activation.
6. Không flush conntrack để “chữa” lỗi NAT hoặc stale cache test.

### I — API/WS/UI

1. REST pagination/filters lớn hơn1page, missing/uncorrelated event, RBAC/timeout.
2. Browser qua Vite proxy như user đang dùng, không chỉ test direct8080.
3. Open/close/reconnect, engine stream reset; verify no duplicate/current data
   không bị kẹt chờ old sequence.
4. Bad fields render Unknown/—, no React crash; lifecycle không thành threat.
5. Policy/JSON shared status, dirty warning, Back, save/validate/load/commit.

## 5. Kết thúc

Phục hồi config/service theo run pre-state bằng cơ chế commit/rollback hợp lệ;
giữ generation tăng. Thu after-restore evidence và ghi test còn NOT_RUN.
Nghiệm thu cần toàn ma trận mandatory PASS, không chỉ checklist A–I của runbook.

Mọi fixture/harness mới cần giữ raw results đủ để một người khác lặp lại.
Không ghi “pass toàn bộ” nếu chỉ chạy unit tests trên Windows.
