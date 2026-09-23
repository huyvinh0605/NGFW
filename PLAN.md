# Kế hoạch xây dựng NGFW theo đặc tả

> **Kế hoạch triển khai M2 hiện tại:** [M2_IMPLEMENTATION_PLAN.md](docs/M2_IMPLEMENTATION_PLAN.md).
> Tài liệu này đã audit source và gồm kiến trúc, danh sách file, thứ tự triển khai,
> unit test và Linux acceptance. M1 đang code-complete, chờ Ubuntu VM acceptance;
> M2 implementation đã có trong workspace và đang chờ Ubuntu VM acceptance.
> Phần bên dưới là kế hoạch tổng thể ban đầu.

> **Đặc tả code M3 hiện tại:** [M3_IMPLEMENTATION_PLAN.md](docs/M3_IMPLEMENTATION_PLAN.md),
> kèm [32 task triển khai](docs/m3/CODING_TASKS.md) và
> [ma trận nghiệm thu](docs/m3-acceptance-matrix.md).
> [CODE_CONTRACTS.md](docs/m3/CODE_CONTRACTS.md) chốt structs, boundary algorithms,
> error codes và JSON fixtures để agent dùng trực tiếp khi code/test.
> Hướng dẫn vào việc và prompt giao agent: [START_HERE.md](docs/m3/START_HERE.md).
> M3 được chốt thành M3-A App-ID/Suricata IDS và M3-B IPS/NFQUEUE/application
> restriction. Đặc tả này thay phạm vi M3 cũ bên dưới; nDPI, URL/TI và behavior
> detectors được hoãn, không coi như đã thực hiện. Hiện mới viết đặc tả code M3,
> chưa triển khai hoặc nghiệm thu M3. M1/M2 vẫn chờ Ubuntu VM acceptance.

## 1. Mục tiêu và phân tích đặc tả

Xây dựng appliance NGFW Linux nhiều NIC, bao phủ toàn bộ chức năng trong tài liệu, triển khai theo các mốc có thể chạy và nghiệm thu độc lập.

Các lựa chọn đã thống nhất:

- Phát triển trên Windows; chạy và kiểm thử mạng trên VM Linux.
- Hoàn thành đầy đủ theo giai đoạn.
- Với HTTP/HTTPS được chọn kiểm tra, chặn request độc hại **trước khi đến server**.
- Hỗ trợ kiểm tra HTTP/1.1 và HTTP/2.
- Chưa có thời hạn, nhân lực và cấu hình host cụ thể; tiến độ bên dưới là ước lượng tuần công.

Tại thời điểm lập kế hoạch tổng thể, workspace `D:\KLTN` là dự án xây mới.
Trạng thái source hiện tại và phạm vi công việc tiếp theo được ghi trong kế hoạch M2 ở trên.

**Giá trị cốt lõi cần chứng minh** là chuỗi xử lý thống nhất:

```text
Traffic → Session → Security Context → Detector Signals
        → Risk → Policy → Enforcement → Cached Decision
```

### Những điểm cần giải quyết trong thiết kế

| Vấn đề | Quyết định triển khai |
|---|---|
| EVE là sự kiện bất đồng bộ | Dùng để phát hiện và phản ứng trên lưu lượng thông thường; bổ sung đường giữ request cho kiểm tra web trước server. |
| NAT làm thay đổi tuple | Lưu original/reply tuple của conntrack và alias trước/sau NAT; không ghép session chỉ bằng IP/port. |
| HTTP/2 có nhiều request trong một connection | Bổ sung context theo request/stream dưới session; quyết định cho request không được tự động áp dụng cho mọi stream. |
| Fast path có thể bỏ qua tấn công xuất hiện muộn | Chỉ áp dụng khi profile cho phép; request web yêu cầu kiểm tra liên tục vẫn phải qua cổng kiểm tra. |
| Commit gồm nftables, route và interface | nftables dùng transaction; toàn bộ cấu hình dùng journal, snapshot và thao tác bù để rollback. |
| Metadata TLS không luôn đọc được | Trường không quan sát được phải trả `unavailable`; không suy diễn thành dữ liệu đã kiểm chứng. |
| Mẫu struct chưa bao phủ hết nghiệp vụ | Hoàn thiện service objects, schedule, tham số action, request context và phiên bản quyết định trước khi xây API. |

nftables có cơ chế thay ruleset nguyên tử, nhưng không tạo transaction chung cho cấu hình route/interface. [Tài liệu nftables](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)

TLS 1.3 mã hóa các thông điệp handshake sau ServerHello; vì vậy không cam kết đọc certificate bằng quan sát thụ động cho mọi kết nối. [RFC 8446](https://www.rfc-editor.org/info/rfc8446/)

## 2. Kiến trúc và các quyết định kỹ thuật

### 2.1. Stack và môi trường

- **Appliance:** Ubuntu Server 24.04 LTS, dịch vụ systemd.
- **Engine/API/proxy:** Go; HTTP/2 dùng thư viện chuẩn và `golang.org/x/net/http2`.
- **Firewall:** Linux routing, nftables, conntrack; NFQUEUE chỉ cho đường cần quyết định userspace.
- **DPI:** nDPI qua adapter cgo, đóng gói và build trên Linux.
- **IDS:** Suricata, chuẩn hóa EVE qua adapter.
- **ML:** Python, scikit-learn, TF-IDF ký tự và Logistic Regression.
- **UI:** React, TypeScript, Vite.
- **Persistence:** SQLite WAL cho appliance đơn; telemetry ghi theo batch và có retention.
- **IPC:** Unix domain socket, API nội bộ có version.
- Khóa phiên bản dependency, image và ruleset trong manifest khi dựng môi trường.

Go cung cấp triển khai HTTP/2 với cấu hình giới hạn stream và bộ đệm; dùng thư viện này thay vì tự viết parser khung HTTP/2. [Tài liệu Go HTTP/2](https://pkg.go.dev/golang.org/x/net/http2)

Cấu hình lab tham chiếu: appliance 4 vCPU, 8 GB RAM, 60 GB disk, bốn NIC WAN/LAN/DMZ/MGMT. Đây là cấu hình bắt đầu thử nghiệm, chưa phải cam kết thông lượng.

Topology gồm appliance, LAN client, DMZ web server và WAN traffic generator. MGMT dùng mạng riêng; kiểm thử mạng cấp quyền chạy trong Linux VM.

### 2.2. Phân chia tiến trình

| Thành phần | Trách nhiệm |
|---|---|
| `ngfw-engine` | Session/context, risk, policy, compiler, enforcement và running configuration. |
| `ngfw-api` | Auth, RBAC, candidate configuration, REST, truy vấn và realtime. |
| `ngfw-proxy` | HTTP/TLS interception, quản lý request/stream, giữ request chờ quyết định. |
| Suricata | Phát hiện trên traffic và kiểm tra nội dung web đã giải mã. |
| `ngfw-ml` | Inference cục bộ, không có quyền firewall. |
| `ngfw-telemetry` | Persistence sự kiện, log rotation, thống kê. |
| `ngfw-ui` | Giao diện quản trị. |

Engine giữ snapshot cấu hình đã commit trên đĩa và trong RAM, không phụ thuộc API hoặc DB để tiếp tục áp dụng policy.

API không có quyền chạy lệnh firewall. Chỉ adapter enforcement được thay đổi trạng thái mạng. CA key chỉ proxy đọc được.

### 2.3. Đường chuyển tiếp và fast path

Thứ tự xử lý:

1. Kiểm tra zone, trạng thái không hợp lệ và dynamic block.
2. Kiểm tra quyết định session còn hiệu lực.
3. Với session mới hoặc bị invalidation: đánh giá connectivity policy và profile.
4. Thu thập tín hiệu cần thiết, tính risk, chọn action.
5. Enforcement cập nhật kernel và cache.

Dùng conntrack mark để nhận biết quyết định đã đánh giá, kết hợp policy generation và bảng thu hồi theo flow. Block và invalidation phải được kiểm tra **trước** nhánh accept established.

Không bật flowtable offload trong phiên bản đầu để tránh đường offload vượt qua cơ chế thu hồi.

Session lưu:

- ID nội bộ, conntrack ID/context và thời điểm tạo.
- Tuple hai chiều, alias NAT, client/server role.
- Application, risk, policy version, decision version.
- Counters, timeout và lý do fast path/invalidation.

Khi mất conntrack event, resync có giới hạn từ kernel. Sự kiện detector không ghép được phải được đánh dấu rõ, không gán vào session gần giống.

### 2.4. Chặn HTTP/HTTPS trước server

Luồng xử lý:

```text
Client
 → HTTP/TLS proxy
 → Request context
 → Decode + URL/DNS/TI + IDS + ML
 → Risk + Policy
 → ALLOW: gửi request lên upstream
 → BLOCK: không gửi request lên upstream
```

- Policy chuyển hướng HTTP hoặc TLS được chọn đến proxy; connection upstream có mark riêng để tránh vòng lặp.
- Proxy xác minh certificate upstream.
- HTTP/2 được terminate tại proxy; mỗi stream có `RequestID`, `StreamID` và deadline riêng.
- Không gửi header hoặc body của request lên upstream trước quyết định.
- Body kiểm tra mặc định tối đa 64 KiB. Profile bảo vệ nghiêm ngặt từ chối request vượt giới hạn; profile khác phải cấu hình rõ việc bỏ qua phần nội dung còn lại.
- Giới hạn cả dữ liệu sau giải nén; request không hỗ trợ hoặc framing không hợp lệ được xử lý theo profile.

**Adapter IDS đồng bộ cho lab:** dựng PCAP TCP/HTTP hữu hạn từ request chuẩn hóa, đưa vào pool Suricata chạy chế độ PCAP qua Unix socket. Mỗi worker xử lý một job tại một thời điểm; chỉ trả “đã kiểm tra” sau khi job hoàn tất và EVE đã được đọc hết.

Suricata hỗ trợ xử lý nhiều PCAP qua Unix socket mà không khởi động lại bộ signature. Tuy nhiên, đây là cơ sở xây adapter, không phải API verdict HTTP có sẵn. [Tài liệu Suricata](https://docs.suricata.io/en/suricata-8.0.0/unix-socket.html)

Các giới hạn phải công bố:

- HTTP/2 chuẩn hóa sang nội dung HTTP phục vụ signature; không tuyên bố phát hiện mọi tấn công đặc thù framing HTTP/2.
- Đường này ưu tiên tính đúng trong lab và phải đo chi phí độ trễ.
- Hết deadline hoặc lỗi detector là `UNAVAILABLE`, không phải kết quả sạch.
- Profile demo chặn trước server dùng `FAIL_CLOSE` khi thiếu bước kiểm tra bắt buộc.
- ML lỗi vẫn cho phép Risk + Policy quyết định bằng các nguồn còn lại theo đặc tả.
- TLS giải mã tắt mặc định. Profile lab thông thường dùng `FAIL_OPEN`; profile bảo vệ nghiêm ngặt ghi đè rõ ràng.
- Pinning, mTLS, HTTP/3 và ECH không được coi là đã giải mã. Profile nghiêm ngặt chặn đường không kiểm tra được; có thể chặn UDP/443 để client có cơ hội dùng TCP.

### 2.5. Risk, policy và action

- Rule ưu tiên số nhỏ trước, first-match; priority trùng bị từ chối khi validate.
- Default inter-zone: deny; cấu hình lab khai báo allow cần thiết.
- Connectivity deny không bị risk thấp hoặc reputation allowlist ghi đè.
- Profile xác định detector cần chạy và ngưỡng chặn.
- Sau khi có context, đánh giá risk-dependent rules; nếu không có rule phù hợp thì dùng kết quả connectivity cùng giới hạn của profile.

Risk dùng mức 0–100 và các khoảng trong đặc tả. Deduplicate bằng detector, observation/signature, request/session và cửa sổ thời gian.

Mặc định khởi đầu:

- IPS tối đa 40; TI 25; ML 20; behavior 20; URL/DNS 20; TLS 10.
- Nhân contribution với confidence.
- IPS và ML cùng xác nhận một loại tấn công, confidence từ 0,9: bonus 25.
- ML yếu không đủ tự vượt ngưỡng chặn mặc định 80.
- Lưu từng contribution, nguồn chứng cứ và correlation reason.

`PolicyDecision` gồm action, scope, policy/config version, reason, TTL hoặc rate-limit parameters.

Phân biệt scope packet, request, session và source indicator. `RESET_SESSION` phải thực sự đóng/reset kết nối phù hợp; xóa conntrack đơn thuần không được coi là reset TCP.

### 2.6. Cấu hình và khôi phục

Quy trình:

```text
Candidate → Validate → Compile → Prepare
          → Apply → Verify → Running
```

- Candidate có revision; commit sai revision trả conflict.
- Validate toàn bộ tham chiếu, CIDR, NAT conflict, risk range, action parameters, TLS mode và resource limits.
- Snapshot trạng thái quản lý; journal ghi tiến trình activation.
- Apply route/interface theo thứ tự có thể hoàn tác; firewall thay bằng transaction.
- Chỉ công bố running version sau xác minh thành công.
- Lỗi thì restore snapshot; reboot giữa commit thì journal phục hồi last known-good.
- Thay đổi có thể làm mất MGMT dùng commit-confirm thời hạn 60 giây.
- NAT thay đổi mặc định áp dụng cho connection mới; không tự ngắt mọi session đang hoạt động.
- Temporary block dùng timeout trong kernel; engine restart giữ block còn hạn, cold boot không tự khôi phục block đã mất.

### 2.7. API và giới hạn vận hành

Giữ `/api/v1`, response envelope và các endpoint trong đặc tả. Bổ sung:

- CRUD users, service objects, schedules và reputation indicators.
- Đọc candidate/running/diff và xác nhận commit.
- Context request/stream trong session detail.
- Trạng thái detector, inspection completeness và enforcement result.
- Model activation chỉ từ artifact tin cậy đã đăng ký, có checksum.
- WebSocket `/ws/events`, `/ws/stats`, thống kê mỗi giây.

Auth dùng password hash Argon2id, cookie bảo mật, chống CSRF và RBAC ADMIN/OPERATOR/VIEWER. Mặc định OPERATOR được terminate session và quản lý temporary block; các thay đổi cấu hình thuộc ADMIN.

Giới hạn khởi đầu, đều cấu hình được:

| Tài nguyên | Mặc định |
|---|---:|
| Active sessions | 50.000 |
| Event queue | 10.000 |
| HTTP headers / URL | 32 KiB / 8 KiB |
| HTTP body kiểm tra | 64 KiB |
| HTTP/2 concurrent streams/connection | 32 |
| ML concurrent requests / timeout | 4 / 200 ms |
| Request inspection deadline | 2 giây |
| Temporary blocks / reputation entries | 10.000 / 100.000 |
| Telemetry retention | 7 ngày hoặc 5 GiB, chạm mức nào trước |

Hàng đợi bảo mật tách khỏi telemetry; đầy hàng đợi bảo mật phải báo mất khả năng kiểm tra và áp dụng failure policy. Telemetry có thể bỏ bản ghi ưu tiên thấp kèm counters. Session table đầy thì hạn chế session mới, ưu tiên session đã thiết lập.

## 3. Các giai đoạn triển khai

Ước lượng cho một người làm chính có nền tảng Go/Linux networking; không phải lịch cam kết.

| Mốc | Công việc và sản phẩm bàn giao | Điều kiện qua mốc | Tuần công |
|---|---|---|---:|
| **M0 — Nền tảng và kiểm chứng kiến trúc** | Monorepo, build Linux, VM topology, ADR, schema/OpenAPI; spike conntrack/NAT, thu hồi cache, HTTP/2 gate và Suricata PCAP completion. | Request độc hại mẫu bị giữ trước upstream; event gắn đúng request; đo được overhead adapter. | 2–3 |
| **M1 — Firewall cơ bản** | Interface, zone, VLAN, static/default route, SNAT/MASQUERADE/DNAT, stateful rules; CLI validate/commit/rollback. | LAN đi WAN, WAN vào DMZ qua DNAT; return traffic đúng; commit lỗi phục hồi được. | 3–4 |
| **M2 — Session và decision core** | Conntrack adapter, NAT aliases, session/context store, risk, policy, action scopes, fast path và invalidation. | Hai chiều cùng session; block vượt cache allow; TTL hết hạn; state không tăng vô hạn. | 3–4 |
| **M3 — Security không giải mã** | nDPI, Suricata EVE, HTTP/DNS/TLS metadata, URL rules, local TI, scan/rate detectors. | Mọi detector tạo event chuẩn; scan/exploit gây action thật; detector lỗi báo degraded. | 3–4 |
| **M4 — HTTP/TLS gate** | Transparent proxy, CA, TLS policy/exclusions, HTTP/1.1 và HTTP/2, IDS request adapter, stream-level context, limits/timeouts. | SQLi/XSS bị chặn trước server; request sạch đi qua; không nhầm stream, không bypass âm thầm. | 4–6 |
| **M5 — ML và correlation** | Dataset pipeline, normalization, training/evaluation, inference service, model registry/activation, correlation với IPS. | Đủ năm lớp bắt buộc; báo cáo test độc lập; weak ML không tự chặn; ML outage xử lý đúng. | 2–3 |
| **M6 — Quản trị đầy đủ** | REST/RBAC, dashboard, network/policy/profile editor, sessions/context, threats, TI, blocks, audit, realtime. | Mọi thao tác UI có backend thật; commit/rollback hoạt động; tắt API/UI không dừng forwarding. | 3–4 |
| **M7 — Nghiệm thu và benchmark** | Fault injection, parser fuzzing, soak test, benchmark A–F, demo A–E, đóng gói và tài liệu. | Đủ 22 acceptance criteria, tái dựng được từ môi trường sạch và có bằng chứng đo. | 3–4 |

**Tổng ước lượng: 23–32 tuần công**, chưa gồm thời gian học nền tảng hoặc thu thập dữ liệu lớn. Sau M0 phải cập nhật lại ước lượng theo kết quả đo thực tế.

API contract và telemetry tối thiểu được xây từ M0–M2; M6 hoàn thiện trải nghiệm quản trị.

## 4. Kế hoạch kiểm thử và nghiệm thu

### Kiểm thử logic và hợp đồng

- Policy ordering, default deny, profile threshold, action scope và schedule.
- Risk deduplication, correlation, confidence thấp, event trễ và hết hạn.
- Session hai chiều, NAT, tuple tái sử dụng và mất conntrack event.
- HTTP framing, DNS malformed, TLS parse lỗi, header/body/decompression limits.
- HTTP/2 multiplexing, stream cancellation và giới hạn tài nguyên.
- Config validation, concurrent commit và recovery từ journal.
- Go race tests cho session/context; fuzz tests cho parser và dữ liệu EVE.

### Kiểm thử mạng có quyền Linux

- Routing, VLAN, SNAT, DNAT, established/related và default deny.
- ALLOW, DROP, REJECT, RATE_LIMIT, RESET_SESSION, TEMP_BLOCK đều có bằng chứng trên traffic thật.
- Flow vào fast path; phát event nguy hiểm; kiểm chứng packet tiếp theo bị chặn hoặc quay lại kiểm tra.
- Test IPv4 đầy đủ; IPv6 có model và xử lý cấu hình cơ bản nhưng mặc định không forward cho đến khi bật profile dual-stack đã kiểm thử.

### Kiểm thử chặn trước server

Mỗi request mang ID kiểm thử; đối chiếu log proxy, context và access log upstream:

- Request sạch HTTP/1.1 và HTTP/2 đến server.
- SQLi/XSS được quyết định block không xuất hiện ở upstream.
- Một connection HTTP/2 có stream sạch và độc hại không bị ghép nhầm.
- Attack ở body, chunked input, encoding và body vượt giới hạn.
- Detector timeout không bị báo thành “đã kiểm tra sạch”.
- TLS exclusions, CA không được trust, upstream certificate lỗi và proxy outage đúng failure policy.

### Kiểm thử lỗi và khả năng phục hồi

- Dừng UI, API, DB, ML, Suricata và telemetry riêng biệt.
- Existing traffic và policy tiếp tục khi management chết.
- Profile kiểm tra bắt buộc áp dụng đúng khi security component chết.
- Disk đầy, queue đầy, session đầy, browser chậm và feed cập nhật lỗi.
- Chèn lỗi giữa các bước commit và reboot khi activation chưa hoàn tất.
- Sau restart, session state được đồng bộ lại và health phản ánh đúng mức bảo vệ.

### Benchmark và ML

Chạy cùng topology, tài nguyên VM và workload cho sáu mode A–F trong đặc tả. Mỗi mode có warm-up, ít nhất ba lần đo; lưu raw results, config, model/ruleset version và thông tin máy.

Báo cáo throughput, p50/p95/p99 latency, packet loss, CPU/RAM, concurrent sessions, session rate và tỷ lệ fast path. Đo riêng request-gate latency, queue wait và timeout rate.

Dataset ML chia theo nguồn/template trước train-validation-test để hạn chế leakage; không dùng flow dataset thay cho nhãn HTTP payload. Báo cáo precision/recall/F1 từng lớp, macro F1, confusion matrix và benign false-positive rate. Chưa cam kết chỉ tiêu độ chính xác khi chưa có dữ liệu kiểm chứng.

## 5. Hồ sơ bàn giao và tiêu chí hoàn thành

Bàn giao gồm:

- Source code, dependency locks, migration và cấu hình mẫu.
- Linux services, script cài đặt và topology lab tái lập.
- OpenAPI, mô tả IPC, schema/version và các ADR quan trọng.
- Test tự động, kịch bản demo A–E và benchmark A–F.
- Model artifact, dataset manifest, quy trình training và báo cáo ML.
- Hướng dẫn build/run, backup/restore, commit recovery và giới hạn sản phẩm.
- Ma trận ánh xạ **22 acceptance criteria → module → test → bằng chứng**.

Không đưa HA, SD-WAN, VPN enterprise hoặc giải mã HTTP/3 vào kế hoạch này. Chỉ tuyên bố khả năng ngăn chặn và hiệu năng trong phạm vi đã kiểm thử.

Mốc kết thúc là appliance hoạt động xuyên suốt từ traffic đến quyết định và enforcement, quản trị được qua UI/API, chịu được management outage và tái dựng được từ môi trường sạch.

Current implementation status: M1 is code-complete pending Ubuntu VM acceptance;
M2 E0-E11 implementation modules and tests are present. The M2 packet-path
acceptance matrix remains `NOT_RUN` until the Linux topology is exercised.
