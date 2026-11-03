# SENTINEL NGFW — Đặc tả tinh gọn UI và kịch bản nghiệm thu web

Ngày lập: **30/10/2026**, múi giờ hiển thị lab: **Asia/Bangkok (UTC+7)**.

> **Phạm vi thực thi được người dùng chốt lại ngày 31/10/2026: UI-only.**
> Chỉ kiểm tra giao diện, đọc API/WS hiện có và fixture trong browser. Bỏ qua mọi
> phần cần thay đổi backend, Running/Candidate thật, Commit/Rollback, block/revoke
> thật, bật/tắt module, restart/reboot hoặc tạo traffic để kiểm tra enforcement.
> Không sửa engine/API, firewall/NAT, session, Suricata hay proxy theo kết quả UI.
> Có thể mô phỏng các thao tác ghi bằng response fixture; request ghi phải bị
> chặn trước khi đến backend. Kết quả fixture chỉ chứng minh hành vi UI.
> Những bước ngoài phạm vi phải ghi `SKIPPED_SCOPE`, không tính là PASS và không
> thay thế bằng chứng nghiệm thu chức năng NGFW trước đây. Quy định này ưu tiên
> hơn các bước LIVE/CLONE có thao tác ghi trong những mục bên dưới.

> **Yêu cầu ảnh minh chứng:** sau mỗi case/subcase, chụp và tải ảnh về workspace,
> gửi ngay link ảnh trong chat kèm kết quả và loại LIVE/FIXTURE; áp dụng cho cả
> PASS, FAIL và bước bị lỗi harness. Giữ ảnh lần cũ khi chạy lại. Mục lục ảnh chung:
> [UI_EVIDENCE_INDEX.md](../artifacts/UI_EVIDENCE_INDEX.md).

**Trạng thái: ĐÃ CÓ BẰNG CHỨNG KIỂM TRA UI-ONLY / CHƯA ĐẠT TOÀN BỘ ĐẶC TẢ.** Xem [báo cáo ban đầu](../artifacts/ui-readonly-20261031/RESULTS.md), [báo cáo bổ sung 31/10](../artifacts/ui-followup-20261031T071325Z/RESULTS.md), [lượt bổ sung 01/11: 11 subcase, 7 PASS / 4 FAIL](../artifacts/ui-followup-20261101T141510Z/RESULTS.md) và [ledger cập nhật](../artifacts/ui-followup-20261101T141510Z/CUMULATIVE_LEDGER.json). Lượt 01/11 giữ nguyên setup IDS/IPS Running v240 đang được người dùng yêu cầu giữ để xem thủ công. Các bước ghi/enforcement hoặc yêu cầu sửa backend được bỏ qua theo phạm vi người dùng chốt ở trên. Tài liệu này quy định UI cần hiển thị gì; không phải báo cáo PASS, không thay thế acceptance matrix M1–M4.

Mục tiêu: người quản trị biết **traffic nào đang đi qua firewall, policy nào áp dụng, chức năng bảo vệ nào thực sự bật, lỗi nào đang xảy ra và thao tác nào đã có hiệu lực**. Không thêm trường hoặc biểu đồ chỉ để lấp ô `Unavailable`.

## 1. Phạm vi và quyết định thiết kế

- Giữ 7 trang hiện có: Tổng quan, Sessions, Sự kiện & kiểm soát, Chính sách, Mạng, Cấu hình, Hệ thống. Không cần thiết kế lại toàn bộ giao diện.
- Phạm vi vận hành là M1/M2/M3/M4 hiện có. Không triển khai Risk Engine, ML, routing M5 hoặc chức năng chưa có backend để phục vụ bộ test này.
- Phần giám sát M4 cần được nối vào các trang hiện có: trạng thái tại Tổng quan/Hệ thống, request evidence tại Sự kiện và liên kết trong session khi có. Đây là **yêu cầu còn thiếu**, không phải mô tả UI đã làm xong.
- Interface, VLAN, route và NAT có thể tiếp tục cấu hình qua JSON. Form riêng cho từng loại là cải tiến về sau; không bắt buộc thêm hàng loạt form để đạt phạm vi này.
- Xem ít thông tin hơn ở bảng chính; vẫn truy cập được thông tin cần chẩn đoán ở drawer/chi tiết nâng cao.
- Mọi số liệu phải có nguồn, phạm vi và thời điểm. Không biến dữ liệu thiếu thành số 0, ALLOW, CLEAN, HEALTHY hoặc kết luận “đã chặn”.
- Khi người dùng yêu cầu model sau thực thi: tái hiện lỗi, sửa nguyên nhân, kiểm tra lại cùng trường hợp và một trường hợp đối chứng. Không chỉ đổi nhãn để che lỗi backend.

### 1.1 Mức ưu tiên

| Mức | Ý nghĩa | Điều kiện hoàn tất |
|---|---|---|
| P0 | Có thể làm mất cấu hình, thực hiện sai thao tác, sai quyền hoặc báo bảo vệ thành công khi chưa có bằng chứng | Phải xử lý trước các bài ghi phụ thuộc; không còn FAIL khi nghiệm thu |
| P1 | Chức năng vận hành cốt lõi hoặc thông tin quan trọng bị thiếu/sai | Phải hoàn tất để gọi bộ UI M1–M4 này đầy đủ |
| P2 | Khả năng đọc, sắp xếp, tối ưu thao tác và tải giao diện | Ghi kết quả riêng; không dùng để che P0/P1 |

**Ẩn tính năng không hỗ trợ** khác **ẩn lỗi của tính năng đang bật**. Risk chưa có nguồn thì bỏ khỏi bảng mặc định; inspection đang bật nhưng sensor chết thì phải hiện cảnh báo.

## 2. Những điểm đã thấy trong mã nguồn và bằng chứng trước đây

Đây là đầu vào thiết kế test. Model thực thi phải đọc lại phiên bản đang chạy; không mặc định trạng thái ngày 30/10 còn nguyên.

| Điểm cần xử lý/kiểm tra | Căn cứ | Mức chắc chắn và hướng xử lý |
|---|---|---|
| Bảng session chỉ nhận trang mặc định, mất metadata phân trang | `App.tsx: loadLive`, `runtimeData.ts: normalizeSessionPage`; API có `page`, `page_size`, `total`, `has_more`, `store_revision`, `snapshot_time` | Thấy trong code. Giữ metadata và phân trang; không mô tả 100 dòng như toàn bộ hệ thống |
| Số ALLOW/chưa đánh giá lấy từ trang session, tổng session lấy từ stats | `OverviewPage` | Thấy trong code. Dùng cùng phạm vi hoặc bỏ số phụ không có aggregate đáng tin cậy |
| Local traffic bị hiển thị Decision/Path như lỗi | Local nằm ngoài đường đánh giá FORWARD của M2; ảnh và dữ liệu đã kiểm tra | Phân loại “Local — không áp dụng policy chuyển tiếp”; không tự gán ALLOW |
| Risk/ML và nhiều ô security trống xuất hiện thường trực | `SessionsPage`, `SessionDrawer`, `SystemPage`, `PolicyEditor` | Thu gọn/ẩn nếu capability không có; không tạo điểm risk từ severity |
| Event runtime dùng drawer của security event | `EventDrawer`; [bằng chứng browser trước đây](../artifacts/ui-event-detail-20261030/result.json) | Tách nội dung theo loại event; signature/capture/verdict không áp dụng thì không dựng ô trống |
| Event còn trong lịch sử nhưng session đã đóng, GET session trả 404 | [Đối chiếu các event trong ảnh trước đây](../artifacts/ui-event-detail-20261030/screenshot-events.json) | Bình thường theo retention hiện tại. Nêu “session đã kết thúc”; không bắt buộc lưu bản sao toàn session |
| UI Mạng chỉ hiển thị Candidate, không phải toàn bộ NIC của Linux | `NetworkPage`, `GET /interfaces` | Bốn NIC được quản lý; ens40 do OS cấu hình. Cần phân biệt inventory thật và cấu hình mong muốn |
| Màu UP và RX/TX có thể lấy từ config/default 0 | `NetworkPage`, `normalizeInterface` | Không gọi admin_state là link operational; không hiển thị RX/TX bằng 0 nếu chưa đo |
| Chuẩn hóa interface/profile bỏ trường cấu hình | `normalizeInterface` không giữ `parent_interface_id`, `vlan_id`; `normalizeProfile` không giữ `request_gate`; đối chiếu `internal/domain/types.go` | Rủi ro xác định ở đường chuyển đổi code, **chưa thử ghi trên VM trong lượt này**. Test D01 phải đi trước mọi bài Commit |
| UI chưa gọi request-gate health/capabilities/evidence | Không có tích hợp tương ứng trong `web/src`, backend có API M4 | Thiếu màn hình quan sát M4. Không coi backend tồn tại là UI đã hỗ trợ |
| Auth UI dùng sự có mặt của token để báo mở quyền | `requireAccess`, `SystemPage`, `AccessModal` | Token chưa kiểm tra/VIEWER không đồng nghĩa quyền ghi; dòng “GET monitoring luôn khả dụng” không đúng với protected runtime reads |
| Session DELETE thực chất cài revoke guard | `sessionByID` trả `revoked=true`, `enforcement=DROP`, `tcp_reset_sent=false` | Nhãn nên là “Chặn phiên này” hoặc giải thích rõ revoke. Không hứa gửi RST/xóa conntrack ngay |
| Một lỗi đọc session detail bị nuốt | `openDetail` bắt lỗi rồi đóng drawer | Phải phân biệt 404 hết hạn với 401/403/503/timeout; không đóng im lặng |
| Thông báo event drops đang gộp nhiều nguồn | `statsSnapshot`, runtime event ring; đánh giá runtime trước đây | Không gọi toàn bộ là packet loss hay chắc chắn queue overflow; cần nhãn trung thực hoặc counters riêng |
| `stats` có thể trả HTTP 200 với `data.status=unavailable` | `statsSnapshot` | UI phải hiểu lỗi ở nội dung, không chuẩn hóa thành 0 và báo đang cập nhật tốt |

Nguồn chính để model sau đối chiếu:

- [App.tsx](../web/src/App.tsx), [runtimeData.ts](../web/src/runtimeData.ts), [inspectionData.ts](../web/src/inspectionData.ts), [inspectionComponents.tsx](../web/src/inspectionComponents.tsx), [api.ts](../web/src/api.ts).
- [Management API](../internal/management/api.go), [M4 API](../internal/management/request_gate_api.go), [RuntimeEvent](../internal/domain/runtime_events.go), [SessionPage](../internal/domain/runtime_ipc.go), [M4 DTO](../internal/domain/request_gate.go).
- [Hợp đồng xác thực runtime](m3/RUNTIME_READ_AUTH.md), [UI trong đặc tả M3](M3_IMPLEMENTATION_PLAN.md), [quyền quản lý ens40](lab/UPDATE_UPLINK.md).
- [Kiểm tra port trong drawer trước đây](../artifacts/ui-session-detail-20261030/result.json): port có dữ liệu nhưng chữ rất nhỏ. Không kết luận thiếu backend chỉ từ ảnh khó đọc.

## 3. UI cần có những gì

### 3.1 Các trang và thông tin chính

| Trang | Thông tin bắt buộc ở mức sử dụng thông thường | Thao tác cần giữ | Đưa vào chi tiết / ẩn khỏi mặc định |
|---|---|---|---|
| Tổng quan | Trạng thái nguồn dữ liệu và thời điểm đọc; Running version; Candidate chờ commit; tổng phiên đang được theo dõi; bảo vệ L3/L4, M3, M4 đang bật/tắt/suy giảm; cảnh báo cần xử lý | Làm mới; đi tới đúng danh sách/bộ lọc từ card | Pipeline minh họa lớn, vòng tròn trang trí, thống kê không có nguồn, App-ID aggregate chưa được backend cung cấp |
| Sessions | IP/port nguồn và đích, protocol/state, zone, local/forward/không xác định, quyết định có căn cứ, policy nếu có; phân trang và phạm vi bộ lọc | Tìm/lọc; chuyển trang; xem chi tiết; chặn đúng phiên có xác nhận khi được phép | Risk/ML khi chưa có nguồn; path/cache/epoch trong chi tiết; App-ID chỉ là cột hữu ích khi có inspection |
| Chi tiết session | Session ID; tuple original/reply/translated khi có; port rõ; trạng thái/tuổi phiên; decision + lý do + policy; counters và thời điểm đo; phần M3/M4 phù hợp | Đóng; sao chép giá trị cần tra cứu nếu có nút; chặn phiên theo quyền | Raw metadata, generation/revision, cache flags; không bắt buộc hiển thị hàng chục thuộc tính cùng lúc |
| Sự kiện & kiểm soát | Loại, thời gian, nội dung, nguồn, liên kết session/request; security severity khi nguồn có; bộ lọc loại; thông báo mất đoạn lịch sử | Xem chi tiết đúng loại; tải thêm; quản lý temporary block; xem audit | Runtime lifecycle gộp trong bộ lọc riêng; reputation lưu trữ đơn thuần ra vùng nâng cao; không dùng drawer Suricata cho mọi event |
| Chính sách | Priority, tên/ID, điều kiện zone/IP/service, action, enabled, profile; phân biệt Candidate với Running | Thêm/sửa/bật/tắt/xóa Candidate; Validate/Commit; mở JSON | Scope chỉ có SESSION thành text; min/max risk bỏ khỏi form nếu chưa hỗ trợ; metadata developer khỏi bảng chính |
| Mạng | Các interface NGFW quản lý và các device OS phát hiện; owner; địa chỉ; cấu hình admin/MTU/VLAN; live link nếu có telemetry; route và NAT đủ điều kiện match | Chuyển Running/Candidate rõ ràng; mở JSON để sửa; xem chi tiết route/NAT | MAC/counters/routes OS nâng cao vào chi tiết; không có telemetry thì không có số giả |
| Cấu hình | Editor chưa lưu, Candidate backend, Running đang áp dụng là ba trạng thái riêng; validation; diff đủ các phần; version/comment | Format; nạp Running vào editor; lưu Candidate; Validate; Commit; Rollback rõ mục đích | Các giới hạn không được engine hiện tại sử dụng; schema kỹ thuật chỉ trong JSON/chi tiết |
| Hệ thống | Danh tính/quyền đã xác thực; tình trạng API/engine/inspection/proxy theo nguồn; nguyên nhân suy giảm; build/version nếu có nguồn; giới hạn thực sự đang áp dụng | Đăng nhập/token/đăng xuất; quản lý tài khoản nếu hỗ trợ và đúng ADMIN | ML chưa hoạt động; API token trong vùng truy cập nâng cao; không thêm nút restart service nếu chưa có backend được thiết kế cho nó |

**Tổng session:** dùng nhãn “Phiên đang được theo dõi” nếu số bao gồm CLOSING/TIME_WAIT. Không gọi tất cả là TCP đang ESTABLISHED. Bộ lọc mặc định nên ưu tiên phiên chuyển tiếp, có tùy chọn xem local/quản trị và tất cả; phải ghi rõ bộ lọc đang dùng.

**Inventory NIC:** mục tiêu là thấy được cả device ngoài NGFW, như ens40, với nhãn “OS quản lý”. Nếu API hiện chưa có inventory, model phải ghi `NOT_IMPLEMENTED` cho yêu cầu đó. Trong thời gian chưa làm, đổi tiêu đề thành “Interface được khai báo trong NGFW”; tuyệt đối không bịa card thứ năm hoặc tự đưa ens40 vào Running để đủ số.

### 3.2 Quyết định giữ / bỏ / thu gọn

| Hạng mục | Quyết định đề xuất | Không được làm mất |
|---|---|---|
| Risk ở mọi dòng session và vòng tròn risk trong drawer | Ẩn khi không có risk capability/result thực | Khả năng hiển thị về sau nếu backend có dữ liệu có nguồn |
| ML inference, ML confidence khi chưa triển khai | Bỏ khỏi màn hình vận hành mặc định | Cấu hình cũ không được tự xóa khi lưu form khác |
| Min/max risk trong policy form M1–M4 | Không cho nhập giá trị chưa hỗ trợ; mô tả trong JSON nếu cần | Không tự biến policy có trường chưa hiểu thành rule ALLOW hợp lệ |
| App aggregate trống | Ẩn card; chỉ giữ trạng thái inspection và App-ID từng session | Không suy diễn App-ID từ port hoặc đếm một trang thành aggregate |
| “Decision chưa sẵn sàng” gộp cả local | Bỏ card này hoặc chỉ đếm lỗi đánh giá thật với phạm vi rõ | Phải giữ cảnh báo lỗi đánh giá/reconciliation thật |
| Path trong bảng session | Chuyển vào chi tiết nâng cao | Không mất nguyên nhân FAST/INSPECT/unknown; FAST không có nghĩa hardware offload |
| Event runtime: signature, capture, packet verdict | Không hiển thị các trường không áp dụng | Kind, time, session ID, reason và version/revision có trong event |
| Reputation registry | Ẩn khỏi luồng chính M1–M4 hoặc chuyển nâng cao, ghi “chỉ lưu danh mục” | Không gọi đây là cơ chế chặn/TI đã hoạt động |
| Metadata/raw JSON | Accordion đóng mặc định | Giá trị vẫn tra cứu được, đã loại secrets/payload nhạy cảm |
| Hai nút revoke ở dòng và drawer | Một action rõ trong drawer hoặc menu dòng; tránh icon X dễ bấm nhầm | Chức năng revoke và thông báo đúng kết quả backend |
| Nhiều điểm vào đăng nhập/cấu hình | Có thể giữ shortcut, dùng chung trạng thái và cùng workflow | Không tạo Candidate/editor riêng hoặc commit ngầm ở mỗi trang |
| Scope SESSION, fail mode OPEN cố định ở M3 | Hiển thị text ngắn hoặc trợ giúp; không giả làm lựa chọn đa giá trị | Giải thích fail-open và giới hạn IDS/IPS vẫn xem được |
| RX/TX nếu chỉ là giá trị config/default | Ẩn số hoặc ghi “Chưa có số liệu trực tiếp” | Số 0 đo được thật phải vẫn hiển thị 0 |
| Các nút “Lưu”, “Validate”, “Commit”, “Rollback” | Giữ riêng vì tác dụng khác nhau, đặt tên đầy đủ | Không gom thành một nút làm thay đổi mạng ngoài dự tính |

### 3.3 Từ điển trạng thái thay cho `Unavailable` dùng chung

| Điều kiện thật | Cách hiển thị | Điều không được suy ra |
|---|---|---|
| Chưa có phản hồi đầu tiên | Đang tải | Không có phiên / 0 lỗi |
| HTTP thành công, danh sách thực sự rỗng | Chưa có dữ liệu trong phạm vi này | Engine chết hoặc tất cả traffic an toàn |
| M3/M4 bị tắt theo Running | Đang tắt / Chưa bật kiểm tra | Lỗi sensor |
| Local flow ngoài M2 FORWARD | Không áp dụng — lưu lượng local | ALLOW/DROP theo policy chuyển tiếp |
| Có inspection, chưa nhận diện được app | Chưa nhận diện / UNKNOWN | HTTP chỉ vì port 80, HTTPS chỉ vì port 443 |
| Trường tùy chọn không được cung cấp | —; tooltip hoặc mô tả ngắn nếu quan trọng | Số 0, CLEAN, không có NAT |
| Đang chờ đánh giá hoặc correlation | Đang chờ, đúng trạng thái nguồn | Kết luận đã có quyết định |
| Capability không hỗ trợ | Chưa hỗ trợ; ẩn action không dùng được | Chức năng đang bật nhưng không có dữ liệu |
| 401/403 | Cần xác thực / Không đủ quyền | Detector hỏng |
| 503/timeout/network error hoặc payload báo unavailable | Không đọc được + nguồn + nguyên nhân + thử lại | Dữ liệu rỗng hoặc HEALTHY |
| Giữ lại dữ liệu cũ sau lỗi | Dữ liệu cũ, thời điểm cập nhật riêng của nguồn đó | “Vừa cập nhật” vì endpoint khác còn hoạt động |
| Session đã đóng hoặc event hết retention | Phiên đã kết thúc / Bản ghi đã hết thời gian lưu | Lỗi toàn hệ thống |
| Zero đo được thật | 0 | Dữ liệu thiếu |

## 4. Nguồn dữ liệu và quy tắc đối chiếu

UI lấy dữ liệu qua API/WS của NGFW. Không xây browser crawler đọc SSH, shell hoặc scrape log để thay API. CLI dưới đây chỉ là nguồn độc lập cho **người chạy test**.

| Dữ liệu | API hiện có | Nguồn đối chứng / giới hạn |
|---|---|---|
| Health runtime | `GET /api/v1/health` | `systemctl`, journal, engine IPC; HTTP 200/engine reachable chưa chứng minh mọi kernel object đúng |
| Config | `GET /api/v1/config` | Running, Candidate, validation state và version; giữ cả hai bản thô trước test |
| Session | `GET /api/v1/sessions`; `GET /api/v1/sessions/{id}` | `conntrack`, traffic log; query hiện có: source/destination IP, zone, protocol, state, decision, tuple_view, page, page_size |
| Tổng runtime | `GET /api/v1/stats/system`; `/ws/stats` | Không có aggregate ALLOW/App-ID thì không tự tạo từ một trang session |
| Runtime event | `GET /api/v1/events?after=...&limit=...`; `/events/{sequence}`; `/ws/events` | Event kind/class/sequence/time/reason; lịch sử hữu hạn, không phải audit vĩnh viễn |
| M3 | `/api/v1/inspection/health`, `/inspection/capabilities`, `/security/events`, `/security/events/{id}` | EVE/Suricata thật, capture/lease và packet trace khi cần; cursor/stream/gap riêng |
| M4 | `/api/v1/request-gate/health`, `/request-gate/capabilities`, `/request-gate/evidence?after_sequence=...&limit=...` | Proxy/engine evidence, client và origin log. Evidence có `forward` khác với `decision` |
| Interface/zone/route/NAT config | `/api/v1/interfaces`, `/zones`, `/routes`, `/nat/rules` và `/config` | Các endpoint config không đồng nghĩa inventory/live state. `ip -j -d link`, `ip -j address`, `ip -j route`, `ip rule`, `networkctl` làm oracle |
| Block / audit / account | `/api/v1/blocks`, `/audit`, `/auth/*`, `/users` | Kết quả action và audit; quyền theo backend, không theo “đã có chuỗi token” |

Nếu cần bổ sung inventory/counters, đi qua engine và IPC/API đọc có giới hạn theo kiến trúc hiện tại. Không thêm quyền chạy `ip`/`nft`/`systemctl` vào API hoặc browser. Endpoint mới chỉ được ghi là có sau khi thực sự triển khai và kiểm thử.

**Quan hệ lịch sử:** event runtime hiện không chứa tuple đầy đủ. Liên kết tới session còn sống là tiện ích; khi session hết hạn phải nêu đúng giới hạn. Lưu snapshot tối thiểu của tuple/action/policy tại thời điểm event chỉ là yêu cầu mở rộng nếu người dùng cần điều tra lịch sử độc lập. Bộ UI này không đòi thêm bản sao đầy đủ RuntimeSession vào mọi event.

## 5. Chuẩn bị và cách chạy

### 5.1 Không dùng trạng thái cũ làm baseline mới

1. Ghi git HEAD + dirty diff, hash binary engine/API/proxy, frontend source/build, hostname, boot ID, thời gian UTC và timezone browser. Nguồn VM có thể khác workspace; không build đè bản đang triển khai mà chưa biết nguồn.
2. Xác minh UI lab tại `http://192.168.100.1:5173` và API VM. URL này là lần cấu hình gần nhất, không phải giả định luôn online. Vite hiện là dev server; không coi nó tự khởi động sau reboot nếu chưa có cơ chế đó.
3. Browser tự động có thể chạy trong VM bằng Playwright/Chromium đã cài, hoặc browser quản trị truy cập cùng URL. Ghi rõ browser ở đâu. **Phải bấm nút/đọc DOM của frontend thật**; curl API không thay thế bằng chứng UI.
4. Chụp riêng Running và Candidate nguyên bản, validation, config version, hash; kiểm tra có nháp của người dùng. Sau test khôi phục **cả Running và Candidate ban đầu**, không mặc định Candidate=Running.
5. Ghi trạng thái service, nftables, địa chỉ, route, policy rule, listeners. Giữ đường MGMT ens39 và uplink tải dependency ens40; không đổi role/route của hai NIC đó chỉ để test UI.
6. Tạo run ID dạng `ui-acceptance-<UTC>`. Dữ liệu test dùng prefix `ui-test-<run-id>`. Không xóa rule/session/block của người dùng để làm trống trang.
7. Kiểm tra D01 bằng fixture/clone trước. Nếu UI mất trường cấu hình, **dừng các bài ghi trên VM chính**; các bài chỉ đọc vẫn có thể tiếp tục.

### 5.2 Ba loại bằng chứng, không được đánh đồng

| Loại | Dùng khi | Cách ghi kết quả |
|---|---|---|
| LIVE | UI thật → API thật → engine/traffic thật trên VM | Có thể kết luận UI tích hợp với hệ thống thật trong phạm vi đã đo |
| FIXTURE | Browser intercept response để thử field thiếu, dữ liệu sai, số lớn, timeout, trạng thái hiếm | Chỉ chứng minh render/interaction chịu được dữ liệu đó; không chứng minh detector/kernel hoạt động |
| CLONE | VM/stack tách biệt để thử lỗi apply, restart, cạnh tranh config hoặc thay đổi nguy hiểm | Ghi môi trường clone và phần tương đương; không tự gắn nhãn đã thử trên appliance chính |

Fixture không được ghi bản ghi giả vào event stream sản phẩm. Nếu chưa có điều kiện LIVE, ghi `BLOCKED`/`NOT_RUN` cho phần live, không đổi thành PASS vì fixture đúng.

### 5.3 Bộ dữ liệu tối thiểu

| Mã | Dữ liệu cần tạo/quan sát | Mục đích |
|---|---|---|
| F0 | UI/browser → MGMT; loopback Vite → API; quan sát 22/5173/8080 nếu hiện có | Local không áp dụng policy FORWARD |
| F1 | TCP giữ kết nối từ LAN tới origin DMZ hoặc WAN lab, rule ALLOW hẹp | Tuple, port, decision, counter, revoke |
| F2 | Kết nối mới bị DROP/REJECT bởi rule test hẹp, có capture/counter | Phân biệt policy deny với lỗi mạng; không bắt buộc kernel giữ session cho mọi packet bị drop |
| F3 | Luồng SNAT/MASQUERADE và DNAT dùng rule lab đã biết, origin riêng | Original/reply/translated tuple và NAT context |
| F4 | UDP/DNS lab và ICMP lab nếu policy cho phép | Không bịa port/TCP state cho giao thức không có |
| F5 | Trên 100 session, có một session mục tiêu ở trang sau; có cả local và forwarded | Phân trang/tìm kiếm, phạm vi tổng |
| F6 | Session đóng nhưng runtime event vẫn còn; một event đã hết retention | Drawer lịch sử, 404, liên kết |
| F7 | IDS alert và IPS packet/drop guard từ marker vô hại trong bộ M3 hiện có | Không nhầm cảnh báo với enforcement |
| F8 | M4 clean, BLOCK và BYPASS/không inspection; request ID, client và origin log | Request decision, coverage, forward và TLS đúng nguồn |

Địa chỉ lab tham chiếu: NGFW WAN `192.0.2.2`, LAN `192.168.10.1`, DMZ `10.20.0.1`, MGMT `192.168.100.1`; client LAN `.10`, origin DMZ `10.20.0.10`, WAN `192.0.2.1`. ens40 dùng DHCP nên đọc địa chỉ hiện tại. Port test phải kiểm tra trống, khai báo trước trong manifest và dùng rule có phạm vi hẹp. Không gửi marker kiểm thử ra Internet.

F5 có thể chạy với khoảng 150–200 kết nối tồn tại có kiểm soát, không flood. Nếu F5 fixture được dùng cho layout/phân trang, vẫn cần một bài LIVE kiểm tra session ở trang sau.

### 5.4 Bằng chứng chung cho mỗi case

- **B:** screenshot đúng thời điểm, DOM/text của giá trị, browser console/page errors, thao tác và URL.
- **A:** request method/path/status và response JSON liên quan; loại Authorization, Cookie, token trong WS subprotocol khỏi bản gửi phân tích.
- **C:** Running/Candidate/validation/version trước và sau, diff những phần được phép đổi.
- **K:** kernel/service state có liên quan: conntrack, nft, link, route, process; không phải dump mọi thứ ở mọi case.
- **T:** client/origin/packet evidence cùng flow/request ID, thời gian.
- **F:** fixture đầu vào và assertion, ghi rõ không phải traffic thật.

Tất cả 72 case dưới đây khởi đầu ở **NOT_RUN**. Mỗi hàng có các bước theo thứ tự. “Đạt” là tiêu chí tương lai, không phải kết quả của lượt lập kế hoạch.

## 6. Bộ kịch bản chi tiết

### G — Truy cập, điều hướng và quyền: 7 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| G01 / P1 / LIVE | Chạy preflight 5.1; mở URL; lần lượt mở 7 trang; ghi build/API và baseline; chưa thao tác ghi | Không trắng trang; xác định đúng appliance; nguồn chưa đọc được hiện lỗi đúng; không có POST/PUT/DELETE từ việc chỉ mở trang | B, A, C |
| G02 / P0 / LIVE | Browser mới không token; mở session/event; nhập token sai; sau đó token đúng | Protected read 401 có hướng dẫn xác thực; token sai không hiện “quyền ghi đã mở”; token đúng làm tải lại dữ liệu; health công khai không bị đánh đồng với đăng nhập thành công | B, A |
| G03 / P0 / LIVE/CLONE | Tài khoản VIEWER đăng nhập; mở policy/config/block/users; thử thao tác ghi qua UI và một request đối chứng trực tiếp | UI chặn/ẩn action không có quyền; API vẫn từ chối; không mutation. VIEWER đăng xuất được. Nếu account auth chưa cấu hình, ghi BLOCKED cho role test, không dùng API token thay VIEWER | B, A, C |
| G04 / P0 / LIVE/CLONE | So OPERATOR và ADMIN theo middleware hiện tại; thử policy Candidate, Validate, block/revoke, Commit, config/network/profile/users | Quyền UI khớp endpoint; OPERATOR không được Commit/Rollback/config/network/profile/users nếu backend đang giới hạn ADMIN; không chỉ kiểm tra token có chuỗi. Cleanup account test | B, A, C, audit |
| G05 / P0 / LIVE | Đăng nhập account → reload → đổi credential → logout → Back/reload; thử token hết hạn/đã logout | Role phục hồi từ xác thực, không tự thành ADMIN sau reload; dữ liệu bảo vệ cũ không còn hiển thị sau logout/401; account token đã logout không đọc được. Xóa static API token trên browser không được mô tả là thu hồi token toàn server | B, A |
| G06 / P1 / LIVE | Vào trực tiếp `/#sessions`, `/#network`, `/#configuration`; reload, Back/Forward; từ Policy mở JSON rồi quay lại; thử hash sai | Đúng trang/breadcrumb; hash sai fallback rõ; không sinh thao tác ghi hoặc vòng lặp history; nháp xử lý theo C02, không mất im lặng | B, A |
| G07 / P1 / LIVE + FIXTURE | Account auth không có, endpoint users 403/404; mở trang Hệ thống và cửa sổ truy cập; thử nhãn token-only | Nói rõ phương thức nào dùng được; không mời đăng nhập bằng account chắc chắn chưa cấu hình; không báo “GET luôn công khai”; lỗi từng vùng không làm mất các trang còn lại | B, A/F |

### D — Tính đúng và vòng đời dữ liệu: 8 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| D01 / P0 / FIXTURE rồi CLONE/LIVE | Tạo config hợp lệ theo schema có VLAN parent/id, profile M3, profile M4 `request_gate`, global request_gate, TLS exclusions; mở JSON; sửa duy nhất tên policy hoặc tên profile; bắt request lưu, rồi GET lại. Thử cả JSON editor, policy editor, profile editor | Chỉ field chủ ý đổi; toàn bộ field lồng nhau khác được giữ; trường mới frontend chưa hiểu không bị rơi. Fixture unknown field chỉ kiểm tra preservation, không buộc backend nhận field ngoài schema. Nếu mất trường: FAIL, khóa các bài ghi tiếp theo | F, A, C |
| D02 / P0 / LIVE | Chọn một flow/event thật; so kernel/engine → HTTP JSON → adapter → DOM. Chọn M4 evidence có `forward` nếu M4 đã được cấu hình cho bài này | Giá trị không biến mất giữa các lớp; ghi đúng lớp đầu tiên làm sai. Không sửa DOM bằng giá trị hardcode để hợp output test | B, A, K/T |
| D03 / P0 / FIXTURE | Cho các response lần lượt: thiếu field, null, số 0 thật, `items=[]`, HTTP 200 nhưng `status=unavailable`, sai JSON, record lỗi cạnh record tốt | Theo từ điển 3.3; không crash toàn trang; không default action thành ALLOW hoặc health xanh; không bỏ record tốt; dữ liệu config lỗi không được chuẩn hóa thành config sẵn sàng ghi | B, A, F |
| D04 / P1 / FIXTURE | Sau khi dữ liệu tốt đã hiện, chỉ cho `/sessions` hoặc `/config` timeout; health/stats vẫn thành công; phục hồi endpoint | Giữ dữ liệu cũ có nhãn stale và timestamp riêng; nguồn khác vẫn đọc được; lỗi có Retry; phục hồi gỡ đúng lỗi, không ghi “vừa cập nhật” cho nguồn còn chết | B, A, F |
| D05 / P0 / CLONE/LIVE | Hai tab cùng đọc config; tab A có editor dirty; tab B thay Candidate rồi commit một thay đổi hẹp; refresh tab A và thử lưu/commit bản cũ | Không overwrite editor dirty; báo bản nền đã đổi. Commit expected_version cũ bị reject. Nếu backend chưa có guard cho Candidate revision, ghi gap rõ và ngăn lưu đè mù; không dùng Running version để giả chứng minh bảo vệ mọi race Candidate | B, A, C |
| D06 / P1 / LIVE + FIXTURE | Tạo runtime/security events; tải trang, nhận WS, mất WS, polling bù, reconnect; thử stream đổi sau restart trong clone và cursor đã hết retention | Không thiếu/trùng vì poll đè WS; dedup theo đúng stream/type/ID, không chỉ chuỗi ID dễ đụng; reset/gap được báo; không trộn event cũ thành event boot mới; giữ giới hạn bộ nhớ | B, A, F/K |
| D07 / P0 / FIXTURE | Flow ID uint64 lớn hơn JS safe integer ở dạng string; IPv6; tên Unicode; reason chứa HTML/script; timestamp UTC; confidence enum HIGH và số confidence thật | ID giữ nguyên; text không thực thi HTML/script; IPv6/port dễ đọc; giờ đúng UTC+7; enum confidence giữ định tính, không tự đổi HIGH thành 90%; không invent severity/risk | B, F |
| D08 / P0 / FIXTURE | Làm chậm response dưới token A, logout/đổi sang B trước khi response về; đổi filter rồi để response filter cũ về muộn; mở detail A rồi detail B | Response thuộc credential/filter/selection cũ không ghi đè trạng thái mới hoặc làm lộ dữ liệu sau logout; request cũ bị bỏ/abort; hết loading có giới hạn | B, A, F |

### O — Tổng quan: 5 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| O01 / P1 / LIVE | Dùng F5, lấy `/sessions` page metadata và `/stats/system` cùng cửa sổ thời gian; mở Tổng quan | Tổng là số phiên được theo dõi theo stats; số trong trang có scope riêng hoặc không hiện; không lấy 100 để suy ra tất cả ALLOW/Unavailable; TIME_WAIT không gọi tất cả là đang truyền dữ liệu | B, A, K |
| O02 / P0 / LIVE | Tạo Candidate khác Running nhưng chưa Commit, đọc policy/default action/version trên Tổng quan/Hệ thống | Posture vận hành lấy Running; thay đổi nháp hiện riêng. Không tuyên bố rule Candidate đang bảo vệ traffic | B, A, C |
| O03 / P0 / LIVE + FIXTURE | So M3/M4 OFF với enabled nhưng sensor/proxy/lease lỗi; thử engine unreachable và API HTTP vẫn trả lỗi có cấu trúc | OFF là chủ động tắt; enabled+failure là suy giảm/lỗi; “engine reachable” không đổi thành “toàn bộ dataplane đã xác minh”; số thành phần healthy không bị gọi là tổng process đang chạy | B, A, K/F |
| O04 / P1 / LIVE + FIXTURE | Bấm card session/block/event và “Xem tất cả”; đối chiếu filter/số đếm; tạo cảnh báo security thật giữa nhiều lifecycle event | Đi đúng nội dung/phạm vi; lifecycle không bị đếm thành threat; security cần xử lý vẫn nhìn thấy; count theo cửa sổ/retention có nhãn | B, A, T/F |
| O05 / P1 / LIVE + FIXTURE | Inspection không có App aggregate; event ring bị eviction có kiểm soát trong fixture/clone; so drops/queue và card block | Ẩn aggregate thiếu nguồn; event retention/drop không gọi packet loss; không gắn event drops như chỉ số của temporary block; nếu API gộp counter, nhãn nói đúng giới hạn hoặc báo thiếu telemetry | B, A, F/K |

### S — Sessions: 9 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| S01 / P1 / LIVE | F0 và F1 cùng tồn tại; chuyển bộ lọc phiên chuyển tiếp, local, tất cả; xem decision/path/App-ID | Local được giải thích không áp dụng FORWARD; không amber lỗi hàng loạt vì local. Không suy đoán scope chỉ từ IP private; dùng zone/reason/metadata đáng tin. Trạng thái thiếu thật vẫn khác local | B, A, K/T |
| S02 / P1 / LIVE | Giữ F1 với source port đã ghi; mở bảng và drawer; so IP/port/protocol/state; copy nếu có nút | Cả hai port đọc rõ; không ẩn port trong chữ 8px; ID và tuple đúng flow; header drawer không dùng “Unavailable” như tên kết nối | B, A, K, T |
| S03 / P1 / LIVE | F3 SNAT/MASQUERADE và DNAT; mở detail mỗi flow; so original/reply/translated với conntrack và capture hai phía | NAT directions được gắn nhãn, không tráo client/server; translated tuple chỉ hiện khi nguồn có; không tự điền bằng original để che thiếu | B, A, K, T |
| S04 / P1 / LIVE + FIXTURE | F4 UDP/ICMP; dùng fixture IPv6 hoặc chạy IPv6 riêng nếu lab sẵn | UDP không mang TCP ESTABLISHED; ICMP không hiện port 0 như một cổng dịch vụ; IPv6 hiển thị đúng, fixture không được ghi là IPv6 forwarding đã nghiệm thu | B, A, K/T/F |
| S05 / P1 / LIVE + FIXTURE | F1 có counters bằng 0 lúc đầu rồi gửi dữ liệu; một record thiếu counters; theo dõi state CLOSING/expiry | 0 thật khác thiếu số liệu; đơn vị bytes/packets đúng chiều original/reply; số làm tròn có quy tắc; không đòi equality giữa snapshot khác thời điểm; biết thời điểm đo | B, A, K/T/F |
| S06 / P0 / LIVE + FIXTURE | F1 ALLOW; F2 deny; sau thay policy tạo INVALIDATED; thử revoked DROP và kernel_cache_verified=false | Decision/effective decision/cache state không bị trộn; INVALIDATED không giữ ALLOW cũ như hiệu lực hiện tại; revoked DROP không mất; FAST chỉ hiện khi có provenance, không suy từ ALLOW | B, A, K/T/F |
| S07 / P1 / LIVE + FIXTURE | F5; tìm session ở trang 2 bằng IP rồi port/protocol/policy/ID; đổi filter khi đang trang 2; dữ liệu thay đổi trong lúc chuyển trang | Có điều khiển phân trang và total/has_more đúng; filter backend hỗ trợ áp dụng toàn tập. Filter chưa được backend hỗ trợ phải ghi rõ chỉ tìm trong trang đã tải hoặc được bổ sung có giới hạn; không báo “không có trong hệ thống” từ trang 1 | B, A, T/F |
| S08 / P1 / LIVE + FIXTURE | Click session vừa hết hạn F6; lần lượt trả 401,403,503,timeout; click hai row nhanh, đóng drawer trước response | 404 hiện session đã kết thúc; lỗi khác có nguyên nhân/Retry; không đóng im lặng hoặc mở lại sau khi người dùng đóng; không hiển thị detail của row khác | B, A, F |
| S09 / P0 / LIVE | Chọn F1 không thuộc MGMT/SSH/UI; bấm action chặn phiên, Cancel rồi Confirm; thử double-click; kiểm tra flow cũ và flow mới có identity khác | Cancel không DELETE; Confirm chỉ một thao tác; thông báo revoke DROP đúng API, không hứa TCP RST; traffic/counter chứng minh flow cũ bị chặn; không chặn nhầm phiên mới/cả IP; audit đúng | B, A, K, T, audit |

Cleanup nhóm S: đóng client/origin test, gỡ rule/guard test theo cơ chế backend hỗ trợ, khôi phục baseline. Không flush conntrack toàn máy để làm danh sách đẹp.

### E — Sự kiện, block và audit: 8 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| E01 / P1 / LIVE | Mở SessionCreated, SessionUpdated, SessionClosed và DecisionChanged thật; so raw event với drawer | Runtime chỉ có kind/time/producer/session/reason và metadata phù hợp; không có hàng signature/capture/verdict `Unavailable` không áp dụng; DecisionChanged không tự đoán action từ text nếu DTO không cung cấp | B, A |
| E02 / P1 / LIVE | F6: xem event còn giữ, bấm session đã đóng; xem event đã evict; so một liên kết còn sống | Không mất event chỉ vì session 404; báo lịch sử không chứa tuple nếu đúng contract; current session được ghi là trạng thái hiện tại, không coi là snapshot lúc event; không gán nhầm flow tái sử dụng tuple | B, A |
| E03 / P0 / LIVE + FIXTURE | F7 IDS alert, IPS packet verdict, session guard APPLIED/FAILED và correlation PENDING/UNMATCHED; mở từng drawer | IDS alert không thành “đã chặn”; packet drop không thành cả session đã chặn; thiếu enforcement không tự thành NOT_REQUESTED có vẻ là kết quả engine; correlation không chắc thì không gắn cứng session | B, A, K, T/F |
| E04 / P1 / LIVE + FIXTURE | Có trên 200 runtime/security event; lọc theo loại, severity, IP/session/request; tải thêm; thử timestamp trùng và một class `inspection` | Mới nhất hiển thị đúng; không lấy trang oldest rồi gọi toàn bộ là gần đây; loại inspection/M4 không mất khỏi bộ lọc; scope tìm kiếm/retention rõ; không reset filter mỗi poll | B, A, F |
| E05 / P0 / LIVE + FIXTURE | Security event có source rõ, có source thiếu, có NAT và correlation chưa chắc; mở action “Chặn source”; Cancel rồi Confirm trên nguồn test hợp lệ | Chỉ cho action khi có IP và đủ thông tin; xác nhận nêu đúng IP/scope/thời hạn; không chặn NGFW/upstream do hiểu nhầm tuple sau NAT; source_event đúng; không có nút chặn vô nghĩa cho lifecycle event | B, A, K, T/F |
| E06 / P0 / LIVE | Tạo temporary block cho IP client test không thuộc quản trị; thử input sai; theo dõi active → hết hạn, tạo lại rồi Gỡ | Chỉ chấp nhận loại indicator kernel hỗ trợ; input sai không tạo record “thành công”; thời hạn đúng timezone; chặn và gỡ/hết hạn có traffic đối chứng; không chỉ xóa dòng ở UI; button chống gửi lặp | B, A, K, T, audit |
| E07 / P1 / LIVE/CLONE | Thực hiện một save Candidate, Validate, Commit test, block/revoke; một request bị từ chối; mở Audit | Actor/role/action/resource/time/result đúng backend; không nói Validate đã áp dụng kernel; lỗi không thành success. Kiểm tra những failure backend có contract audit; nếu chưa audit một loại, ghi thiếu cụ thể, không tự tạo audit ở browser | B, A, C |
| E08 / P1 / LIVE + FIXTURE | Mở mọi tab event/control; inspection OFF; reputation không có enforcement; gửi reason/path có token mẫu giả để kiểm tra render/redaction | Reputation không được quảng cáo là bảo vệ đang chạy; metadata thu gọn, giữ cảnh báo cần xử lý; không lộ Authorization/Cookie/body/query bí mật hoặc private key; không thêm field giả để lấp drawer | B, A, F |

Cleanup nhóm E: gỡ đúng block/indicator test còn tồn tại; giữ audit đã phát sinh như bằng chứng. Không xóa lịch sử người dùng.

### P — Chính sách và profile: 6 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| P01 / P1 / LIVE | Thêm policy Candidate ID `ui-test-*` có zone/IP/service/action rõ; mở lại, sửa tên, bật/tắt, xóa; mỗi bước so Candidate và Running | Bảng thể hiện đủ điều kiện đang giới hạn rule, kể cả source/destination addresses; không làm người dùng tưởng rule áp dụng mọi IP; thao tác chỉ sửa Candidate, chưa thay traffic/kernel | B, A, C, K |
| P02 / P1 / LIVE + FIXTURE | Gõ `tcp:80, tcp:443, udp:53`, xóa rồi gõ Priority, thử chuỗi thiếu protocol, số âm, ID trùng, zone/profile không tồn tại | Có thể nhập tự nhiên; lỗi gắn đúng field, không nuốt dấu phẩy/số 0; không làm mất draft; API reject không để lại row giả; không phát Commit | B, A, C/F |
| P03 / P0 / LIVE/CLONE | Hai rule hẹp chồng match với priority khác nhau; so table, validation, sau Commit kiểm tra F1/F2; thử duplicate/shadow theo validator hiện có | Thứ tự số đúng, giải thích first-match; không âm thầm reorder/đổi action; rule bị validator reject có thông tin rõ; kết quả traffic khớp rule thực sự áp dụng | B, A, C, K, T |
| P04 / P0 / LIVE + FIXTURE | Tạo/sửa profile IDS rồi IPS, gắn app restriction; capabilities thiếu/không hỗ trợ; thử sửa profile đang có cả thuộc tính M4 | Lựa chọn theo capabilities thật; IDS không hứa inline block; restriction nêu độ trễ nhận diện/UNKNOWN theo contract; không dùng fallback capability để tự cho phép; giữ nguyên request_gate/TLS và field không sửa, theo D01 | B, A, C/F |
| P05 / P1 / LIVE + FIXTURE | Kiểm kê Scope, min/max risk, log_start/log_end, profile flags và thao tác sửa; đối chiếu validator/runtime | Scope cố định không cần select; risk chưa hỗ trợ không cho nhập như chức năng hiện hành. Log toggle chỉ quảng cáo tác dụng đã chứng minh; nếu chưa có hiệu lực phải ghi rõ/ẩn. Không xóa giá trị cũ chỉ vì ẩn control | B, A, C/F |
| P06 / P1 / LIVE | Mở editor policy/profile; đổi dữ liệu; Cancel/Escape/click ngoài; mở lại; double-click Save; từ Policy chuyển sang JSON và ngược lại | Hủy không PUT; tránh mất nháp im lặng; Save chỉ một request và chỉ đổi object chủ ý; cùng Candidate ở hai trang; giữ action sửa/xóa có tác dụng, bỏ action chết/duplicated workflow | B, A, C |

### C — Quy trình cấu hình: 8 case

Các case C phải qua D01 trước. Kiểm thử rollback/apply failure dùng config hẹp ở clone hoặc harness phục hồi đã kiểm chứng; không cố ý làm đứt MGMT trên appliance chính.

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| C01 / P0 / LIVE | Sửa editor nhưng chưa Save; sau đó Save Candidate; Validate; cuối cùng Commit, ghi trạng thái sau từng bước | Ba lớp editor/Candidate/Running rõ; chỉ Commit áp dụng kernel; version lấy từ response mới, không giả định `v+1` rồi báo success; traffic đổi đúng sau apply | B, A, C, K, T |
| C02 / P0 / LIVE | Có editor dirty và Candidate dirty riêng; Format; nạp Running rồi Cancel/Confirm; refresh và đổi trang | Format chỉ sửa text; nạp Running chỉ sửa editor; xác nhận mô tả mất gì; không reset Candidate/Running; không mất editor dirty do auto refresh/navigation mà không báo | B, A, C |
| C03 / P0 / LIVE + FIXTURE | JSON sai cú pháp; JSON hợp cú pháp nhưng VLAN/MTU/policy sai; Candidate đúng nhưng validation chưa chạy; Validate rồi sửa Candidate | Lỗi tường minh; không request nếu parse sai; rejected PUT không đổi Candidate/Running; Commit khóa khi invalid/validation thiếu/stale/synced; validation của bản cũ không dùng cho bản mới | B, A, C/F |
| C04 / P0 / LIVE | Diff chỉ thay `default_deny`, sau đó inspection, request_gate và TLS exclusions; thêm/xóa/sửa một VLAN/profile; xem panel thay đổi trước khi Commit | Diff bao phủ cả top-level và nested field; không báo “không thay đổi” vì chỉ so sáu mảng; đối tượng và giá trị trước/sau đủ để review; không cần raw config dài nếu bản tóm tắt rõ | B, A, C |
| C05 / P0 / CLONE/LIVE | Double-click Commit; tab khác tăng Running version; giả lập mạng mất sau khi server đã nhận Commit | Một action không gửi lặp; version conflict báo cần đọc lại; timeout ghi “chưa xác định kết quả” rồi đọc lại Running/audit, không tự retry Commit hoặc hứa chưa áp dụng | B, A, C, audit/F |
| C06 / P0 / CLONE | Tạo apply failure có kiểm soát bằng harness đã có; xem UI trong và sau thất bại; thử lại sau khi xử lý nguyên nhân | UI nhận lỗi apply/rollback thật; Running/version/kernel theo kết quả backend; không toast success và không xóa Candidate test để che lỗi; trạng thái cần phục hồi vẫn hiển thị | B, A, C, K, journal |
| C07 / P0 / CLONE/LIVE | Sau một commit hẹp, bấm Rollback rồi Cancel; sau đó Confirm; kiểm tra version/config/kernel | Nêu rõ khôi phục previous known-good và áp dụng kernel; Cancel không ghi; Confirm khớp trạng thái backend, không chỉ nạp editor; không đặt nhãn “Hủy nháp” cho rollback | B, A, C, K, T |
| C08 / P0 / LIVE + FIXTURE | `/config` fail/malformed, cấu hình từ phiên bản mới có field UI chưa biết; thử mở form và Save; so bản JSON xuất/lưu nếu có nút | Không dựng Candidate rỗng/default rồi cho ghi; giữ field không hiểu hoặc khóa edit với lý do; không tự làm mất subnet/profile. Sau cleanup Running và Candidate bằng baseline theo ngữ nghĩa; version có thể tăng do commit phục hồi | B, A, C, F |

### N — Mạng, NIC, VLAN, route và NAT: 7 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| N01 / P1 / LIVE | Đếm `ip -j -d link`, đối chiếu VMware NIC và Running/Candidate; mở Mạng, chọn device ngoài NGFW như ens40 | Phân biệt NIC vật lý/ảo, loopback và VLAN; không cộng VLAN thành card VMware. Thấy 5 NIC nếu inventory API đã có, trong đó 4 managed và ens40 OS-managed theo trạng thái hiện tại; thiếu inventory ghi NOT_IMPLEMENTED, không fake PASS | B, A, K, C |
| N02 / P0 / LIVE | Xem ens40/ens39 rồi thực hiện save policy/config không liên quan; so IP, owner, rule/table của update uplink trước/sau | Không tự enroll ens40, không sửa DHCP/default route/DNS khi chỉ xem hoặc sửa policy; MGMT và cơ chế egress OS giữ nguyên; địa chỉ DHCP không hardcode | B, A, C, K |
| N03 / P1 / LIVE/CLONE + FIXTURE | Candidate admin UP nhưng link live DOWN; MTU Candidate khác Running; RX/TX thiếu và RX/TX đo bằng 0; thêm IPv6 address fixture | Tách configured admin, observed link và Pending changes; không dùng admin_state vẽ link operational; đúng MTU/địa chỉ theo lớp dữ liệu; thiếu RX/TX không thành số 0 | B, A, K/C/F |
| N04 / P0 / CLONE/LIVE | Khai báo VLAN trên interface không MGMT; qua JSON Save/Validate/Commit; xem parent, VLAN ID, MTU/IP; xóa VLAN và Commit phục hồi | UI giữ đủ trường, giải thích logical/device; trạng thái sau apply khớp `ip -d link/address`; xóa không để card/state live giả; địa chỉ/route test hết đúng lifecycle; không cần thêm form VLAN để chạy case này | B, A, C, K |
| N05 / P1 / LIVE + FIXTURE | So route Candidate/Running/live; route connected, route static, default, metric; xem policy routing cho ens40 ở chi tiết nếu được hỗ trợ | Không gọi bảng static Candidate là toàn bộ bảng định tuyến; gateway/interface/metric/enabled đầy đủ; không kết luận Internet hỏng chỉ vì table main đi WAN trong khi local traffic dùng table khác | B, A, K, C/F |
| N06 / P1 / LIVE | Mở từng DNAT/SNAT/MASQUERADE; đối chiếu match source/destination zone/network/protocol/original port, translation, priority/enabled; thử F3 | Bảng/chi tiết đủ để hiểu rule match gì; MASQUERADE không hiện translated IP bịa; Running/Candidate rõ; traffic chứng minh NAT, không suy từ config rule tồn tại | B, A, C, K, T |
| N07 / P1 / LIVE + FIXTURE | Từ Mạng mở JSON rồi quay lại; sửa MTU sai/VLAN ID sai/route sai family nhưng chưa Commit; thử mất nguồn live inventory | Lỗi validation không thành live state; card Candidate có nhãn; live inventory lỗi không bị thay bằng config như thật; liên kết điều hướng và hướng dẫn chỉnh cấu hình hoạt động | B, A, C, F |

### I — Quan sát M3/M4 từ UI: 7 case

Đây là test khả năng quan sát và thao tác UI với engine hiện có, không tái chạy toàn bộ acceptance matrix M3/M4. Khi backend sai, ghi lỗi backend và phạm vi ảnh hưởng; không sửa nhãn UI để tuyên bố engine đã đúng. Kết quả M4-21 trong bằng chứng trước đây còn FAIL phải được kiểm tra trạng thái mới trước khi chọn test liên quan.

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| I01 / P0 / LIVE | M3 OFF dù service Suricata active; sau đó dùng cấu hình IDS/IPS hẹp đã chuẩn bị, đối chiếu health/capabilities | OFF không có “đang bảo vệ” chỉ vì process active; enabled/configured/capture/lease phân biệt; policy/profile ở Candidate chưa Commit không làm UI báo đang inspect | B, A, C, K |
| I02 / P1 / LIVE | F7 và traffic HTTP/TLS/DNS/SSH phù hợp nguồn inspection; mở App-ID và detail | App đúng evidence/source/confidence/coverage; TLS metadata không đổi thành HTTPS đã giải mã; UNKNOWN giữ đúng; không dùng port làm bằng chứng App-ID | B, A, T, EVE |
| I03 / P0 / CLONE + FIXTURE | Inspection bật; mất reader/sensor heartbeat/capture hoặc IPS lease; phục hồi; dùng outage trong clone, fixture để cover tổ hợp trạng thái | Cảnh báo đúng nguyên nhân, không CLEAN; fail-open được giải thích; UI không tự restart sensor/đổi policy; phục hồi trạng thái theo dữ liệu mới, không che outage bằng data cũ | B, A, K, T/F |
| I04 / P1 / LIVE + FIXTURE | Mở request-gate health/capabilities khi OFF, khi proxy active nhưng listener/CA/workers chưa ready, rồi cấu hình M4 hẹp hợp lệ | Có nơi xem M4; supported không tự thành production_ready; hiển thị enabled, readiness, reason và limitations đúng; UI chưa có panel thì FAIL/NOT_IMPLEMENTED, không ghi PASS vì API đã có | B, A, K/F |
| I05 / P0 / LIVE | F8 clean và blocked request; xem request evidence list/detail; so request ID, method/path đã lọc, inspection result, decision, `forward`, origin log; sau đó poll kết quả forward cập nhật | ALLOW là quyết định cho phép, không đồng nghĩa origin nhận/200. BLOCK có evidence đúng request, không tuyên bố cả session bị chặn; không mất `forward` giữa DTO/adapter/UI; update cùng event không bị dedup bỏ phần mới | B, A, T, proxy/engine log |
| I06 / P0 / LIVE + FIXTURE | TLS DECRYPT, BYPASS/exclusion, không SNI/unsupported theo capability; dữ liệu PARTIAL/UNAVAILABLE, queue/timeout và failure code; dùng fixture cho biến thể chưa nghiệm thu | Bypass không là inspected/clean; PARTIAL không là kiểm tra đầy đủ; không lộ private key/body/credential/query; giới hạn HTTP/3/WebSocket/ECH đúng capability/spec, không quảng cáo đã hỗ trợ; lỗi backend còn tồn tại hiện trung thực | B, A, T/F |
| I07 / P1 / LIVE + FIXTURE | M4 evidence nhiều trang (`limit` tối đa theo API hiện tại là 128), tải thêm, cùng sequence cập nhật forward; session gốc hết hạn; restart/reset trên clone nếu cần | Cursor riêng M4 không trộn cursor M3/runtime; request ID không bị ép thành session ID; session đóng vẫn xem evidence còn retention; nếu API chưa cho biết gap/reset thì UI không hứa lịch sử đầy đủ và phải ghi giới hạn | B, A, F/K |

Cleanup nhóm I: phục hồi Running/Candidate, profile, CA fixture và listeners theo manifest của runner; trở về đúng trạng thái service trước test. Không xóa CA đang dùng của người dùng và không chép private key vào artefact.

### U — Nút bấm, khả năng sử dụng và tải giao diện: 7 case

| ID / mức / loại | Điều kiện và bước thực hiện | Tiêu chí đạt | Bằng chứng |
|---|---|---|---|
| U01 / P1 / LIVE | Liệt kê mọi button/link/input/select/form ở 7 trang, các tab, modal và drawer; bấm mỗi action có nghĩa trong một trạng thái hợp lệ và một trạng thái lỗi/hủy | Mỗi control có tác dụng rõ, đúng API/state, có pending/success/error; control không có tác dụng được bỏ/disable có lý do. Không dùng test selector đếm nút làm bằng chứng chức năng | B, A, `controls-inventory.md` |
| U02 / P2 / LIVE | Viewport 1366×768, 1920×1080, 1024×768; zoom 100% và 125%; thử 390px cho menu/nội dung cơ bản | IP/port/decision dễ đọc; text dữ liệu chính đề xuất ≥14px, phụ quan trọng ≥12px; không cắt action/đè modal; bảng rộng cuộn trong vùng; không mất nút ở màn nhỏ | Screenshot/DOM ở từng kích thước |
| U03 / P2 / LIVE | Dùng Tab/Shift+Tab/Enter/Escape; mở/đóng modal và drawer; thử icon-only; lỗi form | Focus nhìn thấy và quay về đúng control; icon có tên truy cập/tooltip; Escape không bỏ nháp ngoài dự tính; không dùng màu đơn độc để báo lỗi/trạng thái | B, DOM/accessibility snapshot |
| U04 / P1 / LIVE + FIXTURE | Tên dài, IP IPv6, nhiều zone/service, tiếng Việt, reason dài; timestamp hơn 1 phút; thiếu field hợp lệ; dữ liệu chứa từ developer như epoch/revision | Nội dung không phá layout, xem/copy đầy đủ được khi cần; thời gian tuyệt đối và timezone rõ; không còn mảng `Unavailable` không áp dụng; thuật ngữ kỹ thuật ở chi tiết và có giải thích ngắn | B, F |
| U05 / P1 / LIVE + FIXTURE | Mở UI idle 10 phút; chuyển tab 20 lần; đóng/mở drawer; mất/reconnect WS; chuyển browser background 2 phút; theo dõi request và listeners | Không nhân poll timer/socket mỗi navigation; request không chồng vô hạn; không quét toàn bộ session mỗi nhịp để bù thiếu phân trang; background giảm tải; UI không tự tạo mutation. Ghi request count, conntrack local và tài nguyên trước/sau | B, A, browser performance, K |
| U06 / P2 / LIVE + FIXTURE | Danh sách 200 session và tối đa event buffer cấu hình (fixture tới 10.000 nếu UI giữ mức đó); mở/filter/scroll; so phút 5 và phút 10 sau warm-up | Không trắng trang/freezing kéo dài; control phản hồi mục tiêu ≤1 giây khi không đợi API; DOM/bộ nhớ có giới hạn, không tăng không giới hạn sau đầy buffer; không render mọi detail ngầm | B, F, performance trace và số đo |
| U07 / P0 / LIVE/CLONE | Tổng kiểm tra sau suite: đóng browser test, cleanup overlay, so baseline; thử management access và một flow M1/M2, M3/M4 theo baseline bật/tắt ban đầu | Running/Candidate và kernel tương đương baseline trừ version/time/counter được giải thích; không còn rule/block/process test ngoài manifest; không credential trong artefact; không có lỗi console chưa giải thích; các chức năng đang bật trước test còn hoạt động | C, K, T, B, manifest |

## 7. Kiểm kê nút và kết quả mong đợi

Đây là danh mục khởi đầu cho U01; runner phải bổ sung control thực sự tồn tại ở bản đang test. Nút lặp ở hai vị trí vẫn phải dùng chung một handler/state, không tạo quy trình mới.

| Control | Tác dụng đúng | Ràng buộc |
|---|---|---|
| Điều hướng, Back, breadcrumb, Xem tất cả | Chuyển view/filter/history | Không ghi config, không tự mất draft |
| Làm mới / Thử lại | Đọc lại nguồn cần thiết | Không Commit; chống yêu cầu lặp vô hạn; báo nguồn còn lỗi |
| Search/filter/page/load more | Thay truy vấn hoặc lọc phạm vi đã khai báo | Không nói tìm toàn hệ thống nếu chỉ lọc bộ nhớ trang hiện tại |
| Click row | Mở detail đúng ID | Loading, 404, error và response đến muộn được xử lý |
| Chặn/revoke phiên | Gọi session DELETE cho đúng ID theo quyền | Xác nhận tuple/scope; không gọi “đã gửi RST” |
| Thêm/Gỡ block | Enforcement theo IP/TTL backend hỗ trợ | Không chặn nhầm local/MGMT; audit; hết hạn thật |
| Thêm/Sửa/Xóa/Bật/Tắt policy/profile | Cập nhật Candidate | Không áp dụng traffic trước Commit; preserve field ẩn |
| Format | Chỉ format editor | Không API write |
| Nạp Running vào editor | Chỉ thay buffer editor | Cảnh báo overwrite draft; không Rollback dataplane |
| Lưu vào Candidate | PUT Candidate hoặc resource Candidate | Không Commit; invalid response không được báo lưu thành công |
| Validate | Đánh giá Candidate hiện tại | Không kích hoạt cấu hình; mất hiệu lực khi Candidate đổi |
| Commit | Kích hoạt Candidate đã validate | Khóa theo quyền/phiên bản/dirty/pending; xử lý timeout không chắc kết quả |
| Rollback | Áp dụng previous known-good | Không phải discard editor/Candidate; có xác nhận tác dụng thật |
| Đăng nhập / Lưu token | Xác minh credential và cập nhật trạng thái truy cập | Lưu chuỗi chưa được xác thực không thành “đã mở quyền ghi” |
| Đăng xuất | Xóa credential của browser, revoke account session khi hỗ trợ | Đóng WS/clear dữ liệu bảo vệ; không hứa đổi static server token |
| Tạo/Sửa/Xóa tài khoản | Chức năng ADMIN của backend nếu đã cấu hình | Không lộ password/hash/token; giữ cơ chế bảo vệ tài khoản hiện tại/admin cuối theo backend |
| Đóng/Hủy/Escape/click ngoài | Kết thúc thao tác UI | Không phát write; không làm mất nháp mà không có chính sách rõ |

## 8. Thứ tự thực thi và cổng dừng

1. **Đọc và đóng băng baseline:** G01, nguồn/binary/config manifest, controls inventory sơ bộ. Không coi URL truy cập được là toàn bộ ứng dụng hoạt động.
2. **Bảo vệ dữ liệu và quyền:** D01, D03, D07, D08, G02–G05 bằng môi trường phù hợp. Nếu mất config/sai quyền/lộ dữ liệu thì sửa trước những case ghi có liên quan.
3. **Đọc thông tin thật:** O, S01–S08, E01–E04, N01/N03/N05/N06, I01/I04. Phần chưa triển khai ghi thẳng NOT_IMPLEMENTED.
4. **Ghi có kiểm soát:** P, C, S09, E05–E07, N02/N04/N07. Dùng overlay hẹp và giữ Candidate riêng. Mỗi nhóm có cleanup trước nhóm kế tiếp.
5. **M3/M4 có traffic:** F7/F8, I02/I03/I05–I07 và event enforcement. Dùng runner hiện có để chuẩn bị traffic, nhưng capture browser ở đúng giai đoạn profile đang bật; không chạy runner xong đã restore rồi mới chụp UI.
6. **Chất lượng và vận hành:** G06/G07, D04–D06, O05/E08 và U01–U06; cuối cùng U07.

Các nhóm có thể đổi thứ tự theo dependency, nhưng không bỏ D01 trước ghi, xác thực trước mutation hoặc cleanup cuối. Không tự chạy lại toàn bộ soak M3/M4 chỉ để kiểm tra một nhãn UI.

**Nếu phát hiện sai lệch:**

1. Lưu response và screenshot trước khi sửa; nêu expected/actual cụ thể.
2. Xác định tầng lỗi: detector/kernel → engine/domain → IPC → HTTP DTO → adapter UI → render → thao tác người dùng. Một tầng đúng không miễn kiểm tra tầng tiếp theo.
3. Sửa tại tầng làm mất/sai dữ liệu. Không đặt exception theo IP/session ID/payload của case, không fabricate metadata/confidence/risk/health.
4. Kiểm tra ca lỗi, ca tương tự khác dữ liệu và một ca lỗi/thiếu dữ liệu đối chứng. Không cần thêm test lặp lại markup đơn thuần.
5. Nếu sửa code: theo yêu cầu workflow trước đó của người dùng, commit đúng file liên quan, push GitHub và pull VM; build/deploy đúng nguồn đã xác minh. Ghi commit + dirty patch/hash nếu có thay đổi chưa commit. Không `git add .`, reset hoặc đè source VM có thay đổi chưa rõ.
6. Chạy lại phần UI thật chịu ảnh hưởng. Unit/build pass không thay LIVE acceptance. Nếu chỉ sửa CSS/label, không cần restart engine.

## 9. Cách lưu và báo cáo kết quả cho người dùng

Thư mục đề xuất:

```text
artifacts/ui-acceptance-<UTC>/
  RESULTS.md
  run-manifest.json
  controls-inventory.md
  issues.md
  baseline/                 # config/service/kernel đã loại secrets
  G01/ ... U07/             # chỉ tạo folder những case đã chạy
    steps.md
    assertions.json
    api-redacted.jsonl
    browser-console.jsonl
    screenshots/
    oracle/                 # conntrack/nft/traffic khi case yêu cầu
    fixture.json            # chỉ có nếu FIXTURE, có nhãn rõ
  cleanup-verification.md
  SHA256SUMS.txt
```

Mỗi case có record:

```json
{
  "case_id": "S02",
  "status": "NOT_RUN",
  "mode": "LIVE",
  "started_utc": null,
  "finished_utc": null,
  "source_commit": "",
  "binary_manifest": "",
  "browser": "",
  "running_version_before": null,
  "running_version_after": null,
  "expected": "",
  "actual": "",
  "assertions": [],
  "evidence": [],
  "issue_id": null,
  "cleanup": "NOT_RUN"
}
```

Trạng thái hợp lệ:

- **PASS:** đủ mọi assertion và evidence cho loại test ghi trên record.
- **FAIL:** có hành vi sai hoặc sai lệch dữ liệu đã tái hiện.
- **PARTIAL:** chỉ chạy một phần biến thể; ghi phần còn thiếu.
- **BLOCKED:** chưa chạy được do prerequisite, quyền hoặc backend chưa sẵn sàng; không gọi PASS.
- **NOT_IMPLEMENTED:** thiếu feature/nguồn dữ liệu theo yêu cầu mục tiêu, ví dụ live NIC inventory hoặc M4 UI.
- **NOT_RUN:** chưa thực hiện.
- **N/A:** chỉ dùng nếu trường hợp thực sự ngoài phạm vi đã thống nhất; không dùng cho tính năng bắt buộc đang thiếu hoặc vì không đủ thời gian.

Nếu một case có LIVE và FIXTURE, lưu từng subcase. Parent chỉ PASS khi tất cả subcase bắt buộc hoàn tất; một PASS FIXTURE không biến LIVE chưa chạy thành PASS.

Sau mỗi nhóm báo ngắn: case đã chạy, kết quả, lỗi nghiêm trọng, phần đã sửa, phần chưa test và link bằng chứng. `issues.md` cần có: issue ID, case, tầng lỗi, mức ưu tiên, cách tái hiện, expected/actual, file sửa nếu có, retest và regression liên quan. Không ghi “xong UI” chỉ vì mở được các trang.

## 10. Tiêu chí nghiệm thu cuối và phạm vi còn lại

### 10.1 UI dùng được cho demo có kiểm soát

- Không còn lỗi P0 trong phạm vi demo và các nguồn dữ liệu hiển thị.
- Mở web, xác thực, xem phiên F0/F1, đọc event đúng loại, xem Running/Candidate, sửa/validate/commit/rollback hẹp được chứng minh bằng browser + API + kernel/traffic phù hợp.
- Mọi mục chưa có nguồn/chưa hỗ trợ được ghi rõ hoặc ẩn khỏi luồng chính; không có cam kết bảo vệ giả.
- M3/M4 nếu đưa vào demo phải có health và evidence UI LIVE cho chức năng demo. Nếu chưa làm thì phải nêu giới hạn đó, không quảng cáo UI hỗ trợ đầy đủ M4.
- Cleanup đã xác minh. Có thể bàn giao demo với danh sách P1/P2 còn thiếu, nhưng không gọi đó là hoàn tất toàn bộ đặc tả này.

### 10.2 Hoàn tất bộ UI M1–M4 theo tài liệu này

- Toàn bộ yêu cầu P0/P1 có kết quả và bằng chứng; không còn FAIL/NOT_IMPLEMENTED/PARTIAL/BLOCKED ở P0/P1 để rồi tổng kết “đã đủ”.
- Các P2 có kết quả và giới hạn ghi rõ. Nếu còn P2 chưa đạt, dùng nhãn “đạt chức năng, còn cải thiện sử dụng”, không gọi mọi case PASS.
- Mọi control đang hiển thị được kiểm kê và có tác dụng đã kiểm tra; control bỏ đi phải có lý do và không làm mất dữ liệu cấu hình.
- Không tăng bản sao session/event hay thêm dịch vụ mới chỉ để UI bớt trống. Nếu backend cần thêm telemetry, có contract, giới hạn tải và kiểm thử tương ứng.
- Kết luận UI độc lập với kết luận engine: UI hiển thị đúng một lỗi M4 là PASS cho cách hiển thị, nhưng lỗi M4 vẫn là lỗi phải theo dõi ở matrix của nó.

## 11. Prompt bàn giao cho model thực thi

> Đọc `docs/UI_ACCEPTANCE_AND_SIMPLIFICATION_SPEC.md` và các file nguồn được dẫn. Rà lại source/binary/config đang có, không lấy tình trạng cũ làm kết quả mới. Chạy 72 case theo dependency và ghi subcase LIVE/FIXTURE/CLONE rõ ràng. Bắt đầu từ baseline, D01 preservation và quyền truy cập trước các thao tác ghi. Với lỗi đã tái hiện, sửa nguyên nhân tổng quát và retest, giữ nguyên dữ liệu/nháp không liên quan. Tinh gọn UI theo mục 3; không thêm risk/ML giả, không lấy port suy App-ID, không coi health API là chứng minh mọi engine/dataplane đang bảo vệ. Không tự đưa ens40 vào NGFW Running. Nếu sửa code, push đúng commit và pull/build VM theo nguồn đã xác minh, bảo toàn dirty work. Báo kết quả từng nhóm kèm bằng chứng, khôi phục baseline cuối cùng. Thiếu điều kiện ghi BLOCKED/NOT_RUN; thiếu feature ghi NOT_IMPLEMENTED; không sửa tiêu chí để biến fail thành pass.

## 12. Tổng số case

| Nhóm | Phạm vi | Số case |
|---|---|---:|
| G01–G07 | Truy cập, điều hướng, quyền | 7 |
| D01–D08 | Độ đúng và vòng đời dữ liệu | 8 |
| O01–O05 | Tổng quan | 5 |
| S01–S09 | Sessions | 9 |
| E01–E08 | Event, block, audit | 8 |
| P01–P06 | Policy/profile | 6 |
| C01–C08 | Cấu hình | 8 |
| N01–N07 | Mạng | 7 |
| I01–I07 | M3/M4 trên UI | 7 |
| U01–U07 | Control, trải nghiệm, tải UI, cleanup | 7 |
| **Tổng** | **Chưa chạy trong lượt lập tài liệu** | **72** |
