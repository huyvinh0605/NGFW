# SENTINEL NGFW Console – hướng dẫn sử dụng giao diện

Tài liệu này dành cho người vận hành và quản trị viên sử dụng web console của
NGFW. Nội dung giải thích ý nghĩa của từng màn hình, panel, nút bấm, cột dữ
liệu, trạng thái và con số hiển thị trên giao diện.

Console là lớp quản trị và quan sát. `ngfw-engine` mới là thành phần áp dụng
policy, session và enforcement xuống appliance. Vì vậy một thay đổi chỉ được
coi là có hiệu lực khi giao diện báo thành công sau khi backend/engine xác nhận.

## 1. Điều kiện sử dụng

Quản trị hệ thống phải khởi động sẵn `ngfw-engine`, `ngfw-api` và frontend.
Người dùng mở URL được cung cấp, ví dụ:

```text
http://192.168.100.1:5173
```

Nếu trang mở được nhưng API chưa sẵn sàng, console vẫn dựng giao diện và hiển
thị `Đang kết nối`, `Suy giảm` hoặc `unavailable`. Đây là trạng thái dữ liệu
quan sát được; nó không phải là xác nhận rằng traffic đang được bảo vệ.

Sau khi tải lần đầu, console tự đọc:

- health và trạng thái component;
- running/candidate configuration;
- sessions;
- security events;
- temporary blocks;
- reputation indicators;
- audit log;
- system statistics và ML status.

Dữ liệu được polling định kỳ. WebSocket `/ws/stats` và `/ws/events` giúp cập
nhật nhanh hơn khi hoạt động; polling là đường dự phòng. Nút **Làm mới** ở
thanh trên cùng yêu cầu tải lại ngay.

## 2. Các khái niệm cần hiểu trước khi thao tác

### Running và Candidate

- **Running** là cấu hình đã được engine áp dụng vào dataplane.
- **Candidate** là bản chỉnh sửa đang chờ validate và commit.
- Candidate khác running không có nghĩa traffic đã đổi.
- Chỉ sau khi **Validate** thành công và **Commit** thành công, candidate mới
  trở thành running.
- Xóa/sửa policy trong candidate không tự ngắt các session hiện có; tác động
  lên session phụ thuộc policy generation và runtime invalidation của engine.

### Version

Số `v0`, `v1`, `v2`… là phiên bản cấu hình running. Commit mới làm version tăng.
Rollback cũng tạo một version mới; số version không quay ngược về số cũ.

### Snapshot và dữ liệu tạm thời

Các con số trên Overview, Sessions và Events là snapshot của dữ liệu API vừa tải.
Một số danh sách được giới hạn để bảo vệ browser và event queue. Con số nhìn
thấy trên UI có thể thấp hơn tổng số object trong appliance nếu API trả về trang
hoặc cửa sổ dữ liệu giới hạn.

### Dấu thời gian

- Dòng nhỏ như `vừa xong`, `5 phút trước` là thời gian tương đối.
- Dòng đầy đủ hiển thị ngày/giờ theo locale của browser.
- `Unavailable`, dấu `—` hoặc ô trống nghĩa là backend không cung cấp được
  trường đó; không được hiểu là `0`, `clean` hoặc `allow`.

## 3. Quyền truy cập và đăng nhập

Mặc định console mở ở chế độ xem. GET monitoring thường vẫn đọc được, còn các
thao tác ghi sẽ yêu cầu credentials.

Bấm thẻ tài khoản ở cuối thanh bên để mở hộp thoại **Mở quyền thay đổi**. Hộp
thoại có hai tab.

### 3.1. API token

1. Chọn **API token**.
2. Nhập bearer token do quản trị hệ thống cấp.
3. Bấm **Lưu token**.

Khi chạy local, token phải khớp với giá trị cấu hình `NGFW_API_TOKEN` của API.
Token được lưu trong local storage của browser để giữ phiên. Không gửi token qua
chat, không chụp token trong ảnh màn hình và không commit token vào source.

### 3.2. Tài khoản

1. Chọn **Tài khoản**.
2. Nhập tên đăng nhập và mật khẩu.
3. Bấm **Đăng nhập**.

Tài khoản chỉ dùng được khi API đã bật account authentication. Token phiên đăng
nhập được dùng cho các request tiếp theo.

### 3.3. Vai trò

| Vai trò | Ý nghĩa và thao tác |
|---|---|
| `VIEWER` | Chỉ xem dashboard, session, event, config, audit và health. Không được ghi. |
| `OPERATOR` | Vận hành runtime như terminate/revoke session, temporary block và reputation nếu endpoint cho phép. Không được thay các nhóm cấu hình yêu cầu ADMIN. |
| `ADMIN` | Quản lý candidate, policy, interface/zone/route/NAT/profile, commit/rollback và user. |
| API token | Quyền do backend token configuration quyết định. Không chia sẻ token dùng chung nếu cần audit theo người. |

Backend luôn kiểm tra quyền lần cuối. Việc một nút xuất hiện trên UI không có
nghĩa tài khoản chắc chắn được phép dùng nút đó.

### 3.4. Đăng xuất

Trong hộp thoại access hoặc màn hình **Hệ thống**, bấm **Đăng xuất**. Console
xóa token local và khóa lại các thao tác ghi. Nếu tài khoản vừa bị disable hoặc
đổi role, có thể cần đăng nhập lại.

## 4. Bố cục chung của console

### 4.1. Thanh bên

Thanh bên có hai nhóm.

**VẬN HÀNH**

- **Tổng quan** – xem sức khỏe và các chỉ số chính.
- **Sessions** – xem connection/flow và quyết định.
- **Sự kiện & kiểm soát** – runtime/policy/security event, block, reputation
  registry và audit.

**QUẢN TRỊ**

- **Chính sách** – policy và security profile.
- **Mạng** – zone, interface, route và NAT của candidate.
- **Cấu hình** – chỉnh toàn bộ candidate JSON.
- **Hệ thống** – health chi tiết, limits, quyền và user.

Số cạnh **Sự kiện & kiểm soát** là số event `HIGH` hoặc `CRITICAL` đang có trong
dữ liệu console. Dấu chấm cạnh **Cấu hình** nghĩa là candidate khác running.

### 4.2. Thanh trên cùng

- **Tiêu đề và phụ đề**: cho biết màn hình hiện tại và mục đích của màn hình.
- **Candidate chưa commit**: có thay đổi chưa áp dụng.
- **Runtime healthy**: API và engine báo runtime M1/M2 healthy.
- **Runtime suy giảm**: session runtime không còn healthy đầy đủ.
- **Đang kết nối**: chưa nhận được health hợp lệ.
- **Làm mới**: tải lại live data và config; vòng xoay nghĩa là request đang chạy.

### 4.3. Banner lỗi kết nối

Banner **Không cập nhật được dữ liệu** liệt kê endpoint hoặc nguồn đang lỗi.
Console giữ dữ liệu đã tải trước đó để không làm mất ngữ cảnh. Bấm **Thử lại**
sau khi API/engine hồi phục.

Banner không có nghĩa mọi nguồn đều hỏng. Ví dụ health có thể hoạt động trong
khi session hoặc running config tạm thời không đọc được.

### 4.4. Thành phần dùng chung

- **Badge**: nhãn trạng thái, action, zone hoặc role.
- **Dot màu**: trạng thái interface/component hoặc mức severity.
- **Drawer**: panel trượt từ cạnh phải để xem chi tiết; bấm nền tối hoặc `×` để
  đóng.
- **Modal**: hộp thoại nhập liệu/xác nhận; nút **Hủy** không lưu thay đổi.
- **Toast**: thông báo ngắn sau thao tác. Màu xanh là thành công, đỏ là lỗi,
  màu trung tính là thông tin.
- **Spinner**: request đang chờ; không bấm lặp nút khi spinner còn chạy.
- **Empty state**: hiện tại chưa có bản ghi hoặc bộ lọc không khớp; không phải
  lỗi hệ thống.

## 5. Quy ước màu và con số

### 5.1. Risk score

Risk Engine thuộc milestone M3+ và **chưa khả dụng trong M2**. Vì vậy Sessions
hiển thị `Unavailable`, không coi field thiếu là risk `0`. Thang 0–100 dưới đây
chỉ là quy ước cho dữ liệu thật khi Risk Engine được triển khai:

| Khoảng | Nhãn/màu giao diện | Cách hiểu vận hành |
|---:|---|---|
| 0–29 | `LOW` | Chưa có dấu hiệu đáng kể theo dữ liệu hiện có. |
| 30–59 | `MEDIUM` | Có tín hiệu cần theo dõi. |
| 60–79 | `HIGH` | Cần xem xét khi Risk Engine M3+ cung cấp dữ liệu. |
| 80–100 | `CRITICAL` | Ưu tiên điều tra và kiểm tra action/policy. |

M2 không có thẻ hoặc bộ lọc risk. Không dùng số mặc định để kết luận session an
toàn hay nguy hiểm.

### 5.2. Event severity

Mỗi event có `event_class`: `runtime`, `policy` hoặc `security`. Session
open/update/close là runtime telemetry, còn invalidate/decision change là policy
event; hai loại này không phải threat detection. Chỉ security event thật mới có
ý nghĩa threat severity/confidence.

Confidence được hiển thị dưới dạng phần trăm:

```text
confidence hiển thị = confidence API × 100, làm tròn
```

Nếu field severity thiếu hoặc không hợp lệ, frontend chuẩn hóa thành `INFO` để
bản ghi không làm sập trang; đây không phải là bằng chứng event an toàn.

### 5.3. Byte và packet

- Dưới 1024 byte: `B`.
- Từ 1024 byte: `KiB`, sau đó `MiB`, `GiB`.
- `packets` là số packet, không phải số request HTTP.
- RX/TX của interface là counter mà API cung cấp; không phải throughput tức
  thời nếu UI không hiển thị cửa sổ thời gian.
- Nếu conntrack không cung cấp counter, UI hiển thị `Unavailable`; `0 B` chỉ
  được hiển thị khi backend xác nhận counter có mặt và giá trị đo được bằng 0.

## 6. Màn hình Tổng quan

Màn hình Tổng quan là nơi kiểm tra nhanh, không thay thế điều tra chi tiết.

### 6.1. Luồng M1/M2

Chuỗi trên hero panel gồm:

```text
Traffic → Conntrack → Session → L3/L4 Policy → Linux
```

Đây là phần đã có trong M1/M2:

- **Traffic**: packet/connection đi vào dataplane.
- **Conntrack/Session**: hai chiều và NAT alias được gom vào một session.
- **L3/L4 Policy**: chọn ALLOW/DROP/REJECT theo priority, zone, address và
  service.
- **Linux**: nftables/routing/NAT thực thi running configuration.

DPI, App-ID, IDS/IPS, ML, TLS inspection và Risk Engine chưa thuộc M2.

### 6.2. Vòng Runtime health

Vòng tròn hiển thị `OK`, `!` hoặc `—` theo health tổng hợp. Đây là sức khỏe
runtime, không phải phần trăm traffic được bảo vệ. `management_mode=engine` là
mô tả ownership; API chuẩn hóa component dataplane thành status health riêng và
ghi rõ kernel health chưa được đo độc lập.

Dòng **Cập nhật …** là thời điểm live data được cập nhật gần nhất.

### 6.3. Bốn thẻ chỉ số

#### Sessions hoạt động

- Giá trị chính: `active_sessions` từ stats; nếu stats chưa có thì dùng số session
  đang tải trong browser.
- Dòng phụ: số session có decision chính xác là `ALLOW` trong danh sách đang tải.
- Bấm thẻ để mở **Sessions**.

Số `ALLOW` trong dòng phụ có thể không bằng tổng active session nếu danh sách
đang tải bị giới hạn hoặc runtime chưa trả decision.

#### Decision chưa sẵn sàng

- Giá trị chính: số session có decision `Unavailable` hoặc `Invalidated`.
- `Unavailable` nghĩa backend chưa có verdict áp dụng được; `Invalidated` nghĩa
  cache cũ đã bị thu hồi và chưa có quyết định mới.

#### Runtime / policy events

- Giá trị chính: số event trong cửa sổ dữ liệu hiện tại.
- Dòng phụ: số event thật sự có class `security`.
- Bấm thẻ để mở **Sự kiện & kiểm soát → Events**.

#### Temporary blocks

- Giá trị chính: số block còn trong danh sách active.
- Dòng phụ: số event đã bị event queue bỏ (`event_queue_dropped`).
- Bấm thẻ để mở **Sự kiện & kiểm soát → Temporary blocks**.

Event queue loss lớn nghĩa là telemetry/event có thể thiếu; không suy luận rằng
không có event nguy hiểm.

### 6.4. Sự kiện gần đây

Hiển thị tối đa năm event runtime/policy mới nhất, sắp theo timestamp giảm dần.
Mỗi dòng ghi class, producer, session ID và thời gian. Lifecycle bình thường
không được gọi là cảnh báo bảo mật.

### 6.5. Panel Thành phần

Mỗi dòng là một component health do API trả về:

- tên component;
- status;
- message mô tả;
- thời gian cập nhật.

Status thường gặp:

- `ok`/`healthy`: đang hoạt động;
- `degraded`: hoạt động nhưng thiếu một phần khả năng;
- `down`: component không hoạt động;
- `unknown`/trống: chưa có dữ liệu đáng tin.

Panel đếm `ok` và `healthy` là đang hoạt động; luôn đọc message để biết phạm vi
được đo.

### 6.6. Ứng dụng trong session

Panel hiển thị rõ **App-ID chưa khả dụng trong M2**. `Unavailable (M2)` không
nghĩa traffic bị block và không được suy diễn application từ port. App-ID/DPI
thuộc M3+.

### 6.7. Policy posture

- **Default inter-zone**: `DENY` nếu candidate `default_deny=true`, ngược lại
  `ALLOW`.
- **Policies bật**: số policy trong candidate có `enabled=true`.
- **Security profiles**: số profile trong candidate.
- **Candidate**: `Đồng bộ` nếu running và candidate giống nhau; `Chờ commit` nếu
  khác nhau.

## 7. Màn hình Sessions

### 7.1. Thanh tìm kiếm và bộ lọc

Ô tìm kiếm dò chuỗi không phân biệt hoa thường trong:

- client IP;
- server IP;
- application;
- policy ID;
- session ID.

Bộ lọc **Decision** gồm:

- `ALLOW`: cho phép;
- `DROP`: bỏ packet/flow theo action;
- `REJECT`: từ chối chủ động theo action;
- `RATE_LIMIT`: áp giới hạn;
- `RESET_SESSION`: yêu cầu kết thúc/reset theo khả năng enforcement;
- `TEMP_BLOCK`: chặn source tạm thời.

Bộ đếm `X/Y sessions` là `số dòng khớp / số dòng đã tải`, không nhất thiết là
tổng session trong toàn appliance.

### 7.2. Các cột session

| Cột | Ý nghĩa |
|---|---|
| Client | client/source IP và source port. |
| Server | server/destination IP và destination port. |
| App / Protocol | M2 hiển thị `Unavailable (M2)` cho application; protocol và TCP state vẫn lấy từ conntrack. |
| Zones | source zone → destination zone. |
| Risk | `Unavailable` trong M2 vì Risk Engine chưa được triển khai. |
| Decision | action đã evaluate, `INVALIDATED`, hoặc `UNAVAILABLE`; UI không đổi giá trị thiếu thành ALLOW. |
| Path | `Fast` chỉ khi backend xác minh provenance kernel mark; nếu chưa xác minh thì `Unavailable`, không mặc định thành `Inspect`. |
| `×` | yêu cầu kết thúc/revoke session, cần quyền ghi. |

### 7.3. Session detail drawer

Bấm một dòng để mở drawer. Drawer gồm các nhóm:

#### Risk summary

- vòng risk: `—` trong M2;
- badge decision;
- trạng thái Risk Engine chưa khả dụng;
- policy reason hoặc policy ID đã match.

#### Kết nối

- Client và Server gồm IP:port;
- Zone source → destination;
- Protocol và TCP state;
- **Bắt đầu**: created/start time;
- **Lần cuối**: thời điểm last seen dạng tương đối.

#### Lưu lượng

- **Original**: bytes và packets theo original direction;
- **Reply**: bytes và packets theo reply direction.

Đây là counters của flow, không phải tốc độ. Nếu conntrack event chưa có
counters, UI ghi `Unavailable`. Runtime thực hiện bounded resync định kỳ để lấy
counter từ kernel dump; giá trị `0` chỉ có nghĩa measured zero khi field có mặt.

#### Security context

- **Policy**: matched policy ID;
- **Scope**: `SESSION` trong M2;
- **ML**: predicted class và confidence nếu ML available;
- **TLS**: TLS version/metadata nếu quan sát được;
- **Signals**: số security signal gắn với context.

Nếu context chưa có, UI dùng `Unavailable` hoặc giá trị mặc định an toàn. M2 API
có thể trả original, reply và translated tuple; drawer hiện ưu tiên client/server
được map từ original tuple. Muốn kiểm tra đầy đủ NAT alias/reply tuple, xem
response session qua API.

Risk contributions chỉ xuất hiện khi backend tương lai cung cấp dữ liệu thật;
M2 không tạo contribution giả.

### 7.4. Kết thúc session

1. Bấm `×` ở dòng hoặc **Kết thúc session** trong drawer.
2. Xác nhận hộp thoại.
3. Chờ toast thành công.

Thao tác gửi revoke/drop guard tới engine. Nó không phải chỉnh candidate và
không nên được dùng thay cho thay đổi policy lâu dài. Nếu API/engine lỗi, session
không được coi là đã terminate.

## 8. Màn hình Sự kiện & kiểm soát

Badge trên bốn tab là số bản ghi console đang có trong từng nhóm.

### 8.1. Tab Events

#### Bộ lọc

- ô tìm kiếm: class, session, producer/detector, IP, category hoặc signature ID;
- class: `runtime`, `policy`, `security`;
- severity: `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`;
- số ở cuối toolbar: số event khớp filter.

#### Bảng Events

| Cột | Ý nghĩa |
|---|---|
| Thời gian | thời gian tương đối và đầy đủ. |
| Loại | `runtime`, `policy` hoặc `security`. |
| Sự kiện | kind/category, producer và signature nếu có. |
| Session | session ID liên quan. |
| Severity | có ý nghĩa threat severity đối với class `security`; lifecycle thường là `INFO`. |
| Chi tiết | reason/evidence nếu backend cung cấp. |

Bấm event để mở drawer.

#### Event drawer

- **Nguồn sự kiện**: class, producer, signature và recommended action nếu có;
- **Liên kết**: source, destination và session ID;
- **Evidence**: bằng chứng dạng text nếu backend cung cấp;
- **Metadata**: object JSON nếu backend cung cấp;
- **Chặn source trong 1 giờ** chỉ xuất hiện cho class `security` có source IP.

`Uncorrelated` hoặc session trống nghĩa event chưa ghép được với session. Không
được gán event cho session khác chỉ vì hai IP trùng nhau.

### 8.2. Tab Temporary blocks

#### Form tạo block

- **IP hoặc indicator**: IP/domain/indicator source cần chặn;
- **Lý do**: bắt buộc, sẽ xuất hiện trong danh sách và audit;
- **Thời hạn**: 5 phút, 15 phút, 1 giờ hoặc 24 giờ;
- **Áp dụng block**: gửi request enforcement.

#### Danh sách đang chặn

Mỗi dòng hiển thị indicator, lý do, thời điểm tạo và thời điểm hết hạn. Nút
**Gỡ** xóa block trước hạn. Block có thời hạn là enforcement action, khác với
reputation indicator và khác với policy candidate.

### 8.3. Tab Reputation

#### Form indicator

- **Indicator**: giá trị IP, domain, URL hoặc hash;
- **Loại**: `IP`, `DOMAIN`, `URL`, `HASH`;
- **Risk score**: số 0–100; càng cao càng đáng ngờ theo nguồn này;
- **Category**: nhóm mô tả, ví dụ `malicious`;
- **Lưu indicator**: ghi vào local reputation store.

Danh sách hiển thị score, indicator, type, category, source và trạng thái
`enabled/disabled`. Nút **Xóa** xóa indicator.

Trong M2 đây chỉ là registry quản trị. Nó chưa nối vào Risk Engine hoặc
enforcement, không phải temporary block và không chặn traffic.

### 8.4. Tab Audit log

Các cột:

- **Thời gian**: lúc thao tác xảy ra;
- **Actor**: người hoặc token thực hiện;
- **Role**: vai trò tại thời điểm ghi;
- **Action**: loại thao tác;
- **Resource/ID**: object bị tác động;
- **Result**: thường là `SUCCESS` hoặc lỗi;
- **Thông tin**: mô tả ngắn.

Audit log không lưu credentials hoặc payload nhạy cảm. Badge `N gần nhất` là số
entry đang tải, không phải tuổi thọ lưu trữ của toàn hệ thống.

## 9. Màn hình Chính sách

Màn hình này chỉnh policy trong candidate. Lưu policy chưa apply dataplane.

### 9.1. Thanh trạng thái cấu hình

- `Running vN`: running version đang được engine áp dụng;
- `Candidate synced với Running`: Candidate giống Running;
- `Candidate changed — chưa Commit`: Candidate có diff nhưng dataplane chưa đổi;
- `Validation: hợp lệ`: Candidate hiện vượt qua kiểm tra backend;
- `Validation: cần kiểm tra`: Candidate hiện chưa hợp lệ;
- ô ghi chú: comment sẽ lưu cùng commit;
- **Validate**: chỉ kiểm tra Candidate, không apply dataplane;
- **Rollback**: khôi phục previous known-good theo backend, có xác nhận và có
  thể làm thay đổi Running/dataplane;
- **Commit**: kích hoạt Candidate thành Running và apply dataplane; bị disable
  nếu Candidate không có diff hoặc chưa hợp lệ.

Thanh này dùng chung cùng trạng thái/backend workflow ở cả trang **Chính sách**
và **Cấu hình JSON nâng cao**. Đây không phải hai hệ thống commit độc lập.

### 9.2. Bảng policy

Nút **Mở JSON nâng cao** chuyển sang trình soạn thảo toàn bộ Candidate. Nút này
không lưu, validate hay commit. Khi mở từ đây, trang JSON có nút
**← Quay lại Chính sách** và breadcrumb `Chính sách > Cấu hình JSON`.

| Cột | Ý nghĩa |
|---|---|
| Thứ tự | priority; số nhỏ được đánh giá trước. |
| Policy | tên hiển thị và ID duy nhất. |
| Source → Destination | zone nguồn và zone đích; `any` khi không chọn. |
| Service L3/L4 | service bắt buộc có protocol, ví dụ `tcp:80`, `udp:53`. |
| Tương thích M2 | `Compatible` hoặc cảnh báo Validate sẽ từ chối field M3+. |
| Action | quyết định khi rule match. |
| Scope | phạm vi áp dụng của decision. |
| Trạng thái | công tắc enabled/disabled. |
| Nút thao tác | sửa hoặc xóa khỏi candidate. |

Nếu hai policy trùng priority, backend phải từ chối validate. Policy disabled vẫn
có thể nằm trong candidate nhưng không được đánh giá.

### 9.3. Thêm/sửa policy

Các trường trong modal:

- **ID**: bắt buộc khi tạo; chỉ gồm ký tự identifier và không đổi sau khi tạo;
- **Tên hiển thị**: tên dùng trên bảng/audit;
- **Priority**: số nguyên từ 0; số thấp hơn chạy trước;
- **Source zones**: chọn một hoặc nhiều zone; bỏ chọn nghĩa là any;
- **Destination zones**: tương tự source zones;
- **Services**: danh sách cách nhau bởi dấu phẩy, ví dụ `tcp:80, tcp:443`;
  chỉ nhập `80` là sai cú pháp;
- **Applications**: M3+, phải để trống để policy tương thích M2;
- **Action**: action khi tất cả matcher của rule phù hợp;
- **Scope**: M2 chỉ hỗ trợ `SESSION`;
- **Security profile**: M3+, phải để trống trong policy M2;
- **Minimum risk/Maximum risk**: M3+, phải để trống trong policy M2;
- **Policy được bật**: enable/disable;
- **Log khi bắt đầu/kết thúc**: tạo log tại các mốc session.

Các phần tử trong cùng một danh sách zone/service/application mang semantics OR.
Ví dụ `tcp:80, tcp:443` cho phép rule match một trong hai service; không phải
bắt buộc một packet vừa có port 80 vừa port 443. Các nhóm matcher khác nhau
(source zone, destination zone, service…) vẫn kết hợp theo AND.

### 9.4. Ý nghĩa action và scope

| Action | Ý nghĩa giao diện |
|---|---|
| `ALLOW` | cho phép theo scope của rule. |
| `DROP` | bỏ traffic im lặng theo enforcement. |
| `REJECT` | từ chối có phản hồi phù hợp action. |
| `RATE_LIMIT` | chưa hỗ trợ trong policy M2; dùng sẽ bị validation từ chối. |
| `RESET_SESSION` | chưa hỗ trợ trong policy M2; revoke session là API runtime riêng. |
| `TEMP_BLOCK` | chưa hỗ trợ như policy action M2; temporary block là API runtime riêng. |

| Scope | Đối tượng bị tác động |
|---|---|
| `SESSION` | toàn connection/session. |

`PACKET`, `REQUEST` và `SOURCE_INDICATOR` thuộc phạm vi sau M2. Endpoint
**Validate** chạy cả validation cấu trúc lẫn `CompileM2`, nên phải báo lỗi trước
Commit nếu candidate dùng các scope hoặc matcher chưa hỗ trợ.

### 9.5. Security profile cards

Trang chỉ hiển thị số định nghĩa profile được lưu và badge
`Unavailable in M2`. Các profile dành cho milestone sau; gắn profile vào policy
M2 sẽ làm Validate thất bại.

### 9.6. Quy trình commit policy

```text
Thêm/sửa policy
→ Lưu vào candidate
→ kiểm tra priority và matcher
→ Validate
→ xem Candidate changed/Thay đổi
→ ghi comment
→ Commit
→ kiểm tra version và status
```

Nếu commit thất bại, giữ lại candidate để sửa hoặc dùng Rollback. Không coi toast
lỗi là đã apply một phần.

## 10. Màn hình Mạng

Màn hình Mạng chủ yếu để đọc candidate và kiểm tra trước commit. Chỉnh chi tiết
interface/route/NAT bằng **Cấu hình JSON**.

### 10.1. Zone cards

Mỗi card hiển thị:

- `id` viết hoa;
- tên zone;
- mô tả;
- số interface/NIC có `zone_id` đó.

Số NIC là số mapping trong candidate, không phải số cổng vật lý đang link up.

### 10.2. Interface cards

- chấm link/admin: trạng thái `admin_state` theo candidate;
- tên logical interface;
- `system_name`: tên device Linux;
- mode: L3, VLAN parent, VLAN subinterface hoặc management;
- zone badge;
- các IPv4 address đã khai báo;
- MTU, RX và TX.

`RX/TX` là counter nếu API cung cấp. Interface không có IPv4 hiển thị `Chưa
gán IPv4`; điều đó không tự nghĩa interface down.

Badge:

- **Synced**: phần interface candidate giống running;
- **Candidate changed**: có thay đổi chưa commit.

### 10.3. Static routes

| Cột | Ý nghĩa |
|---|---|
| Destination | CIDR đích, ví dụ `0.0.0.0/0`. |
| Gateway | next-hop; `direct` nếu route trực tiếp. |
| Interface | interface dùng để đi route. |
| Metric | độ ưu tiên route theo Linux. |
| Chấm trạng thái | enabled/disabled trong candidate. |

### 10.4. NAT rules

| Cột | Ý nghĩa |
|---|---|
| Rule | tên và loại `SNAT`, `MASQUERADE` hoặc `DNAT`. |
| Zones | source zone → destination zone; `any` nếu không giới hạn. |
| Translation | địa chỉ/port sau translate hoặc tên loại NAT. |
| Priority | số nhỏ được xét trước. |
| Chấm trạng thái | rule enabled/disabled. |

Các matcher source/destination network, protocol, port và interface có thể xem
đầy đủ trong Candidate JSON. Màn hình bảng chỉ hiển thị các cột tóm tắt.

## 11. Màn hình Cấu hình JSON nâng cao

Đây là **Advanced Configuration Editor** cho toàn bộ model Candidate. Nó thao
tác trên cùng Candidate backend với màn hình Chính sách.

### 11.1. Điều hướng và trạng thái dùng chung

Nếu mở từ trang Chính sách:

- **← Quay lại Chính sách** trở về màn hình Chính sách trước đó;
- breadcrumb cho biết `Chính sách > Cấu hình JSON`;
- nút Back của trình duyệt cũng trở về trang trước vì mỗi trang có URL hash và
  history entry riêng.

Thanh `Running vN / Candidate / Validation` có cùng ý nghĩa và cùng dữ liệu với
trang Chính sách. Luồng duy nhất là:

```text
Nội dung editor
→ Lưu vào Candidate
→ Validate Candidate
→ Commit Candidate thành Running
→ engine apply dataplane
```

### 11.2. Candidate JSON editor

- **Editor đồng bộ Candidate**: text trong editor đang khớp Candidate gần nhất
  mà trang đã tải;
- **Editor chưa lưu**: text đã khác Candidate backend; thay đổi này mới chỉ nằm
  trong trình duyệt;
- **Nạp Running vào trình soạn thảo**: chỉ lấy Running hiện tại và thay text
  trong editor. Thao tác này không gọi Commit, không apply dataplane, không tăng
  Running version, không tạo config version và không tạo audit event `COMMIT`;
- **Format**: chuẩn hóa indent JSON; nếu JSON sai sẽ báo lỗi;
- **Lưu vào Candidate**: parse JSON và gửi lên endpoint Candidate. Thao tác này
  chưa Commit và chưa apply dataplane;
- vùng text editor: nội dung đang chỉnh, chưa chắc đã được lưu ở backend.

Nếu editor đang có nội dung chưa lưu hoặc Candidate khác Running, nút
**Nạp Running vào trình soạn thảo** phải hiện xác nhận trước khi thay text. Chọn
**Hủy** để giữ nguyên nội dung. Chọn **Tiếp tục** chỉ đổi editor; Candidate
backend vẫn giữ nguyên cho đến khi bấm **Lưu vào Candidate**.

Phân biệt từng action:

| Action | Nguồn → đích | Có đổi dataplane/version? |
|---|---|---|
| Nạp Running vào trình soạn thảo | Running → editor | Không |
| Lưu vào Candidate | editor → Candidate backend | Không |
| Validate | kiểm tra Candidate | Không |
| Commit | Candidate → Running/engine | Có, khi thành công |
| Rollback | previous known-good → Running/engine | Có, theo backend semantics |

Khi lỗi parse, sửa dấu ngoặc, dấu phẩy, kiểu dữ liệu hoặc chuỗi trước khi bấm
**Lưu vào Candidate**. Khi lỗi validation, đọc toast/backend detail để sửa ID, CIDR, zone,
interface, priority, port, action hoặc resource limit.

### 11.3. Các nhóm cấu hình JSON

| Nhóm | Nội dung cần hiểu |
|---|---|
| `interfaces` | device, zone, mode, address, VLAN parent/ID, MTU và admin state. |
| `zones` | miền trust/logical dùng chung bởi interface, NAT và policy. |
| `routes` | destination, gateway, interface, metric, enabled. |
| `nat_rules` | loại NAT, zone/network/protocol/port, translated address/port, priority. |
| `policies` | matcher, priority, action, scope, profile, logging, enabled. |
| `security_profiles` | cờ detector, TLS mode, ngưỡng và failure action. |
| resource limits | giới hạn session, queue, body/header/URL và timeout. |
| `default_deny` | action mặc định giữa zone khi không policy nào match. |

### 11.4. Panel Thay đổi

Panel so sánh running với candidate theo nhóm. `Interfaces changed` không chỉ
ra interface nào; nó báo nhóm interfaces có khác. Muốn biết chính xác object
nào, xem JSON candidate hoặc diff API.

`Không có thay đổi` nghĩa hai config giống nhau theo dữ liệu console đang nhận.

### 11.5. Resource limits

- **Active sessions**: số session đồng thời tối đa;
- **Event queue**: số security event tối đa trong queue;
- **HTTP body**: số byte body tối đa được inspection;
- **HTTP headers**: kích thước header tối đa mỗi request;
- **ML timeout**: thời gian chờ ML, tính bằng ms;
- **Inspection deadline**: deadline inspection request, tính bằng ms.

Các giá trị này là candidate limits. Thay đổi chỉ có hiệu lực sau commit và phụ
thuộc thành phần backend có hỗ trợ giới hạn đó.

### 11.6. Last known good

- **Version**: running version cuối được backend xác nhận;
- **comment**: ghi chú commit;
- **author**: hiển thị ở thanh trạng thái nếu có;
- **timestamp**: thời điểm commit;
- **checksum**: một phần checksum để nhận dạng cấu hình.

Checksum bị rút gọn trên UI để dễ đọc; dùng API/evidence nếu cần đối chiếu đầy
đủ.

## 12. Màn hình Hệ thống

### 12.1. Component health cards

Mỗi card có:

- icon theo status;
- tên key component và tên hiển thị;
- message;
- thời gian cập nhật tương đối;
- badge status.

Status `down` màu nghiêm trọng; `degraded` cảnh báo; `ok/healthy` bình thường.
Nếu thời gian cập nhật cũ, component có thể đang stale dù badge chưa đổi.

### 12.2. Runtime protection

- **Management API**: `ONLINE` nếu health API trả được; `OFFLINE` nếu không có
  health object.
- **ML inference**: `CONFIGURED` nếu ML endpoint được cấu hình;
  `EXTERNAL / OFF` nếu chưa bật trong console.
- **Event queue loss**: số event bị bỏ do queue đầy hoặc drop.
- **Default inter-zone**: DENY/ALLOW theo candidate.
- **Config version**: version running đang hiển thị.

`ONLINE` của Management API không đồng nghĩa conntrack, nftables hoặc mọi
inspection detector đều online; xem từng component và engine health.

### 12.3. Quyền truy cập

Hiển thị:

- **Danh tính**: username, `API token` hoặc `Anonymous`;
- **Vai trò**: role account, `Token access` hoặc `Read only`;
- **Thao tác ghi**: đã mở/đã khóa.

Nút **Đổi thông tin xác thực** mở lại access modal. Nút **Đăng xuất** xóa token
local và khóa thao tác ghi.

### 12.4. Giới hạn vận hành

Panel này lặp lại các giá trị candidate để người vận hành đọc nhanh:

- Sessions: số lượng đồng thời;
- Event queue: số security signal;
- HTTP body/header: byte hoặc KiB/MiB;
- URL: độ dài tối đa;
- Deadline: ms.

### 12.5. Tài khoản quản trị

Khu vực này cần token/account đủ quyền và backend account store khả dụng.

**Thêm tài khoản**:

1. Nhập username.
2. Nhập mật khẩu; nên dùng ít nhất 12 ký tự.
3. Chọn `VIEWER`, `OPERATOR` hoặc `ADMIN`.
4. Bấm **Tạo tài khoản**.

Trong bảng:

- dropdown role cập nhật role;
- công tắc cập nhật enabled/disabled;
- thùng rác xóa tài khoản khác;
- badge `Đang đăng nhập` đánh dấu tài khoản hiện tại.

Không thể xóa tài khoản đang đăng nhập. Sau khi đổi role/disable tài khoản hiện
tại, hãy đăng nhập lại để kiểm tra token/session.

## 13. Quy trình sử dụng thường gặp

### 13.1. Kiểm tra runtime M1/M2

1. Mở **Tổng quan**.
2. Kiểm tra nhãn **Runtime healthy**.
3. Kiểm tra vòng **Runtime health** và đọc message từng thành phần.
4. Kiểm tra `Management API ONLINE` ở **Hệ thống**.
5. Nếu có `Suy giảm`, đọc message component thay vì chỉ nhìn phần trăm.

### 13.2. Điều tra session và decision

1. Mở **Sessions** hoặc bấm thẻ **Decision chưa sẵn sàng**.
2. Tìm IP, protocol, policy hoặc session ID.
3. Mở Session detail.
4. Kiểm tra zone, tuple, decision reason và trạng thái counters.
5. Mở Events để xem lifecycle/invalidation liên quan.
6. Nếu cần chặn ngay, tạo Temporary block và ghi lý do.

### 13.3. Chặn một source trong thời gian ngắn

1. Vào **Sự kiện & kiểm soát → Temporary blocks**.
2. Nhập indicator và lý do.
3. Chọn 5 phút/15 phút/1 giờ/24 giờ.
4. Bấm **Áp dụng block**.
5. Xác nhận indicator và thời hạn xuất hiện.
6. Gỡ block khi không còn cần hoặc chờ tự hết hạn.

### 13.4. Thay đổi policy an toàn

1. Vào **Chính sách**.
2. Thêm/sửa policy hoặc dùng **Cấu hình** nếu cần sửa network/NAT/address.
3. Kiểm tra priority, zone, service, action và scope.
4. Bấm **Lưu vào candidate**.
5. Bấm **Validate**.
6. Kiểm tra badge `Candidate changed`, panel Thay đổi và default deny.
7. Nhập ghi chú và bấm **Commit**.
8. Đợi toast thành công, refresh và kiểm tra version/running.

### 13.5. Khôi phục cấu hình trước

1. Xác nhận đang ở đúng appliance và version.
2. Vào **Chính sách** hoặc **Cấu hình**.
3. Bấm **Rollback**.
4. Đọc hộp thoại xác nhận.
5. Sau khi thành công, kiểm tra version mới, policy posture và Mạng.
6. Kiểm tra Audit log để lưu actor, thời gian và result.

### 13.6. Kiểm tra thay đổi của người khác

1. Vào **Sự kiện & kiểm soát → Audit log**.
2. Tìm action `COMMIT`, `ROLLBACK`, `UPDATE`, `REVOKE`, `CREATE` hoặc `DELETE`.
3. Đối chiếu actor/role, resource ID, message và thời gian.

## 14. Trạng thái và lỗi thường gặp

### `Đang kết nối` kéo dài

API health chưa trả dữ liệu. Kiểm tra URL frontend/API proxy và nhờ quản trị hệ
thống kiểm tra service. Nút refresh chỉ thử lại request, không sửa network.

### `Suy giảm`

Ít nhất một component health không healthy hoặc một nguồn live data lỗi. Mở
Hệ thống để đọc message. Runtime health không chứng minh DPI/IDS/ML đang chạy;
các thành phần đó chưa thuộc M2.

### `Candidate chưa commit`

Bạn đã lưu candidate nhưng chưa apply. Traffic vẫn theo running cho tới commit
thành công.

### `Validation: hợp lệ` nhưng Commit không thành công

Validation kiểm tra cấu trúc và khả năng tương thích runtime M2 tại thời điểm đó.
Commit vẫn còn phụ thuộc version conflict, engine IPC, interface/route/nft apply
và khả năng rollback. Đọc toast, refresh config và xem Audit log.

### `Cần đăng nhập hoặc API token`

Thao tác cần quyền ghi. Mở access modal và nhập token/account.

### `401 Unauthorized`

Token sai/hết hạn hoặc username/password sai.

### `403 Forbidden`

Đã xác thực nhưng role không đủ cho endpoint.

### `ENGINE_UNAVAILABLE`

API không gọi được engine owner. Không coi commit, rollback, terminate hoặc block
là đã thực hiện. Đợi engine hồi phục rồi refresh.

### Bảng rỗng

- Có thể thật sự chưa có traffic/event.
- Có thể filter đang loại hết bản ghi.
- Có thể API trả empty do runtime chưa resync.
- Có thể dữ liệu cũ đang được giữ trong khi endpoint mới lỗi.

Xóa filter, bấm refresh và xem banner lỗi.

### WebSocket lỗi

UI có polling fallback. Nếu số liệu vẫn đứng yên, bấm refresh và kiểm tra banner.
WebSocket lỗi không tự động đồng nghĩa policy hoặc session bị mất.

## 15. Giới hạn và cách đọc đúng dữ liệu

- UI chỉ hiển thị endpoint và field đã được backend cung cấp.
- `Unavailable` nghĩa không quan sát được; không được đổi thành `ALLOW`, `CLEAN`
  hoặc `0` khi phân tích sự cố.
- Risk score chưa khả dụng trong M2; severity chỉ là threat severity cho
  `event_class=security`.
- Runtime health không phải tỷ lệ packet được kiểm tra.
- Sessions hoạt động và `ALLOW` trên Overview có thể lấy từ các nguồn/cửa sổ dữ
  liệu khác nhau; không cộng/trừ chúng như cùng một mẫu thống kê.
- Filter trong Sessions/Events áp dụng trên dữ liệu đã tải vào browser.
- DPI/App-ID/IDS/IPS/ML/TLS inspection/Risk Engine chưa được triển khai trong
  M2; `Unavailable` là trạng thái đúng.
- Network page hiển thị candidate; chỉ running sau commit mới là cấu hình đang
  áp dụng.
- Temporary block là enforcement tạm thời; reputation là tín hiệu, không phải
  hard block.
- UI không tự cấp Linux capability, không tự sửa nftables khi engine offline và
  không thể biến một commit lỗi thành thành công.

## 16. Khi cần báo lỗi

Gửi cho quản trị hệ thống:

- URL và màn hình đang mở;
- thời gian xảy ra lỗi;
- toast/banner nguyên văn;
- version cấu hình đang hiển thị;
- filter đang chọn;
- session/event ID liên quan;
- ảnh chụp đã che token, mật khẩu, IP nhạy cảm và payload.

Không gửi bearer token, mật khẩu, cookie browser hoặc nội dung request nhạy cảm.
