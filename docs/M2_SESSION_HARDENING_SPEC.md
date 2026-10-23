# Đặc tả củng cố session M2 và hướng tối ưu sau đo đạc

**Trạng thái:** Đặc tả kỹ thuật lập trước khi sửa code; nghiệm thu thực tế cần bằng chứng test riêng.
**Ngày:** 2026-10-16.
**Phạm vi:** Linux Conntrack adapter, session RuntimeStore, resync, cleanup và truy vấn session. Phần thống kê từ bài báo được tách thành một nhánh quan sát tùy chọn.

Tài liệu này cụ thể hóa các sửa đổi được ưu tiên sau khi đối chiếu [kế hoạch M2](M2_IMPLEMENTATION_PLAN.md), [ADR runtime/cache](adr/0002-m2-runtime-and-cache.md), [M2 acceptance matrix](m2-acceptance-matrix.md), [quy trình test trên VM](../tests/integration/m2/README.md), mã hiện tại và file đề xuất AI `C:\Users\HuyTran\Downloads\SENTINEL_NGFW_Paper_Analysis_Integration_Plan.txt`. Những con số hiệu năng trong bài báo không phải chỉ tiêu nghiệm thu của NGFW này: dataplane của dự án là Linux Conntrack/nftables, còn RuntimeStore là bản quan sát và tương quan ở Go.

## 1. Ranh giới và bất biến

| Mã | Bất biến phải giữ |
|---|---|
| I-01 | Conntrack kernel là nguồn sự thật về sự tồn tại của flow. `ExpiresAt` trong Go chỉ là thời điểm cần kiểm tra; không tự chứng minh flow đã biến mất. |
| I-02 | Không phát `CLOSED` với lý do kernel hết hạn, không phát sự kiện tương đương `DESTROY` và không gỡ guard của session chỉ vì timeout dự đoán hoặc một lần đọc kernel lỗi. `DESTROY` đúng incarnation và full dump đủ điều kiện là hai nguồn chứng cứ độc lập. |
| I-03 | Phân biệt incarnation bằng boot ID, network namespace, zone, family, original tuple và ID/kernel start khi có. Không dùng tuple khớp đơn lẻ để xác nhận cùng phiên; khi thiếu trường quyết định thì trạng thái là thiếu xác minh. |
| I-04 | Dump thiếu/truncated, event loss hoặc Get lỗi không được dùng làm bằng chứng âm để đóng hàng loạt session. Cập nhật dương từ record hợp lệ vẫn được phép, có gắn chất lượng và tình trạng degraded. |
| I-05 | Forwarding M1/M2 hiện tại không phụ thuộc thời gian phản hồi của dump, Get, thống kê hay UI. Không đổi thứ tự policy, NAT, ct-mark upper/lower bits, M3/M4 guard và phạm vi IPv4/IPv6 hiện có. |
| I-06 | Giữ giới hạn RAM/queue/worker; không thêm map per-IP, lịch sử event hay heap tăng vô hạn. Giữ API phân trang/lọc và IPC hiện hành; thay đổi phá hợp đồng phải có versioning riêng. |

**Ngoài phạm vi bản sửa này:** thay Linux Conntrack bằng Session_ID/Session_ST của bài báo; chèn splay tree vào packet path; tự động drop ACK/SYN theo EWMA; tự đổi thứ tự luật firewall; sửa timeout kernel đồng loạt; sửa M1 NAT/routing.

## 2. Hiện trạng kiểm chứng từ code

| ID | Hiện trạng | Hệ quả cần khắc phục | Vị trí |
|---|---|---|---|
| C-01 | `LinuxSource.Dump` gọi `s.dump.Dump(nil)` trước khi áp dụng `MaxRecords/MaxBytes/Deadline`. `Bytes` hiện là ước lượng record đã decode. | Dump lớn vẫn gom toàn bộ bảng trong RAM; deadline không bao trùm thời gian gọi thư viện. | [source_linux.go](../internal/conntrack/source_linux.go), [source.go](../internal/conntrack/source.go) |
| C-02 | `LinuxSource.Get` dùng dump tối đa 200.000 record để tìm một identity. | Xác minh timeout/guard tốn O(số flow), có thể trả lỗi vì dump không đầy đủ. | [source_linux.go](../internal/conntrack/source_linux.go) |
| C-03 | Presence của ID/mark/zone/counters/timeout suy từ giá trị khác 0; merge ghi `KernelMark` kể cả khi `Presence.Mark=false`. | Trộn lẫn “không có attribute” với “có attribute = 0”; UPDATE thiếu mark có thể xóa mark đã biết. | [source_linux.go](../internal/conntrack/source_linux.go), [runtime_store.go](../internal/session/runtime_store.go) |
| C-04 | Merge luôn đẩy `LastSeen` và `Revision`, kể cả dump lặp lại không chứng minh hoạt động mới; resync vẫn chạy evaluation/inspection. | Dashboard thể hiện sai thời điểm hoạt động, tăng work/event/CAS churn theo chu kỳ 30 giây. | [runtime_store.go](../internal/session/runtime_store.go), [runtime.go](../internal/engine/runtime.go) |
| C-05 | `CleanupExpired` đóng và xóa khi tới `ExpiresAt`, sau đó engine gỡ guard; lịch quét mặc định 512 session mỗi 30 giây. | Có thể đóng nhầm flow được kernel gia hạn mà event mất; backlog lớn dù có thêm heap. | [runtime_store.go](../internal/session/runtime_store.go), [main.go](../cmd/ngfw-engine/main.go) |
| C-06 | `Query` clone mọi active session, rồi lọc/sort mới lấy tối đa 500 mục; guard-key lookup quét active; correlation quét ring closed. | Allocation và thời gian giữ lock/CPU tăng theo toàn bảng ở các đường gọi thường dùng. | [runtime_store.go](../internal/session/runtime_store.go), [inspection.go](../internal/session/inspection.go) |

Đây là review tĩnh tại thời điểm lập đặc tả, **trước các bản sửa tiếp theo**; không phải kết quả benchmark hay xác nhận lỗi đã tái hiện trên VM.

## 3. Bảng đặc tả thay đổi

| ID / ưu tiên | Hợp đồng cần thực hiện | File dự kiến | Tiêu chí chấp nhận |
|---|---|---|---|
| S-00 / P0 | Đóng băng baseline: phiên bản code/kernel, cấu hình, số flow, mix TCP/UDP/ICMP, NAT, IPv4/IPv6, M3/M4 mode; đo tách packet-path và Go paths. | Benchmark/test mới; `tests/integration/m2/README.md` (phụ lục) | Có số đo p50/p95/p99, CPU/RSS/allocation, throughput, event loss, dump duration/bytes, query và cleanup backlog; không gọi thay đổi Go là cải thiện packet throughput nếu chưa đo. |
| S-01 / P0 | Thay dump gom-slice bằng transport Linux đọc multipart từng datagram/record, giới hạn **wire bytes**, record count và thời gian ngay trong receive/decode; giữ socket event và dump riêng. | `internal/conntrack/source_linux.go`, adapter/decoder Linux mới, `source.go` | Peak memory có trần theo limit + receive buffer + queue, không theo toàn bộ kernel table; cancel/timeout có tác dụng khi đang nhận; chỉ `Complete=true` sau DONE hợp lệ. |
| S-02 / P0 | `Get(identity)` thành truy vấn conntrack targeted theo tuple + zone/family trong namespace đúng; kiểm tra lại identity trả về, không dùng full dump. | `internal/conntrack/source_linux.go`, test Linux | Trả phân biệt chính xác: exact present, confirmed absent, identity mismatch/ambiguous, unavailable. Không xác nhận phiên chỉ vì tuple trùng. |
| S-03 / P0 | Decode presence từ netlink attributes; merge chỉ thay field có presence. Giá trị 0 hợp lệ phải khác attribute thiếu. | `internal/conntrack/*`, `internal/session/runtime_store.go` | UPDATE thiếu mark/timeout/counters/zone không xóa giá trị đã biết; attribute mark=0 cập nhật thành 0 đúng khi thực sự có. |
| S-04 / P0 | Resync idempotent và giữ cutover: tách quan sát hiện diện khỏi hoạt động packet; chỉ đánh giá lại policy/inspection khi session/policy/inspection input thay đổi thực sự. | `internal/engine/runtime.go`, `internal/session/runtime_store.go` | Dump lặp cùng nội dung không tự đẩy `LastSeen`, không phát update/decision event và không gây inspection work; không close khi dump/loss không đủ điều kiện. |
| S-05 / P0 | Cleanup hai pha: chọn expiry candidate → xác minh ngoài store lock → kiểm tra lại incarnation/mutation token → refresh, close hoặc đánh dấu STALE. `DESTROY` đúng identity vẫn xử lý ngay. | `internal/session/runtime_store.go`, `internal/engine/runtime.go`, `cmd/ngfw-engine/main.go` | Kernel còn flow thì gia hạn; kernel xác nhận vắng mới close/gỡ guard; Get lỗi thì giữ hoặc evict *tracking-only* theo chính sách RAM riêng, không giả sự kiện kernel; event xen giữa không bị close nhầm. |
| S-06 / P0 | Bổ sung health/backlog counters cho dump/get/expiry, lý do degraded và event loss; mọi thống kê là bounded và không chặn dataplane. | `internal/engine/runtime.go`, `internal/domain/runtime_ipc.go`, runtime service/API | Operator thấy được incomplete dump, verify unavailable, số candidate chờ, thời gian chờ, count/duration/byte; trường mới additive hoặc có IPC versioning nếu phá hợp đồng. |
| S-07 / P1, sau S-00–S-05 | Giảm clone ở query: lọc/count trên field tối thiểu, sort chọn trang ổn định, chỉ clone kết quả; thêm index phụ **chỉ nếu benchmark chứng minh**. | `internal/session/runtime_store.go`, benchmark/test mới | `Total` chính xác, thứ tự CreatedAt+SessionID ổn định, filters original/translated/any và max page 500 giữ nguyên; allocation giảm ở workload đích, không làm apply chậm quá ngân sách đã chốt. |
| S-08 / P1, sau S-00–S-05 | Index cho active nft guard-key và closed NAT aliases nếu lookup/correlation là bottleneck. Duy trì cùng lock với byID/tombstone. | `internal/session/runtime_store.go`, `internal/session/inspection.go` | Không mất ambiguity/temporal filter, không xóa guard của incarnation mới, không giữ reference sau TTL/close; giới hạn bộ nhớ theo MaxSessions/MaxClosed/MaxAliases. |
| S-09 / P1, **chỉ khi đo cleanup scan đắt** | Index deadline theo SessionID (indexed min-heap hoặc timing wheel bounded); cập nhật trên NEW/timeout/close, không append lazy vô hạn. Cải thiện cả drain scheduler/rate, vì heap không giải quyết mức 512/30s. | `internal/session/expiry_index.go` (mới nếu chọn heap), `runtime_store.go`, `main.go` | Không mất candidate khi gia hạn, không duplicate/unbounded heap; backlog về ngưỡng đã chốt dưới tải mục tiêu, CPU/RSS/lock p95 tổng thể tốt hơn baseline. |
| S-10 / P2, nhánh độc lập | Chỉ khi có nguồn counter packet đúng: collector bounded và EWMA/Chi-square **observe-only**, có quality/warm-up/reset/generation. | `internal/trafficstats/*`, `internal/adaptive/*` (mới nếu được duyệt) | Không suy ACK rate từ số session; không tự mutate nft/policy hay phân loại attack chỉ từ p-value; số đo false positive và overhead được công bố riêng. |

P0 là sửa hợp đồng đúng đắn đã ghi trong kế hoạch M2. P1/P2 là quyết định hiệu năng/sản phẩm sau baseline, không phải điều kiện tự động để gọi M2 hoàn tất.

## 4. Hợp đồng xử lý chi tiết

### 4.1 Dump, Get và chất lượng dữ liệu

| Tình huống | Kết quả/hiệu ứng bắt buộc |
|---|---|
| Nhận multipart hợp lệ, kernel sender/sequence/family đúng, gặp DONE, không vượt limits và không có loss trong cutover | `Complete=true`; được phép reconcile vắng mặt đối với session trước cutover, có xét event mới hơn. |
| `MaxRecords` hoặc `MaxBytes` chạm, timeout/cancel, MSG_TRUNC, ENOBUFS, NLMSG_ERROR, interrupted dump, malformed nested attribute, sender/sequence/family sai | `Complete=false` + reason có cấu trúc; không dùng “vắng trong dump” để close; health degraded. Phải đếm wire bytes trước khi cấp phát/giải mã record vượt ngưỡng. |
| Event queue mất record trong cửa sổ dump/replay | Ghi loss/cutover ID, không dùng negative sweep của vòng này; schedule resync có backoff, không spin. |
| Get trả flow đúng toàn bộ identity đủ tin cậy | `PRESENT_EXACT`; merge các field có presence và gia hạn expiry nếu timeout hợp lệ. |
| Kernel trả ENOENT cho truy vấn hợp lệ, đủ zone/family/tuple và không có lỗi transport | `ABSENT_CONFIRMED` cho identity được hỏi; chỉ lúc đó expiry cleanup có thể đóng phiên cũ sau khi CAS. |
| Trả flow cùng tuple nhưng khác ID/kernel start/boot/namespace, hoặc thiếu trường cần để phân biệt | `MISMATCH_OR_AMBIGUOUS`; không dùng kết quả để xác nhận phiên cũ hay release guard; chuyển sang resync/đối chiếu khác. |
| Permission error, quá hạn, transport/decoder lỗi hoặc IPv6 targeted query chưa được chứng minh | `UNAVAILABLE`; session STALE/UNVERIFIED, retry có budget; không giả thành “not found”. |

`github.com/ti-mo/conntrack v0.5.1` hiện có `Conn.Get` theo tuple+zone, nhưng cần kiểm tra đường IPv6: bản thư viện chọn family IPv6 khi **cả** original và reply tuple đều IPv6. Spike triển khai S-02 phải chứng minh query IPv4/IPv6, NAT, zone 0/khác 0; nếu không bảo đảm thì dùng raw targeted CT_GET riêng. Không gọi `Conn.Dump` làm fallback im lặng. Nếu interface `Source.Get` vẫn trả `(Record, error)`, dùng typed errors cho ABSENT/MISMATCH/UNAVAILABLE; không gộp các lỗi vào “not found”.

Presence phải xuất phát từ attribute có thật trên wire của dump **và event**, gồm ID, mark, zone, counters, timeout, timestamp, reply/protoinfo. Các trường không có presence không được xóa giá trị store đã biết; trường có presence với số 0 phải xử lý đúng. Cần chứng minh decoder và thư viện hiện có có giữ thông tin này hay không trước khi quyết định reuse decoder; giá trị zero trong struct thư viện không đủ bằng chứng.

### 4.2 Merge, resync và vòng đời

| Input/trạng thái | Thay đổi được phép | Thay đổi cấm |
|---|---|---|
| NEW hoặc UPDATE cho incarnation mới, identity đủ | Tạo session, alias NAT, quality/expiry, đánh giá policy đúng generation. | Gộp với incarnation cũ chỉ vì original tuple giống. |
| Dump nhắc lại session không đổi | Tăng `LastObservedAt`/last-resync marker theo hợp đồng telemetry; cập nhật tình trạng health. | Tăng `LastSeen`, emit update/decision, gọi inspection hoặc policy evaluate không cần thiết. |
| Counters tăng hoặc state có bằng chứng hoạt động mới | Cập nhật counters monotonic trong cùng incarnation, `LastSeen`, phiên bản cần thiết; xử lý thay đổi có ý nghĩa. | Cộng dồn counter snapshot như delta; áp dụng counter cũ sau event mới hơn. |
| Timeout thay đổi nhưng counters/state không đổi | Cập nhật `ExpiresAt` và token dành cho expiry CAS/index; giữ nguyên `LastSeen`. | Xem sự hiện diện trong dump là packet mới. |
| Partial UPDATE thiếu mark/reply/counters | Bảo lưu field cũ, đánh dấu missing/quality và targeted Get khi cần. | Ghi zero/default đè mark, NAT alias hoặc confidence cũ. |
| Full dump hoàn chỉnh, không mất event và không thấy incarnation trước cutover | Close bằng reason “verified absent in complete dump”, cleanup index/guard an toàn. | Close session có NEW/UPDATE sau cutover hoặc identity mơ hồ. |
| DESTROY đúng incarnation | Close, tombstone, gỡ guard theo kiểm tra guard-key hiện hữu. | DESTROY cũ đóng phiên mới tái sử dụng ID/tuple. |

`LastObservedAt` là lần đọc tại nguồn; `LastSeen` là lần có bằng chứng hoạt động. Quy định revision cần nhất quán với CAS: no-op observation không tăng session revision/store revision chỉ để chống churn; expiry refresh phải có mutation token/epoch mà cleanup kiểm tra lại. Nếu API muốn bộc lộ `LastObservedAt` realtime mà không tăng revision, document rõ đây là trường quan sát không phải khóa CAS. Policy generation/guard revision vẫn phải được kiểm tra độc lập.

Resync không được giữ store lock trong lúc I/O netlink hoặc Get. Event listener tiếp tục nhận vào queue bounded; cutover/replay phải ngăn dump cũ ghi đè event/DESTROY mới. Nếu queue tràn, không tăng queue vô hạn để “cứu” một vòng dump: hạ quality và resync lại có giới hạn.

### 4.3 Cleanup expiry hai pha

| Bước | Hợp đồng |
|---:|---|
| 1 | Dưới store lock, chọn tối đa ngân sách candidate có `ExpiresAt <= now`; chụp SessionID, full identity, expiry token/Revision; không đổi state. |
| 2 | Ngoài lock, thực hiện targeted Get với timeout/rate/concurrency budget. Có fairness giữa cleanup, event, query; không để Get nối đuôi vô hạn. |
| 3 | Dưới lock, so lại SessionID, incarnation và token. Nếu UPDATE/DESTROY/resync chen vào, bỏ kết quả cũ và quyết định lại. |
| 4 | `PRESENT_EXACT`: merge timeout/counters có presence, requeue expiry. `ABSENT_CONFIRMED`: close đúng incarnation, rồi phát lifecycle event và release guard ngoài lock. `MISMATCH/UNAVAILABLE`: STALE/UNVERIFIED + backoff, không phát kernel DESTROY. |
| 5 | Nếu giới hạn RAM buộc phải bỏ bản ghi tracking khi Get luôn lỗi: đây là sự kiện “tracking evicted”, không phải “kernel flow destroyed”; không gỡ kernel guard dựa trên suy đoán. Cần thiết kế riêng quyết định guard TTL/capacity và báo degraded. |

Mặc định 512 candidate/30 giây xử lý 50.000 candidate trong khoảng **49 phút** nếu không có nguồn cleanup khác và mỗi lượt đều xử lý đủ 512. Vì vậy chỉ thêm heap để tìm deadline không đủ; ngân sách xác minh/worker và độ trễ backlog phải được đo rồi chốt theo CPU/VM. Index expiry chỉ thay đổi chi phí *chọn* candidate, không thay thế bước xác minh.

## 5. Tối ưu theo số đo, không đổi ngữ nghĩa

| Đường đo | Baseline cần ghi | Lựa chọn khi vượt budget | Điều kiện loại bỏ lựa chọn |
|---|---|---|---|
| Query sessions | N=1k/10k/50k; page đầu/cuối; filter zone/state/IP/original/translated/any; `Total`/sort/alloc/p95 | Lọc và count trên con trỏ dưới RLock, chỉ clone page; nếu sort toàn tập vẫn tốn, cân nhắc ordered/indexed snapshot có giới hạn. | Index thêm làm apply/close/RSS xấu hơn lợi ích query hoặc trả sai Total/HasMore/thứ tự. |
| Guard-key lookup | Số lần lookup, p95 với 1k/10k/50k active, ID reuse | Map key (namespace, zone, family, ID, original tuple) → tập SessionID/refcount; **không** đưa KernelStart vào key nft-visible. | Không chứng minh được đồng bộ với NEW/merge/close/rollback; nguy cơ gỡ guard incarnation mới. |
| Closed correlation | p95 theo MaxClosed 5k, NAT aliases, temporal ambiguity | Chỉ mục alias → tập recent closed bounded; TTL eviction cùng ring/tombstone. | Mất ứng viên hợp lệ hoặc tăng false match sau thời điểm đóng. |
| Expiry selection | Scan time, lock hold p95, due/backlog và expired age | Indexed heap/timing wheel bounded; update in place/remove khi timeout/close. | Heap phình theo số UPDATE hoặc total CPU/RSS tăng mà backlog không giảm. |

Giữ chính xác `Total` của query có thể vẫn cần đọc toàn bộ session khớp; đặc tả **không** hứa O(page size) cho mọi filter. Phân trang theo `page/size` hiện có cũng không phải snapshot cố định giữa hai request. Cursor, approximate total hay thay JSON schema là thay đổi API độc lập.

EWMA/Chi-square chỉ nên khởi động sau khi có counter packet-level đáng tin cậy (ACK/SYN/RST, invalid/drop) và profile tải hợp lệ. Event NEW/DESTROY không thay thế bộ đếm ACK packet. Collector phải tách nguồn, cửa sổ, reset khi boot/ruleset generation đổi, quality khi thiếu mẫu, giới hạn cardinality và overhead. Đầu ra ban đầu chỉ là telemetry/alert để đánh giá; mọi quyết định chặn cần đặc tả và nghiệm thu riêng.

## 6. Thứ tự triển khai và cổng quyết định

| Mốc | Phụ thuộc | Deliverable reviewable | Cổng qua mốc |
|---|---|---|---|
| G0 Baseline | Code hiện tại, VM topology M2 | Script/benchmark + dữ liệu tải hợp lệ, cấu hình và metric định nghĩa | Có số đo riêng packet/Go; không có benchmark “máy khác, luật khác” để so trực tiếp. |
| G1 Source đúng | G0 | S-01, S-02, S-03, typed error/presence tests | Dump memory bounded; targeted Get và zero-vs-missing được chứng minh trên Linux. |
| G2 Lifecycle đúng | G1 | S-04, S-05, S-06 | Không false close/guard release dưới timeout refresh, loss, ID reuse, event race; forwarding không suy giảm chức năng. |
| G3 Chọn tối ưu | G2 và benchmark | Chỉ các S-07/08/09 vượt cổng đo, kèm before/after | CPU/RSS/p95/lock và backlog đạt budget chốt từ G0, tất cả invariants còn đúng. |
| G4 Tín hiệu thống kê (tùy chọn) | Nguồn packet counter được chứng minh | S-10 observe-only, quality và báo cáo false positive | Không tự đổi nft/policy; không ảnh hưởng traffic hợp lệ hoặc khả năng quản trị. |

Không gộp G1–G4 thành một PR lớn: một PR cho adapter, một PR cho lifecycle, rồi mỗi index/collector độc lập để dễ review và rollback. Mỗi PR mô tả rõ hợp đồng API/IPC nào giữ nguyên.

## 7. Ma trận kiểm thử bắt buộc khi triển khai

| Test ID | Kịch bản | Assertion/evidence tối thiểu |
|---|---|---|
| T-01 | Dump lớn hơn `MaxRecords` và `MaxBytes`, deadline/cancel giữa multipart, malformed/ENOBUFS/MSG_TRUNC | Không cấp phát theo toàn bảng; `Complete=false` đúng reason; không mass-close; source health degraded; raw counter/memory profile. |
| T-02 | Get IPv4/IPv6, NAT SNAT/DNAT, zone 0/khác 0, ID/KernelStart reuse; ENOENT vs timeout/permission | Đúng bốn outcome; không accept record khác incarnation; không dùng full dump; trace request/response đã lược bí mật. |
| T-03 | Attribute mark=0 có mặt, mark vắng, timeout/counter/reply vắng; UPDATE-before-NEW | Presence và merge chính xác; không mất NAT alias/epoch đã biết; quality PARTIAL khi thiếu bằng chứng. |
| T-04 | Cùng một full dump lặp nhiều lần; counter tăng; policy generation đổi | No-op không đẩy `LastSeen`/inspection; hoạt động thật tăng `LastSeen`; generation đổi vẫn đánh giá lại đúng. |
| T-05 | Dump hoàn chỉnh thiếu flow; dump lỗi thiếu flow; event queue loss khi dump; event NEW/DESTROY xen giữa cutover | Chỉ case có bằng chứng âm hợp lệ mới close; không resurrect session; không release guard của phiên mới. |
| T-06 | ExpiresAt qua hạn nhưng kernel còn; kernel xác nhận vắng; Get lỗi; event gia hạn đúng lúc xác minh; guard key tái sử dụng | Close/gỡ guard chỉ khi đã verify + CAS; STALE khi unavailable; không tạo false kernel DESTROY. |
| T-07 | 10k+ expiry candidates cùng lúc, tải mới tiếp tục đến, bounded worker | Báo backlog/oldest age; drain theo budget đã chốt, không starve event/API; không có goroutine/heap tăng vô hạn. |
| T-08 | Query 1k/10k/50k, trang đầu/cuối, mọi filter/NAT aliases, concurrent mutation | Item/Total/HasMore/thứ tự giữ hợp đồng, race-free; báo alloc, lock p95 và latency p95 so baseline. |
| T-09 | M3/M4 guard, inspection correlation active/closed, ID reuse và rollback/reboot | Không đổi quyết định policy/NAT/IPS; không mất attribution; activation/generation recovery đúng. |
| T-10 | EWMA/Chi-square nếu làm G4: burst hợp lệ, flood lab, counter reset/loss, mẫu ít, policy đổi | Chỉ signal kèm quality, không tự drop; đo false positive và overhead, không kết luận attack từ một statistic. |

Test unit/fuzz/race và Linux cross-build đi trước VM. VM nghiệm thu theo topology trong `tests/integration/m2/README.md`, thêm các kịch bản T-01–T-09; lưu command, stdout/stderr, journal, conntrack/nft snapshot, pcap khi liên quan, cấu hình và commit hash dưới một thư mục `artifacts/m2-session-hardening-<UTC>/`. Tài liệu kết quả phải phân biệt **PASS unit**, **PASS VM**, **FAIL**, **NOT_RUN**; không sửa trạng thái [M2 matrix](m2-acceptance-matrix.md) thành PASS VM chỉ vì có đặc tả này.

## 8. Vấn đề cần chốt trước khi code

| Quyết định | Cách chốt |
|---|---|
| Ngân sách max wire bytes/records, Get QPS/concurrency, expiry backlog và p95 acceptable | Lấy từ G0 trên VM mục tiêu, ghi số tuyệt đối cùng workload, không suy từ PDF. |
| Cách decode presence trên event và dump | Spike Linux chứng minh access raw attributes; nếu thư viện mất thông tin, thay adapter cần thiết nhưng giữ contract `Source`. |
| Semantics revision vs `LastObservedAt`/`ExpiresAt` | Định nghĩa CAS token cho expiry/decision và tác động lên API event trước khi sửa merge. |
| Chế độ xử lý khi kernel Get unavailable lâu và MaxSessions đầy | Tách tracking eviction khỏi verified close và định nghĩa guard TTL/capacity; ưu tiên không false release. |
| Có nên thêm heap/index/statistics | Chỉ quyết sau G0–G2 theo bảng mục 5; mỗi lựa chọn có benchmark và regression riêng. |

**Kết quả kỳ vọng của đặc tả:** có thể chia việc thành các thay đổi nhỏ, chứng minh đúng trước khi tối ưu, và dùng VM evidence để nghiệm thu. Tài liệu này không thay thế bằng chứng M1/M2 hiện có và không tự xác nhận hệ thống đã đạt các tiêu chí nêu trên.
