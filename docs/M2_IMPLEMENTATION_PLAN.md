# M2 – Stateful Session / Flow Engine, NAT Tuple Tracking, Decision Cache, Fast Path và Policy Invalidation

Ngày audit: 2026-09-16. Workspace: `D:\KLTN`.

Trạng thái tài liệu: **PLAN sau khi audit source; implementation M2 đã có trong workspace**.
M1 đang code-complete theo trạng thái dự án và **chưa có Ubuntu VM acceptance**; M2
đã có unit/race/static evidence nhưng packet-path Ubuntu vẫn `NOT_RUN`.
Các bảng kiểm thử bên dưới là công việc phải thực hiện, không phải kết quả đã PASS.

## Cách giao tài liệu này cho agent triển khai

> Đọc toàn bộ `docs/M2_IMPLEMENTATION_PLAN.md`, audit lại những điểm neo source
> trong mục A, rồi triển khai lần lượt E0–E11. Chỉ làm M2 trong phạm vi tài liệu.
> Giữ cơ chế routing/NAT/network reconciliation và rollback của M1, chỉ thay các
> điểm tích hợp được chỉ ra. Mỗi bước phải build và có kiểm thử tương ứng trước
> khi chuyển bước. Không dùng dữ liệu mock để tuyên bố Linux enforcement đã chạy.
> Khi kết thúc, báo file thay đổi, test đã chạy, test chưa chạy và evidence.
> Chỉ ghi “M2 code complete, ready for VM acceptance” khi đạt mục I.4; chỉ ghi
> “M2 completed” khi có evidence Linux integration của mục G.

Phạm vi gồm L3/L4 stateful tracking, conntrack/NAT tuples, cache, invalidation,
IPC/session API, temporary block và session revoke cần cho invariant M2.
Không triển khai DPI/nDPI, application identification, Suricata/IDS/IPS,
DNS/URL inspection, TLS, ML, Risk Engine, WAF, HTTP proxy, DoS/anomaly detector,
Threat Intelligence, UI redesign, flowtable offload hoặc HA/cluster.
Các module thử nghiệm đã tồn tại ngoài phạm vi được giữ để build tương thích;
không nối chúng vào runtime M2, không viết thêm test chức năng M3+.

## A. Current state – audit source hiện tại

Các vị trí dưới đây được đọc trực tiếp trong workspace. Dòng có thể dịch chuyển
sau khi chỉnh sửa; tên hàm/type là điểm neo chính.

| Thành phần / điểm neo | Đã tồn tại | Thiếu hoặc giới hạn đối với M2 |
|---|---|---|
| `cmd/ngfw-engine/main.go:46` | Tạo `engine.New`; controller apply running config lúc startup; mở Unix socket. | Engine dùng `enforcement.NewMemory()`. Chưa có conntrack source. Session runtime chưa được feed bởi kernel. |
| `cmd/ngfw-api/main.go:42` | API apply cấu hình qua IPC, không gọi `ip`/`nft`. | API vẫn tạo `engine.New(manager, memory)`, session store, event bus và cleanup riêng. Đây là blocker ownership của M2. |
| `internal/domain/types.go:143` | `FlowKey`, `Reverse()`, `String()`. | IP/protocol là string; chưa có family, CT zone, ICMP identity và canonical binary key. |
| `internal/domain/types.go:160` | `Session`: counters lên/xuống, policy/decision version, boolean invalidation; hai tuple optional. | Chưa có CT identity, NAT aliases, lifecycle/cache enums, expiry cụ thể. `OriginalTuple`/`ReplyTuple` chưa được store populate từ kernel. |
| `internal/session/store.go:48` | Mutex, capacity, hai chiều cơ bản qua canonical string, clone khi đọc. | Không có CT index/NAT index. `FindByFlowID` quét toàn bộ; `Delete/Cleanup` quét index lồng nhau. API list clone tất cả. Chưa xử lý reuse/reorder/resync. |
| `internal/session/store_test.go` | Một test hai chiều của tuple TCP. | Chưa chứng minh NAT mapping, kernel lifecycle, bounded recovery hoặc concurrent query/commit. |
| `internal/engine/engine.go` | Cache/invalidation trong RAM và event bus. | `EvaluateFlow` nhận observation do caller cung cấp; phụ thuộc application/risk. Gán TCP ESTABLISHED khi thấy observation TCP. Không phải M2 connectivity runtime. |
| `internal/policy/evaluator.go:107` | Priority, first-match, default deny, một phần L3/L4. | Trộn risk/profile/application. Matcher port chỉ so chuỗi port đơn; khác compiler vốn hỗ trợ range. Zone so không phân biệt hoa thường trong khi compiler tra ID chính xác. |
| `internal/dataplane/compiler.go:64` | Ruleset stateful, NAT, OR semantics; DNAT guard trước chain forward. | `ct state established,related accept` vô điều kiện, không có generation/cache mark/revocation. Policy ALLOW→DROP chưa thu hồi established flow. |
| `internal/dataplane/compiler.go:30` | Có set `temporary_blocks` và rule prerouting kiểm tra source. | API block chưa cập nhật set này thật; chưa có cơ chế block theo original tuple ở cả hai chiều. Chưa có contract/test bảo toàn dynamic state qua mọi activation. |
| `internal/dataplane/controller.go` | Reconcile, snapshot, activation journal, restore khi lỗi. | Snapshot/journal chỉ chứa config, chưa gắn generation/epoch của cache. Controller nhận Apply không cập nhật config manager trong engine. |
| `internal/config/manager.go:521` | Commit/rollback có callback apply, persist previous config. | API hiện là writer của running.json. Callback chưa truyền activation version; giữ `m.mu` trong lúc apply/network I/O. Engine manager có thể giữ config/version cũ sau API commit. |
| `internal/config/manager.go:573` | Rollback đã dùng `current version + 1`. | Giữ hành vi tốt này; bổ sung đồng bộ generation đến engine/kernel, không viết lại thành số version cũ. |
| `internal/engineipc/ipc.go:21` | IPC v1, operation `apply`, giới hạn request, 16 pending, timeout. | Không có query sessions/stats, commit generation, revoke, block. Timeout mặc định 90 giây không phù hợp query. |
| `internal/management/api.go:755` | Có list/detail sessions, DELETE session, stats và websocket. | Đọc local engine. Pagination chỉ ghi page=1 và trả tất cả. DELETE chỉ xóa RAM nhưng trả `terminated`; chưa revoke traffic. |
| `internal/enforcement/enforcer.go` | Interface và mock Memory phục vụ test. | Chưa có implementation block/revoke kernel cho M2. Không được xem `Memory` là enforcement production. |
| `internal/events/bus.go` | Publish nonblocking, có dropped counter. | Capacity theo từng subscriber; số subscriber chưa có trần. Event mới chỉ theo SecurityEvent, chưa có lifecycle M2. |
| `internal/telemetry/writer.go` | Queue bounded, JSONL writer bất đồng bộ. | Không phải SQLite. Rotation hiện reopen cùng file append nên chưa giới hạn file thật; không dựa vào writer này để bảo đảm bounded M2. |
| `deploy/ngfw-*.service` | Engine có CAP_NET_ADMIN; API user ngfw. | API còn được ghi chung state directory. Cần tách quyền ghi running state khi chuyển owner sang engine. |
| `go.mod` | Go 1.22, x/net, x/crypto, x/sys. | Chưa có thư viện conntrack/netlink. Không tự nâng Go hoặc dùng dependency `@latest`. |

### A.1. Những sửa đổi M1 bắt buộc để nối M2

1. Bỏ local runtime engine khỏi API và chuyển quyền commit running config sang
   engine: cần để generation, kernel activation và SessionStore cùng một owner.
2. Thay accept established vô điều kiện bằng nhánh cache có kiểm tra epoch,
   zone pair và hard block/revocation.
3. Tách normalized connectivity program dùng chung giữa evaluator và compiler.
4. Mở rộng metadata của activation journal, giữ compensating rollback M1.
5. Cấp đường kernel thật cho temporary block/session revoke.

Không có lý do từ audit này để viết lại `NetworkReconciler`, tạo network stack
mới hay đổi Linux routing/NAT sang userspace. Những điểm trên là thay seam tích
hợp; mọi thay đổi rộng hơn phải kèm bug tái hiện được và M1 regression test.

### A.2. Phạm vi IPv6 thực tế

M1 có model/validation/apply address và route IPv6, nhưng policy address parser
hiện chỉ nhận IPv4; chưa có acceptance dual-stack. Vì vậy M2 hỗ trợ tuple và
tracking IPv6 non-NAT ở tầng dữ liệu, không tự bật IPv6 forwarding hay cam kết
firewall IPv6 đầy đủ. Flow IPv6 ngoài khả năng policy đã kiểm thử phải ghi rõ
`connectivity_evaluation=UNSUPPORTED_FAMILY`, không suy ra một ALLOW đã kiểm chứng.

## B. Architecture decisions

### B.1. Ownership và đường xử lý

```text
Traffic ──> Linux conntrack + routing/NAT + nftables ──> destination
                         │
                         └── ctnetlink events / bounded dump
                                      │
                                  ngfw-engine
                           ConntrackAdapter / SessionStore
                           ConnectivityProgram / DecisionCache
                           Generation / Invalidation / RuntimeGuards
                                      │
                           Unix socket IPC có giới hạn
                                      │
                                   ngfw-api
                           Auth / RBAC / candidate / HTTP
```

- Kernel quyết định packet đầu tiên bằng nftables; không chờ một conntrack
  event bất đồng bộ rồi mới quyết định cho packet đó.
- Engine là owner duy nhất của runtime session, flow indexes, cache, current
  generation, conntrack source và các mutation dataplane.
- Runtime evaluator phản ánh L3/L4 policy và giải thích quyết định; compiled
  nftables program là nơi enforce. `CACHED` trong RAM không tự chứng minh rằng
  một packet đã được kernel accept.
- API giữ candidate editor, auth/audit và DTO. API không tạo `engine.Engine`,
  `session.Store`, mock enforcement hoặc authoritative running manager.
- `Memory` chỉ là test double. Windows có thể chạy API với fake IPC trong test;
  khi không có engine thì query thật trả 503, không trả session mock như dữ liệu thật.
- Existing experimental proxy không được install/start trong M2. Không sửa
  nghiệp vụ proxy để mở rộng milestone; có thể giữ compatibility adapter cho build.

### B.2. Conntrack source: ctnetlink, không parse output command

Chọn `github.com/ti-mo/conntrack v0.5.1` cho typed decoder;
`github.com/mdlayher/netlink v1.7.2` cho message encoding/decoding/socket helpers;
giữ x/sys hiện có theo dependency resolver. V0.5.1 khai báo Go 1.21 và có public
`Event.Unmarshal`, phù hợp baseline Go 1.22. Khóa version trong go.mod/go.sum;
không lấy master vốn yêu cầu toolchain mới hơn.
Nguồn: [go.mod v0.5.1](https://raw.githubusercontent.com/ti-mo/conntrack/v0.5.1/go.mod),
[event decoder v0.5.1](https://raw.githubusercontent.com/ti-mo/conntrack/v0.5.1/event.go).

Interface định hướng; concrete types nằm trong domain/conntrack, không lộ type
thư viện bên thứ ba vào session/policy/API:

```go
type Source interface {
    Subscribe(ctx context.Context, sink EventSink) error
    Dump(ctx context.Context, limits DumpLimits, visit func(Record) error) (DumpResult, error)
    Get(ctx context.Context, identity Identity) (Record, error)
    Close() error
}

type EventSink interface {
    TryEnqueue(Event) bool // không block khi queue đầy
    ReportLoss(Loss)
}
```

Quyết định implementation:

1. File Linux có build tag; non-Linux trả `ErrUnsupportedPlatform`. Fake source
   dùng được trong Windows unit test.
2. Socket event riêng, subscribe NEW/UPDATE/DESTROY trước khi bắt đầu dump.
   Một reader giữ receive order; không mở goroutine vô hạn cho từng event.
3. Socket dump/Get riêng, có deadline/cancel. Dùng transport đọc từng datagram
   netlink với buffer trần, decode message vào từng `Record`, rồi bỏ raw bytes.
4. Không gọi `conntrack.Dump()` rồi truncate kết quả. Thư viện có thể đã gom cả
   bảng vào RAM trước khi caller cắt; `netlink.Conn.Receive()` cũng gom multipart
   thành slice. Adapter dump phải dùng receive datagram có giới hạn
   (`unix.Recvmsg`/RawConn trên socket chuyên dụng), dừng đúng NLMSG_DONE/ERROR.
   Nguồn: [netlink Receive implementation](https://raw.githubusercontent.com/mdlayher/netlink/v1.7.2/conn.go).
5. Validate sender kernel, family, sequence của dump, nested lengths và byte
   order. `MSG_TRUNC`, ENOBUFS, interrupted dump, decoder failure hoặc queue drop
   đều làm `DumpResult.Complete=false` và tracking health degraded.
6. Không tắt thông báo ENOBUFS. Không diễn giải multicast sequence=0 là global
   ordering hoặc giả định có số event liên tục do kernel cung cấp.
7. Ghi presence flags: thiếu counters/mark/timeout/ID khác với giá trị 0. UPDATE
   thiếu tuple hoặc metadata không được xóa dữ liệu đã biết. Get bounded để bổ sung.
8. NEW bị firewall drop trước confirmation có thể không xuất hiện như một live
   conntrack. Không tạo session giả để có đủ số blocked packet trên dashboard.
9. Production không chạy `conntrack -E`/parse text; CLI conntrack chỉ dùng trong
   script nghiệm thu để thu evidence.

Bật/persist `nf_conntrack_acct=1`, `nf_conntrack_events=1` và
`nf_conntrack_timestamp=1` khi kernel hỗ trợ; xác minh readback. Accounting và
timestamp có thể thiếu ở connection đã có trước khi bật; API phải báo missing,
không báo 0/CreatedAt giả. Không tự tăng `nf_conntrack_max`, đổi TCP timeout hay
tắt checksum/rp_filter. Nguồn: [Linux 6.8 conntrack sysctls](https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/networking/nf_conntrack-sysctl.rst).

### B.3. Tuple, identity và NAT alias

- Tạo comparable `Tuple` với `netip.Addr`, uint16 port, uint8 protocol/family,
  ICMP type/code/ID. Key luôn kèm network namespace identity và conntrack zone.
- Normalize IPv4-mapped address có kiểm tra family; không gộp IPv4 với IPv6 chỉ
  do dạng string giống nhau. Reject invalid/mixed family, port overflow và scope
  IPv6 không đủ identity. Không lowercase tùy ý zone ID.
- `FlowKey` là scoped directional tuple. Canonical bidirectional key dùng so
  sánh các field nhị phân theo thứ tự cố định. Giữ direction riêng, không biến
  tuple nhỏ hơn thành “client” hay “original”.
- Với ICMP echo, reverse phải đổi type request↔reply và giữ identifier;
  không dùng hai port=0 làm identity chung cho mọi ping.
- Conntrack zone 16-bit không phải Security Zone WAN/LAN/DMZ. M2 production
  dùng network namespace hiện tại, không yêu cầu CAP_SYS_ADMIN/setns; model và
  fake fixtures vẫn kiểm tra isolation theo namespace/CT zone.

Với original tuple `O` và reply tuple `R` đã hoàn chỉnh:

```text
T = Reverse(R)                           # tuple original-direction sau NAT
P = (O.src_ip, O.src_port, T.dst_ip, T.dst_port, protocol)
                                        # view tại forward: sau DNAT, trước SNAT
aliases = unique(O, Reverse(O), R, T, P, Reverse(P))
```

SNAT khi source endpoint của O khác T; DNAT khi destination endpoint của O khác
T. Có thể đồng thời SNAT+DNAT; không giới hạn vào một enum loại trừ lẫn nhau.
Chỉ công bố translated tuple khi reply/NAT status đủ tin cậy. Không lấy địa chỉ
WAN trong config để đoán translated source port.

| Case | O | R | T = Reverse(R) |
|---|---|---|---|
| SNAT/MASQUERADE | `192.168.10.10:50000 → 203.0.113.10:443` | `203.0.113.10:443 → 192.0.2.2:61000` | `192.0.2.2:61000 → 203.0.113.10:443` |
| DNAT | `198.51.100.20:51000 → 192.0.2.2:8443` | `10.20.0.10:443 → 198.51.100.20:51000` | `198.51.100.20:51000 → 10.20.0.10:443` |

SNAT và MASQUERADE có thể không phân biệt được chỉ bằng O/R. Trả `snat=true`,
`source_translation_method=UNKNOWN` trừ khi có evidence mapping đúng NAT rule
và đúng activation; không gắn tên MASQUERADE chỉ vì source trùng WAN IP.

Identity ưu tiên `(boot_id, netns, CT zone, family, CTA_ID, O, kernel_start)`.
CTA_ID không được coi là globally unique hoặc vĩnh viễn không reuse. Index theo
CT ID là scoped index và phải verify O/start trước merge/delete. Một ID collision
không được overwrite session khác; bucket ambiguity cũng có trần.

SessionID có thể derive bằng hash của stable identity khi đủ dữ liệu. Nếu thiếu
ID/start, tạo ID local và ghi `identity_confidence=PARTIAL`; không cam kết ID giữ
nguyên qua restart trong case này. Trong một runtime, NEW/UPDATE/dump của cùng
identity phải chỉ có một SessionID. Aliases trùng giữa hai live identities trả
`AMBIGUOUS`, yêu cầu CT identity để phân giải, không chọn session “gần giống”.

### B.4. Session lifecycle, cleanup và resync

- TCP: NEW khi handshake chưa hoàn tất; ESTABLISHED từ TCP protoinfo; CLOSING
  cho FIN/CLOSE_WAIT/LAST_ACK/TIME_WAIT/CLOSE còn trong kernel; CLOSED khi
  DESTROY hoặc xác nhận kernel không còn entry. Không suy ra ESTABLISHED chỉ từ UPDATE.
- UDP/ICMP echo: NEW khi chưa thấy reply; ESTABLISHED khi kernel status cho
  biết đã thấy hai chiều; CLOSED khi DESTROY/expiry được xác minh.
- Counter là snapshot tuyệt đối từ kernel. Merge theo presence và monotonic
  value trong cùng incarnation; không cộng lại toàn bộ counters ở mỗi UPDATE.
- `LastObservedAt` là thời điểm event/Get/dump; `LastSeen` là quan sát hoạt động
  gần nhất dựa trên counter/state. Dump lặp lại không chứng minh có packet mới.
- `ExpiresAt = observed_at + kernel_remaining_timeout` khi có timeout. Không
  expire một TCP idle hợp lệ chỉ vì không có UPDATE trong 5 phút.
- Trước cleanup timeout không chắc chắn: targeted Get có budget; nếu netlink
  lỗi thì đánh dấu STALE/UNVERIFIED. Có thể evict bản ghi tracking theo TTL để
  giữ giới hạn RAM, nhưng không xóa conntrack/firewall và không phát “kernel DESTROY”.
- Closed record giữ trong ring riêng tối đa 5.000 entries/60 giây; active indexes
  gỡ ngay khi close. Tombstone bounded chống event trễ hồi sinh incarnation cũ.

Resync algorithm bắt buộc:

1. Receiver đăng ký event trước, đẩy vào bounded queue và gắn local receive sequence.
2. Bắt đầu dump với resync ID/cutover marker; stream từng record vào merge path.
3. Events đã chạm một session sau cutover không bị snapshot cũ ghi đè.
   DESTROY/tombstone của đúng incarnation thắng record dump cũ.
4. Drain/replay bounded event buffer; merge idempotent. UPDATE-before-NEW phải
   Get bổ sung hoặc tạo record PARTIAL có identity rõ; không tự nhân bản.
5. Chỉ sweep “không có trong kernel” sau full dump thành công, không có loss,
   và chỉ xét session tồn tại trước cutover không có event mới hơn. Với identity
   mơ hồ, targeted Get xác nhận trước khi close.
6. Dump truncated/timeout/loss không được sweep cả store. Giữ degraded, schedule
   retry với backoff; Get round-robin giúp refresh entries không nằm trong phần
   dump đã nhận. Native netlink dump không có pagination ổn định để tự chế cursor.
7. Event có ID reuse/counter regression/timestamp conflict: quarantine bounded,
   Get lại, không apply DESTROY nhầm sang connection mới cùng 5-tuple.

Periodic resync mặc định 30 giây; request resync do loss được coalesce, không
spin-loop khi kernel lớn hơn tracking capacity. Khởi động lại engine luôn xây
store từ kernel; không restore một session cache RAM cũ như dữ liệu đáng tin.

### B.5. Connectivity semantics dùng chung

Tạo immutable `connectivity.Program` từ config validated, chứa ordered rules,
zone→interfaces, normalized IP sets và protocol/port intervals. Cả nft compiler
và runtime `EvaluateConnectivity` nhận cùng program.

- Priority nhỏ trước, first-match; duplicate priority bị reject như M1.
- Các field khác nhau AND; nhiều zone/address/service trong một field OR.
- Service hỗ trợ `tcp`, `udp`, `icmp`, port đơn và range đang được M1 hỗ trợ.
- CIDR canonical; empty matcher là wildcard; action chỉ ALLOW/DROP/REJECT.
- `default_deny=false` vẫn được hỗ trợ như M1, nhưng default ALLOW phải đi qua
  guard rồi mới set mark; không có bypass do base-chain policy accept.
- Runtime dùng `PolicyView=P` ở B.3. M1 forward match destination sau DNAT;
  không chuyển sang match public port 8443 nếu kernel đang kiểm tra DMZ port 443.
- Reply direction cũng evaluate cùng original-direction PolicyView, không
  so reverse packet với rule LAN→WAN rồi kết luận default deny.
- Kernel slow rules cho tracked TCP/UDP dùng `ct original ip saddr`, original
  source port khi cần, `ct reply ip saddr` và `ct reply proto-src` cho destination
  đã DNAT. Guard bằng family/protocol trước khi đọc transport fields.
  Nguồn cú pháp: [nft conntrack expressions](https://netfilter.org/projects/nftables/manpage.html).
- Unknown zones không tự đoán bằng longest-prefix IP. Rule đòi zone không thể
  evaluate khi thiếu provenance phải trả `NOT_EVALUATED/CONTEXT_UNAVAILABLE`.
- Profiles/application/risk không tham gia quyết định M2. Giữ profile references
  legacy như annotation và báo `inspection_active=false`. Enabled rule có
  application/risk predicate không thể enforce bằng L3/L4 phải reject rõ khi
  activate M2, không âm thầm bỏ predicate và mở rộng ALLOW.

Đóng băng fixture semantics độc lập: expected action/matched ID viết tay cho
ports/CIDR/zone/NAT; không chỉ để evaluator và compiler cùng lặp một bug.

### B.6. Kernel fast path và zone provenance

**Chọn kernel-only packet verdict, không NFQUEUE, không offload.** Kernel slow
path nghĩa là evaluate full nft L3/L4 program; không có packet round-trip qua Go.

Conntrack events không cung cấp trực tiếp security ingress/egress zone của
project. M2 sẽ ghi provenance zone pair vào phần ct mark do NGFW sở hữu, cùng
cache epoch. Điều này tránh đoán WAN/LAN bằng địa chỉ IP và không thêm NFLOG.

Mark layout đề xuất cố định cho M2 lab:

```text
bits 31..20 : kernel epoch 12 bit, 1..4095 (0 = chưa cache)
bits 19..14 : source zone slot 6 bit, 1..63 (0 = unknown)
bits 13..8  : destination zone slot 6 bit, 1..63 (0 = unknown)
bits 7..0   : giữ nguyên, NGFW không sở hữu

NGFW_MASK = 0xffffff00
encoded = epoch<<20 | source_slot<<14 | destination_slot<<8
set ALLOW: ct mark = (ct mark & 0x000000ff) | encoded
clear NGFW cache: ct mark = ct mark & 0x000000ff
```

Chỉ mark ALLOW; không cần thêm bit ALLOW. DROP/REJECT không set epoch hợp lệ.
Epoch là token kernel, **không phải** `PolicyGeneration mod 4096`.
Zone slots nằm trong activation snapshot, chỉ decode mark bằng mapping của
đúng epoch. Không đoán slot của epoch cũ theo zone ordering mới.

Giới hạn 63 security zones được validate cho mode cache này; đây là giới hạn
đóng gói M2 lab, không phải giới hạn conntrack zone. Nếu môi trường có bên khác
ghi upper 24 bits hoặc config vượt capacity thì không enable mark cache;
giữ nft full-policy path và báo capability limitation, không ghi đè mark khác.
Model/query vẫn hoạt động nhưng zone provenance thiếu phải báo unavailable.
Khi cache disabled do không sở hữu mark, compiler không đọc mark để accept và
không ghi/clear bất kỳ bit nào của mark. Khi chỉ hết epoch nhưng ownership vẫn
hợp lệ, có thể clear NGFW bits; hai trường hợp phải có compile options riêng.

Forward packet path:

1. Guard invalid/untracked theo capability policy; source block/revocation.
2. DNAT destination-zone guard của M1 vẫn trước nhánh accept.
3. Dispatch theo actual ingress/egress interface và `ct direction` vào zone-pair
   chain. Original: source=iif-zone, destination=oif-zone. Reply: hoán đổi vai
   trò hai interface để có original-direction zone pair.
4. Cache hit chỉ khi `ct state established`, mark masked bằng encoded của
   **epoch hiện tại và zone pair hiện tại**, không có revoke/recheck. Tăng
   `fast_path_hits` rồi accept.
5. Cache miss trong mode sở hữu mark: clear phần NGFW mark, evaluate full current connectivity program
   trên normalized PolicyView; ALLOW ghi encoded và accept; DROP/REJECT enforce.
6. NEW/SYN retransmission chưa ESTABLISHED vẫn đi full policy; không nâng state
   của kernel. Next established packet có thể hit cache ở cả hai chiều.

Dùng nft verdict map theo `(iifname,oifname)` cho dispatch nếu kernel/nft VM
support; compiler xuất các chain cho những pair thực tế. Không expand mỗi
policy thành mọi tổ hợp địa chỉ/port; đặt trần số statement. Mọi cú pháp mark,
ct tuple và verdict map phải qua `nft -c` trong E0/E6.

ICMP echo dùng identity riêng ở userspace và matching protocol/address ở kernel.
`RELATED` không được accept vô điều kiện: chỉ ICMP error hợp lệ gắn với tracked
parent được current connectivity policy cho phép, sau block/revocation checks.
FTP/helper-created related connection không được inherit ALLOW tự động.
Không đọc TCP header của packet ICMP để suy ra policy parent. Khi không đủ
parent/zone evidence thì dùng explicit ICMP policy hoặc drop theo default;
ghi limitation và test PMTU/ICMP error để tránh phá M1 âm thầm.

### B.7. Generation, epoch, commit và rollback

Ba giá trị khác nhau:

| Giá trị | Ý nghĩa | Tăng khi nào |
|---|---|---|
| ConfigVersion / PolicyGeneration uint64 | Version running đã publish; M2 dùng cùng giá trị cho hai field. | Successful commit và explicit rollback: `current+1`. Không wrap uint64. |
| KernelEpoch | Token ct mark, gắn với config checksum/generation/zone slots và boot ID. | Startup/recovery, activation mới, compensation sau apply lỗi, global revalidation. |
| DecisionGeneration uint64 | Revision quyết định của một session, không phải config version. | Invalidation hoặc publish evaluation mới; giữ cùng giá trị khi chỉ refresh counters. |

Nâng engine thành writer duy nhất của running config. API vẫn có candidate
store với `candidate_revision`, `base_running_version`, không dùng manager local
để publish running. IPC `CommitConfig` mang candidate snapshot, expected version,
revision, actor/comment và operation ID. `RollbackConfig` gọi previous snapshot
trong engine. API `/config` đọc running/version từ IPC.

Commit transaction:

1. Serialize bằng activation queue riêng; check expected version và validate.
2. Compile Program + target version/epoch/zone slots; persist epoch high-water
   và journal intent bằng temp file, file sync, rename, directory sync trên Linux.
3. Đưa cache về disabled hoặc rotate sang safe current program trước bước đổi
   interface/route. Đây chỉ là bỏ optimization; traffic vẫn qua full policy.
4. Gọi NetworkReconciler M1, atomic nft policy replacement, verify kernel.
   Dynamic guards không bị xóa hoặc snapshot ngược trong thao tác này.
5. Persist running.json + previous với new version; publish immutable
   `RuntimeSnapshot{Config, Program, Generation, Epoch}` trong engine.
6. Session cache mismatch hết hiệu lực ngay theo snapshot/generation check;
   quét invalidation/event/evaluation theo batch. Không chờ quét 50.000 sessions
   xong mới chặn cached ALLOW trong kernel.
7. Trả ACK success chứa version/generation/epoch/checksum sau các bước trên.

Giữ compensation M1 khi interface/route/nft/persist lỗi. Khôi phục old config
với epoch **mới**, không dùng lại mark của attempted activation. Failed commit
không publish new ConfigVersion; session cache phải invalid theo epoch dù version
running giữ nguyên. Explicit rollback thành công luôn publish version lớn hơn.

Journal mở rộng lưu old/new config, version, epoch, zone mapping, phase,
operation ID và checksum. Nếu crash giữa nft apply và persist running: startup
đối chiếu journal/running, khôi phục last known-good hoặc hoàn tất đúng activation
đã durable; rotate epoch rồi resync. Không suy ra success chỉ từ applied snapshot.

`config.Manager` tách transaction serialization khỏi read-state mutex: copy
snapshot trong lock ngắn, release rồi mới gọi apply; publish bằng lock ngắn.
Không giữ session lock/read-state lock khi chờ filesystem, nft, ip hay IPC.
Có thể giữ một activation mutex/actor để serialize network writers; nó không
được dùng làm lock của ListSessions/event ingestion.

### B.8. Epoch exhaustion và restart strategy

Chọn **rotate epoch đã persist, không reuse trong cùng kernel boot**. File
`runtime-epoch.json` lưu schema version, kernel boot_id, highest allocated epoch,
current activation binding. Mỗi allocation phải durable trước khi compiler dùng.

- Sau engine restart, giữ running PolicyGeneration nhưng cấp epoch mới. Mark
  cũ không match rules mới; packet đi slow policy rồi tự được remark nếu ALLOW.
- Không tin RAM cache hoặc mark cũ chỉ vì config version giống nhau.
- Epoch vượt 4095: disable mark cache, tiếp tục full kernel policy. Không modulo,
  không flush conntrack. Chỉ reset allocator khi boot_id thực sự đổi (kernel CT
  table đã mất) hoặc có quy trình sweep/verify riêng được kiểm thử sau milestone.
- Nếu state epoch mất/hỏng mà kernel còn connection/marks: fail-safe cache
  disabled, health degraded, không tự chọn epoch=1. Policy vẫn enforce.
- Tradeoff: tối đa 4095 allocations/boot và thêm zone-pair dispatch; đổi lại
  không cần một bulk mark clear vừa race với packet vừa đụng NAT bindings.

Startup order chi tiết:

1. Load/recover durable running config/version; build immutable program/store.
2. Inspect kernel capability/runtime guard sets, epoch metadata; preserve M1
   routes/NAT và blocks/revokes còn hiệu lực.
3. Apply running config với fresh epoch hoặc safe no-cache ruleset.
4. Mở event subscription vào bounded buffer **trước dump**, để không mất cửa sổ
   NEW/DESTROY giữa dump và subscribe.
5. Stream dump, rebuild indexes, drain events theo B.4; không phát duplicate
   SessionCreated cho duplicate dump/NEW.
6. Publish `tracking=ready` nếu resync hoàn chỉnh; nếu lỗi vẫn cho IPC health,
   config management và kernel forwarding hoạt động, tracking báo degraded.

### B.9. Runtime guards và invalidation API

Tạo bảng `inet ngfw_runtime` riêng, engine sở hữu. Bảng chứa timeout source
blocks và per-flow revocation/recheck sets; chain forward priority -20 thực hiện
guard trước DNAT guard -5 và policy/cache chain 0. Không dùng cùng priority để
dựa vào thứ tự ngẫu nhiên. Nguồn: [nft hook priority và verdict](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).

M1 policy recompilation chỉ thay `inet ngfw`; không flush `ngfw_runtime` khi
commit, rollback, telemetry lỗi hay engine restart. Giữ bảo vệ raw-source ở
prerouting nếu cần tương thích; guard connection dùng `ct original saddr` để
temporary source block ảnh hưởng cả chiều request và reply của session đã NAT.

Temporary block M2: indicator là một source IP hợp lệ, timeout bắt buộc, trần
10.000 entries. API thêm block chỉ ACK sau nft transaction + readback; invalidation
RAM chạy sau enforcement. Không cần đợi session tìm thấy trong store mới block.
Block hết TTL tự hết trong kernel kể cả engine chết. Engine restart import TTL
còn lại; cold boot không hồi sinh block đã mất.

Session revoke dùng exact kernel identity: family + CT zone + CT ID nếu có +
original tuple, không chỉ client IP và không chỉ CT ID. Key typed cho TCP/UDP;
ICMP có ID/type/code riêng. Runtime nft selectors dựa trên original tuple ở cả
hai chiều nên NAT không làm mất match. Bộ set phải có capacity/timeout hoặc GC
có xác nhận, không tăng mãi khi mất DESTROY.

API DELETE session đổi nghĩa thực hiện thành revoke: install guard trước,
đánh dấu INVALIDATED/REVOKED, giữ record đến kernel DESTROY hoặc cleanup. Trả
`revoked=true`, `enforcement=DROP`, `tcp_reset_sent=false`; không nói đã reset TCP
hoặc đóng socket chỉ vì xóa store/conntrack. Không tự flush/delete mọi connection.
Revoke set không tự hết TTL trong khi kernel entry còn sống: GC chỉ remove sau
DESTROY đúng identity hoặc bounded Get/full resync xác nhận entry đã mất. Set
có trần 10.000 để engine chết cũng không gây tăng RAM vô hạn; khi đầy phải từ
chối revoke mới. Cách này tránh guard timeout mở lại một session đã revoke trong
lúc engine đang down. New incarnation có CT ID khác không match guard cũ.
Nếu identity không đủ chắc thì từ chối thao tác thay vì báo success. Test reuse
ID/tuple và restart; collision không phân giải được phải báo rõ, không xóa guard
chỉ vì SessionID cũ không còn trong RAM.

Contract nội bộ:

```text
Invalidate(selector, reason_code, mode, expected_generation)
selector: session ID | config-wide | zone/interface set | original-source IP
mode: REEVALUATE | REVOKE
result: affected_count, generation, enforcement_status, incomplete
```

| Trigger | Enforcement trước | Session transition |
|---|---|---|
| Policy/config generation đổi | Replace current policy + epoch atomically | CACHED→INVALIDATED; batch reevaluate bằng current snapshot. |
| Interface/zone topology hoặc route đổi | Disable old cache, reconcile, fresh epoch | Invalidate toàn store trong M2 cho đơn giản; reason có interface/zone. |
| NAT config đổi | Fresh epoch; giữ established NAT binding | Reevaluate theo tuple thực tế đang tồn tại, không giả vờ entry đã NAT sang target mới. |
| Manual revoke | Exact-flow guard drop trước cache | INVALIDATED, effective decision DROP, giữ lifecycle kernel riêng. |
| Temporary block | Kernel source block timeout trước cache | Invalidate các session matching original source; source guard có hiệu lực cả khi store đầy. |
| Recovery / cache không đáng tin | Fresh epoch hoặc disable cache | INVALIDATED/UNVERIFIED đến khi đủ metadata để reevaluate. |
| Internal selective REEVALUATE | Exact-flow recheck fence bypass cache | Clear cache bits rồi full kernel policy; chỉ bỏ fence sau xác minh generation/revision phù hợp. |

Risk/IDS reason có chỗ mở rộng enum/interface cho tương lai; M2 không nhận
security verdict chưa có evaluator. Không coi “clear mark rồi evaluate ALLOW
ngay” là implementation của REVOKE. Quota guard đầy phải trả lỗi/counter; không
ACK thao tác chưa enforce. Một activation actor serialize guard mutation và
config activation, nhưng đọc session/events không bị giữ theo network I/O.

### B.10. Cache trong RAM và concurrency

Cache hit đòi cùng PolicyGeneration và KernelEpoch, session incarnation/revision
không đổi, state còn sống, không invalidated, không active block/revoke/recheck,
và context cần thiết đã known. Cached allow không được dùng chỉ vì boolean
`FastPathEligible=true`.

Algorithm evaluate:

1. Đọc immutable current snapshot và copy session cùng revision dưới store lock.
2. Ra ngoài lock để match program, đọc guard snapshot và chuẩn bị events.
3. Publish bằng compare-and-swap logic trên `(session revision, generation,
   epoch, guard revision)`. Nếu có concurrent commit/DESTROY/block, bỏ result cũ
   và retry bounded hoặc giữ INVALIDATED; không ghi đè DROP mới bằng ALLOW cũ.
4. Publish event sau khi release store lock. API chỉ nhận clone/DTO immutable.

Bắt đầu bằng một RWMutex cho indexes, critical section ngắn. Tránh callback
`Update(fn)` có thể làm I/O hoặc đổi indexed fields tùy ý. Thay bằng mutation
typed và central alias replacement; mọi index update/remove cùng transaction RAM.
Không cần sharding trước khi benchmark chỉ ra contention.

### B.11. Resource budgets và failure behavior

| Tài nguyên | Mặc định / giới hạn |
|---|---|
| Active tracked sessions | 50.000; reuse MaxSessions hiện có |
| Aliases/session | 8 tối đa; trần global = 8 × MaxSessions |
| Closed records / tombstones | Mỗi loại 5.000 hoặc 60 giây; eviction có counter |
| CT ID/alias ambiguity bucket | Tối đa 4; vượt trần trả ambiguous/untracked, không ghi đè |
| Conntrack event queue | 10.000, tách khỏi telemetry |
| Netlink datagram / dump | 1 MiB buffer; 200.000 records hoặc 64 MiB raw hoặc 30 giây, chạm mức nào trước |
| Resync | Một job; periodic 30 giây, retry backoff 1→30 giây |
| Targeted Get | 100/s, tối đa 4 outstanding, deadline 1 giây |
| Cleanup | Tick 5 giây, batch tối đa 512 records |
| Telemetry lifecycle ring | 10.000 events; event ≤4 KiB; update coalesce tối đa 1/session/giây |
| Internal subscribers | Tối đa 8, queue riêng ≤1.024; drop có counter |
| IPC | 16 query pending, 8 mutation pending; bounded connection admission |
| Query timeout / response | 2 giây / 1 MiB; page mặc định 100, max 500 |
| Config mutation timeout | Engine 60 giây, API 90 giây; compensation có deadline riêng |
| Temporary block / revoke / recheck sets | Mỗi loại 10.000; validate trước khi ACK |
| Kernel cache / compiler | 63 known security zones; tối đa 100.000 generated statements |

Limits phải validate và có config/defaults; không chỉ khai báo const nhưng
không enforce. Record lists/raw frames không được giữ vô hạn trong hidden queue.

Session capacity đầy chỉ làm tăng `tracking_drops{reason=capacity}`; kernel vẫn
thực hiện routing/NAT/full policy/cache của nó. API/UI/telemetry chết không
flush tables, disable forwarding hoặc làm event receiver chờ vô hạn. Netlink
tracking lỗi chưa chứng minh kernel policy sai: giữ enforcement hiện tại, báo
tracking degraded, resync. Chỉ cache metadata/binding không đáng tin mới cần
rotate/disable optimization; fallback vẫn là current nft connectivity policy.

Nếu nft mutation thất bại, không báo success. Nếu ruleset không thể xác minh,
giữ last known-good hoặc rollback theo M1, expose enforcement degraded; không
tự flush toàn bộ firewall để “khôi phục”. Kernel conntrack hết capacity là lỗi
dataplane riêng, khác SessionStore đầy; báo health, không hứa forwarding vẫn
hoạt động trong mọi trường hợp kernel resource exhaustion.

### B.12. IPC, REST và event transport

IPC lên protocol v2 với payload typed theo operation; giữ Unix socket 0660,
peer access thuộc service group, API không có CAP_NET_ADMIN. Reject version
mismatch rõ ràng; không âm thầm fallback v1 `apply` bỏ generation.

| Operation | Kết quả / contract |
|---|---|
| GetRunningConfig | Config, version/generation, checksum, activation state. |
| CommitConfig / RollbackConfig | ExpectedVersion + operation ID; ACK sau activation/persist; conflict typed. |
| ListSessions | Filter, page/cursor, bounded DTOs, total/has_more, snapshot time. |
| GetSession | Session + tuple/NAT/cache/tracking/enforcement metadata; NOT_FOUND riêng. |
| SessionStats / Health | Counters O(1)/snapshot, không gọi List toàn bộ ở mỗi tick. |
| RevokeSession | Guard đã enforce hoặc error; không chỉ delete RAM. |
| List/Add/RemoveTemporaryBlock | Kernel timeout state là authority, API không có block map riêng. |
| ReadRuntimeEvents | Cursor có epoch/sequence, max 200 events, dropped/gap; không cần stream vô hạn. |

Timeout/cancel áp dụng cả dial, read/write và pending queue. Unknown payload,
oversized body/response, queue full có error code; reject path có write deadline
để một client không đọc response không chặn accept loop. Slow query không chặn
commit slot và ngược lại. API map: 400 invalid filter, 404 no session, 409 version
conflict, 503 engine unavailable/busy/degraded operation, 504 timeout.

Mutation operation ID được ghi trong activation journal và bounded receipt
store (ví dụ 1.024 receipts/24h). API timeout không đồng nghĩa rollback đã xảy ra:
client query operation outcome/current generation, retry cùng ID không commit
lần hai. Không tự sinh operation ID mới để retry một mutation chưa biết kết quả.

REST giữ `/api/v1` và envelope `success/data/error`:

```text
GET /api/v1/sessions?page=1&page_size=100
    &source_ip=192.168.10.10&destination_ip=203.0.113.10
    &protocol=tcp&source_zone=lan&destination_zone=wan
    &state=ESTABLISHED&decision=ALLOW
GET /api/v1/sessions/{id}
```

- IP filter mặc định trên original tuple; bổ sung `tuple_view=original|translated|any`
  nếu cần tra sau NAT, định nghĩa rõ trong OpenAPI. Query sai enum/IP trả 400.
- Page ≥1, size 1..500; sort ổn định `(created_at,id)`. Hỗ trợ cursor là lựa chọn
  ưu tiên cho traversal; `page` giữ compatibility của endpoint hiện có.
- Snapshot/pagination là weakly consistent dưới traffic: không bảo đảm kết quả
  đóng băng giữa hai HTTP request. Trả snapshot_time/store_revision; test count
  exact trên traffic đã quiescent và no duplicate trong cùng response.
- Query phải scan có budget, copy IDs/summary bounded dưới lock ngắn, filter/sort
  ngoài lock, clone full Session chỉ cho page cần trả. Không build response chứa
  toàn bộ bảng rồi mới cắt page. Giới hạn concurrent scans và response bytes.
- Detail giữ shape `data.session`; legacy client/server fields derive từ O.
  `security_context` có thể null/not_applicable_m2; không tạo context DPI/risk giả.
- Runtime không có engine: 503 và health down/degraded, không fake `total=0`.
- Stats/ws/events hiện có chuyển sang đọc IPC. Một API relay polling bounded
  ReadRuntimeEvents phục vụ browser; không một conntrack subscription/browser.
- Event gồm SessionCreated/Updated/Closed/Invalidated/DecisionChanged, ID,
  timestamp, sequence, generation/revision, reason. Mất event không mất policy.
  M2 dùng ring bounded; không mở rộng JSONL writer đang thiếu rotation thành hệ
  persistence mới. Evidence VM có thể thu journal/JSON ra thư mục riêng.

RBAC giữ viewer đọc, operator được block/revoke, admin mới commit/rollback.
Author trong audit lấy từ authenticated identity, không tin field username từ
client. Không thêm UI mới hoặc đổi cookie/auth architecture trong milestone.

## C. Danh sách file sẽ sửa / tạo khi triển khai

Tên file có thể tách nhỏ nếu cần readability, nhưng trách nhiệm và dependency
boundary bên dưới phải được giữ. Đây là inventory tương lai, không phải báo cáo
file M2 đã được code.

### C.1. File sửa

| File | Thay đổi dự kiến |
|---|---|
| `cmd/ngfw-engine/main.go` | Wire M2 Runtime, source, recovery, IPC v2; không wire inspection/risk. |
| `cmd/ngfw-api/main.go` | Bỏ `engine.New/NewMemory`, cleanup local; wire RuntimeClient/candidate/relay. |
| `internal/domain/types.go` | Compatibility aliases/legacy DTO fields; tách session/tuple contracts ra file riêng. |
| `internal/session/store.go` | Typed indexes, lifecycle merge, bounded remove/cleanup/query; snapshot revisions. |
| `internal/engine/engine.go` | Giữ legacy EvaluateFlow ngoài production M2; chỉnh tối thiểu để dùng compatibility store/types nếu cần. |
| `internal/policy/evaluator.go` | Chỉ bridge L3/L4 helper sang shared program khi cần; M2 không gọi risk evaluator ở file này. |
| `internal/dataplane/compiler.go` | Nhận connectivity Program/activation metadata; guarded cache path; giữ NAT rendering. |
| `internal/dataplane/controller.go` | Versioned activation metadata/journal, policy-cache fence, compensation fresh epoch. |
| `internal/dataplane/nft.go` | Thêm transaction/readback cho runtime tables/sets, serialized mutation, không shell interpolation. |
| `internal/config/manager.go` | Prepare/apply/publish locks; engine authority; Snapshot config+version atomic; candidate tách riêng. |
| `internal/engineipc/ipc.go` | Protocol v2 generic framing, deadlines, admission, bounded response/error. |
| `internal/management/api.go` | Depend interface RuntimeClient; sessions, stats, health, commit, rollback, blocks, DELETE chuyển IPC. |
| `internal/events/bus.go` | Bounded subscriptions/nonblocking close; hoặc reuse generic bounded transport cho RuntimeEvent riêng. |
| `deploy/ngfw-engine.service` | Quyền đọc boot_id/netlink và ghi đúng conntrack sysctls/state; vẫn CAP_NET_ADMIN. |
| `deploy/ngfw-api.service` | State write chỉ management subtree/log; không ghi running/epoch/journal. |
| `deploy/ngfw.env.example` | Phân biệt engine state, API candidate state và M2 limits. |
| `scripts/install-linux.sh` | Cài/verify conntrack requirements, sysctl file, state migration có backup; không cài M3+. |
| `docs/openapi.yaml` | Session/NAT/cache schemas, filters, bounded pagination, operation errors và revoke contract. |
| `README.md`, `docs/architecture.md` | Quy trình chạy M2, ownership, failure modes, status chưa nghiệm thu. |
| Các `_test.go` hiện có liên quan | Giữ M1 assertions, đổi dependency injection cho API; thêm case regression. |

Không sửa `internal/dataplane/linux.go` và `forwarding.go` trừ blocker M1 có test
tái hiện. Không sửa `web/`, ML, inspection hoặc proxy business logic để làm M2.

### C.2. File mới

| File / nhóm | Trách nhiệm |
|---|---|
| `internal/domain/flow.go`, `session.go`, `runtime.go` | DTOs/types tuple, identity, NAT, lifecycle/cache, runtime event/stats. |
| `internal/flow/tuple.go`, `nat.go`, `identity.go` | Canonicalization, reverse đúng protocol, alias generation, safe identity compare. |
| `internal/conntrack/source.go`, `record.go` | Source/event contracts, presence flags, limits, typed errors. |
| `internal/conntrack/source_linux.go`, `transport_linux.go`, `decode_linux.go` | ctnetlink receiver, bounded multipart dump/Get, typed decode. |
| `internal/conntrack/source_unsupported.go` | Non-Linux source trả unsupported rõ ràng, không giả dữ liệu runtime. |
| `internal/conntrack/cttest/fake.go` | Deterministic test source/clock/transport helpers dùng lại từ engine/session tests; production không import package này. |
| `internal/conntrack/testdata/` | Raw/synthetic binary fixtures NEW/UPDATE/DESTROY/NAT/IPv6/malformed; provenance ghi rõ. |
| `internal/session/lifecycle.go`, `indexes.go`, `query.go` | Merge state/counters, atomic indexes, pagination/filter. |
| `internal/connectivity/program.go`, `service.go`, `evaluate.go` | Shared immutable normalized L3/L4 semantics. |
| `internal/engine/runtime.go`, `tracking.go`, `resync.go` | Runtime M2, source/store orchestration, lost-event recovery. |
| `internal/engine/cache.go`, `invalidation.go`, `activation.go` | Cache CAS, explicit invalidation, engine-owned config coordinator. |
| `internal/engine/stats.go`, `runtime_events.go` | Atomic counters, bounded lifecycle ring/relay. |
| `internal/config/candidate.go`, `activation.go` | API-only candidate storage; prepared snapshot/version contract. |
| `internal/dataplane/mark.go`, `epoch.go`, `runtime_guards.go` | Layout masks, durable allocator, actual block/revoke/recheck. |
| `internal/engineipc/contracts.go`, `client.go`, `server.go` | Typed operations v2, RuntimeClient, dispatch độc lập session internals. |
| `internal/management/runtime_client.go` | Interface nhỏ để API test bằng fake IPC client. |
| `deploy/91-ngfw-conntrack.conf` | Accounting/events/timestamp config và documentation hỗ trợ kernel. |
| `configs/examples/m2-lab.json` | Topology M1 với chỉ policy L3/L4 và M2 resource limits. |
| `docs/adr/0002-m2-runtime-and-cache.md` | Quyết định cuối cùng sau spike, mark ABI, failure/recovery protocol. |
| `tests/integration/m2/README.md` | Kịch bản A–J và extension cases, exact commands/evidence. |
| `scripts/verify-m2-linux.sh` | Non-traffic checks có cấu trúc, export evidence; không tự claim traffic PASS. |
| `docs/m2-acceptance-matrix.md` | Yêu cầu → module → unit → Linux scenario → evidence/status. |
| `_test.go` cạnh mỗi module mới | Các test trong F; test Linux raw source có build tag phù hợp. |

Dependency hướng: domain/flow ← connectivity/session/conntrack contracts ←
engine runtime. Package engineipc chỉ dùng DTOs và service interface; server
không import concrete engine/session/dataplane. `cmd/ngfw-engine` inject runtime
vào interface của IPC server. Cách này cần được giữ cả khi client/server cùng
package, vì Go build toàn package, không chỉ file client. API chỉ import
contracts/client/domain/config candidate; không kéo runtime engine/dataplane/
production conntrack vào qua transitive dependencies.

## D. Data model changes

### D.1. Session và các trường bắt buộc

| Nhóm | Fields / quy ước |
|---|---|
| Identity | `id` (SessionID), optional `conntrack_id`, `netns_id`, `conntrack_zone`, `kernel_boot_id`, optional `kernel_start`, `identity_confidence`. |
| Transport | `ip_family`, `protocol` numeric + JSON name, `original_tuple`, optional `reply_tuple`, optional `translated_tuple`, `nat`. |
| Zone | `source_zone`, `destination_zone`, `zone_status=KERNEL_MARK/UNAVAILABLE`, `zone_epoch`. |
| Lifecycle | `state=NEW/ESTABLISHED/CLOSING/CLOSED`, optional raw `tcp_state`, `close_reason`. |
| Time | `created_at`, `created_at_source=KERNEL/OBSERVED`, `last_seen`, `last_observed_at`, optional `expires_at`, `closed_at`. |
| Counters | `packets_original`, `bytes_original`, `packets_reply`, `bytes_reply`, `counters_available`, observed timestamp. |
| Connectivity | `matched_policy_id`, `policy_generation`, `decision`, `decision_generation`, `decision_reason`, `evaluation_status`. |
| Cache | `cache_state=NOT_EVALUATED/CACHED/INVALIDATED`, `invalidated_at`, `invalidation_reason`, `kernel_epoch`, `kernel_mark`, `kernel_cache_verified`. |
| Enforcement | `effective_decision`, `enforcement_status`, `revoked`, `block_id`; phân biệt với connectivity decision trước block. |
| Concurrency/quality | `revision`, `tracking_status=COMPLETE/PARTIAL/STALE`, missing fields/reason, last resync ID. |

NAT object chứa `original_tuple`, `reply_tuple`, `translated_tuple`, `snat`,
`dnat`, `source_translation_method`, optional `matched_nat_rule_id`, evidence
generation, pre/post source và destination endpoint. Các endpoint dư thừa là
derived serialization, không lưu nhiều bản có thể lệch nhau.

`decision` không known dùng null/UNKNOWN kèm evaluation status; không dùng ALLOW
zero value. `effective_decision` phản ánh block/revoke cao hơn connectivity rule.
Lifecycle CLOSED là tình trạng connection/tracking, không đồng nghĩa decision DROP.

### D.2. Store structure và interfaces

```text
byID:             SessionID -> immutable/current session record
byConntrack:      ScopedConntrackID -> bounded identity candidates
byOriginal:       ScopedTuple -> identity candidates
byReply:          ScopedTuple -> identity candidates
byAlias:          ScopedTuple -> identity candidates
aliasesBySession: SessionID -> fixed/bounded key list
closedRing / tombstones: bounded, có TTL
```

`ApplyConntrack(record)`, `Close(identity)`, `Resolve(tuple, identityHint)`,
`Get(id)`, `Query(filter,page)`, `Invalidate(selector)`, `Cleanup(clock,budget)`
đều có unit contracts. Update indexed tuple phải remove old keys rồi thêm new
keys trong cùng lock; deletion chỉ đi qua key list của session, không quét toàn
bộ store. Trả read snapshots, không leak map/slice có thể mutate từ caller.

### D.3. Compatibility/migration

- Old JSON `id/client_ip/client_port/server_ip/server_port/protocol/start_time`
  giữ qua DTO derive từ O và CreatedAt. `packets_up/down` chỉ compatibility alias
  của original/reply; không tạo counters độc lập.
- `PolicyVersion` legacy map sang generation; `DecisionVersion` legacy map
  DecisionGeneration. Booleans FastPathEligible/Invalidated là derived field.
- Không tạo một SecurityContext nặng cho mọi connection M2. Legacy tests/proxy
  có adapter riêng nếu cần; production M2 chỉ allocate fields trong scope.
- Đọc được running.json/applied snapshot M1 chưa có schema M2: migrate metadata,
  disable/rotate cache ở lần đầu, giữ config/version/previous. Backup file trước
  schema/ownership migration; lỗi migration không overwrite file gốc.
- Parent state dir thuộc root:ngfw, API chỉ ghi management subdirectory; running,
  epoch và activation journal thuộc engine. Installer không tiếp tục recursive
  chown mọi state file cho API user.

## E. Thứ tự triển khai – mỗi bước build/test được

Không bật production M2 khi chỉ mới có một nửa pipeline. Trong các bước chuyển
tiếp có thể dùng constructor/feature switch nội bộ; cuối milestone không được
để API tự fallback sang local session engine. Sau mỗi bước ghi file thay đổi và
command/output test vào implementation log, chưa đánh dấu VM acceptance.

### E0. Baseline và chốt kernel contract

**Input:** source hiện tại, plan này, Ubuntu 24.04 lab khi có sẵn.

- Lưu baseline M1 bằng Git commit/worktree nếu đã có Git; workspace audit hiện
  chưa có `.git`, vì vậy nếu chưa khởi tạo Git thì dùng source archive + checksum
  và test log. Không ghi đè source đang sửa của người dùng.
- Đọc lại audit A và chạy focused baseline cho config/dataplane/engineipc/
  management/session. Ghi đúng những test hiện có, không coi chúng là M2 coverage.
- Chốt dependency v0.5.1 bằng build spike; test cancel/ENOBUFS/presence detection
  và memory của streaming dump trước khi chọn wrapper API cụ thể.
- Trong network namespace lab tách biệt: kiểm chứng `ct original/reply` fields
  ở forward trước/sau NAT, ct mark bit masks, zone-pair dispatch, `RELATED` ICMP,
  exact-flow guard keys, và first packet bị drop có/không có CT event.
- Ghi kernel version, `nft --version`, dependency versions và raw trace trong ADR.
  Nếu chưa có VM, ghi spike PENDING; vẫn có thể code model/fakes, nhưng không
  tuyên bố kernel contract đã kiểm chứng hoặc M2 completed.

**Exit:** baseline có thể tái chạy; mark ABI và assumptions ghi rõ. Nếu kernel
không hỗ trợ cú pháp đã chọn, sửa ADR/compiler representation trong phạm vi M2,
không đổi sang NFQUEUE mà không phân tích latency/overflow/order.

### E1. Contracts và model tương thích

- Thêm Tuple/Identity/NAT/Session enums, DTOs, RuntimeClient interfaces và limits.
- Giữ alias/adapters để legacy packages build; chưa wire detector vào runtime.
- Thêm schema migration tests đọc running.json M1; JSON roundtrip/null fields.

**Verify:** unit domain/flow foundations; `go test -run '^$' ./...` compile mọi
package/test; Linux cross-build engine/api. Chưa đổi packet path.

### E2. SessionStore và NAT mapping

- Implement typed indexes, immutable snapshots, atomic upsert/delete, lifecycle,
  close ring/tombstones, bounded query/cleanup.
- Implement SNAT/DNAT/double-NAT alias mapping với direction và identity hint.
- Counter merge presence-aware; không cộng trùng snapshot.

**Verify:** F01–F09, F15–F18 và phần store merge của F25–F26; race test session store. Assert indexes
không giữ dangling SessionID và size không vượt budgets sau churn/capacity.
Orchestration restart/resync của F25–F26 được hoàn thiện ở E7 sau khi có runtime.

### E3. Linux conntrack adapter

- Implement typed source/fake, binary decoder, streaming dump/Get/event reader.
- Bounded cancellation, sender/length/family/sequence checks, loss notification.
- Không đưa `ip`/`conntrack` text parsing vào session core.

**Verify:** binary fixtures NEW/UPDATE/DESTROY + missing attrs; truncated netlink
frame; socket close/cancel; dump incomplete; Linux package tests/race trong Linux
khi có runner. Windows compile bằng unsupported source, không skip fake tests.

### E4. Shared connectivity program

- Parse services/address/zone matcher một lần, share giữa compiler và evaluator.
- Preserve NAT render semantics/priority M1; normalize forward view và reverse
  evaluation; reject active unsupported predicates rõ ràng.
- Keep `CompileRuleset(config)` facade nếu giúp giữ M1 tests; production dùng
  explicit compile options chứa activation metadata.

**Verify:** F10–F12, F27; M1 compiler/reconciler/validator regression. Golden
fixture có TCP range, OR, DNAT 8443→443 và default allow/deny.

### E5. Runtime owner, generation và activation coordinator

- Add Runtime M2 và immutable RuntimeSnapshot; engine owns running config.
- Split config manager lock; implement engine-side commit/rollback prepare/apply/
  persist/publish, journal metadata và operation receipt.
- Add IPC v2 config operations; chuyển API commit/rollback/config reads sang
  client, candidate persistence tách riêng. Không còn API ghi running.json.
- Durable epoch allocator có exhaustion/failure tests; startup recovery giữ M1
  network reconciler và previous config behavior.

**Verify:** F13, F20, F30–F33; concurrent commit/version conflict; injected failures
ở network/nft/persist/recovery; rollback số generation tăng. Query không đợi
session lock khi fake network apply bị giữ chậm.

### E6. Kernel fast path và runtime guards

- Implement mark layout, zone-pair dispatch, guarded cache hit/miss và normalized
  slow rules cho cả hai direction.
- Tạo runtime table/sets với block/revoke/recheck trước cached accept; giữ NAT
  chains và DNAT zone guard của M1.
- Serialize runtime guards với activation; rollback không xóa block vừa thêm.
- Define safe no-cache mode cho epoch uncertainty/exhaustion; không có code path
  quay lại unconditional established accept của M1 trong mode M2.

**Verify:** F14, F19, F28–F31; compiler ordering test, low bits preserved,
default allow still guarded, stale reply sau ALLOW→DROP, IPv4 NAT fixtures.
Trên VM dùng `nft -c` và namespace smoke test; nếu chưa chạy ghi rõ pending.

### E7. Event ingestion, cache và invalidation/recovery

- Wire source→lifecycle merge→EvaluateConnectivity→cache→lifecycle events.
- Implement subscription-before-dump, bounded replay, lost event handling,
  cleanup/Get fairness, CAS against session/config/guard revisions.
- Implement triggers policy/zone/interface/route/NAT/revoke/block/recovery.
- Quota/telemetry errors không unwind M1 controller hoặc stop forwarding.

**Verify:** F03–F09, F13–F24, F28–F29; dùng fake clock/source không flaky sleeps.
Simulate DESTROY cùng commit/reevaluate, stale result ALLOW không thắng revoke.

### E8. Session API và bounded telemetry

- Bỏ local `engine.New` khỏi API main; bỏ `Engine *engine.Engine` trong management.
- List/Get/Stats/Health/DELETE/block handlers đọc/mutate qua RuntimeClient.
- Add pagination/filter/tuple view; read bounded event ring qua IPC cho existing
  events/ws/stats, không thiết kế UI mới.
- Return engine-down/timeout/operation-in-progress rõ ràng; preserve envelope
  và legacy tuple fields; auth/RBAC regression.

**Verify:** F21–F24, F26, F32–F34; start API test với fake client có dữ liệu trong
engine, chứng minh không có store API thứ hai. `go list -deps ./cmd/ngfw-api`
không chứa `internal/engine`, `internal/session`, `internal/dataplane` hoặc Linux
conntrack adapter (contracts được đặt để không kéo deps này vào client).

### E9. Packaging và tài liệu VM

- Add M2-only example, sysctl capability checks, service state permissions và
  installer migration có backup. API khởi động lại không reset sessions.
- Tạo ba artifacts bắt buộc ở G, OpenAPI và ADR. Đánh trạng thái từng row
  `NOT_RUN` cho tới khi có output thật; không copy M1 PASS sang M2.
- `verify-m2-linux.sh --collect DIR` chỉ inspect/export, không tự sửa ruleset,
  flush conntrack hoặc chạy flood traffic.

**Verify:** shell syntax (`bash -n`), unit schema load, systemd verify trên Linux;
installer re-run preserve config/version/epoch/dynamic runtime state.

### E10. Code-complete gate

Chạy test package thuộc M1/M2 và các race cases, không dùng test M3+ làm evidence:

```bash
go test -count=1 ./internal/domain ./internal/flow ./internal/conntrack \
  ./internal/session ./internal/connectivity ./internal/config ./internal/dataplane \
  ./internal/engineipc ./internal/management ./internal/events
go test -count=1 ./internal/engine -run '^TestM2'

go test -race -count=1 ./internal/flow ./internal/conntrack ./internal/session \
  ./internal/connectivity ./internal/config ./internal/dataplane \
  ./internal/engineipc ./internal/management ./internal/events
go test -race -count=1 ./internal/engine -run '^TestM2'

go vet ./cmd/ngfw-engine ./cmd/ngfw-api ./internal/domain ./internal/flow \
  ./internal/conntrack ./internal/session ./internal/connectivity \
  ./internal/config ./internal/dataplane ./internal/engine ./internal/engineipc \
  ./internal/management ./internal/events
go test -run '^$' ./...
GOOS=linux GOARCH=amd64 go build ./cmd/ngfw-engine ./cmd/ngfw-api
```

Unit test M2 trong engine đặt prefix `TestM2` để tách khỏi thử nghiệm risk/IDS
legacy. Linux source/decoder tests phải chạy trên Linux CI/runner với race,
không thay bằng Windows `!linux` stub PASS. Các test root/network thật nằm ở G.
Không cần quyền NET_ADMIN cho fake transport tests trên Linux.

**Exit:** tất cả I.4 đạt, lưu log và limitation thực tế. Nếu thiếu Linux unit
runner/race result thì chỉ báo tiến độ code, không ghi code-complete đã kiểm chứng.

### E11. Ubuntu VM acceptance

Chạy lại M1 baseline và M2 G theo topology cùng NIC/IP, cùng config revision.
Lưu output/pcap/timestamp/raw JSON. Fix case fail trong M2 hoặc blocker M1 tối
thiểu có reproduction. Chưa có VM/evidence thì dừng ở trạng thái ready for VM,
không dựng kết quả giả và không tự mở rộng sang M3.

## F. Unit test matrix bắt buộc

Mỗi row có assertion về kết quả quan sát được; không chỉ kiểm tra constructor
trả non-nil hoặc so string render với chính helper đã tạo ra string đó.

| ID | Test / file dự kiến | Assertion chính |
|---|---|---|
| F01 | `flow/tuple_test.go`: canonicalization | IPv4/IPv6 normalized, protocol numeric, family mismatch rejected; canonical deterministic, binary key không collision. |
| F02 | `flow/tuple_test.go`: directions/ICMP | O và reverse resolve cùng flow nhưng direction khác; ICMP ID/type/code phân biệt hai ping cùng endpoints. |
| F03 | `session/lifecycle_test.go`: NEW | Tạo đúng một session, state từ kernel, populate O/R, optional CT ID. |
| F04 | UPDATE | NEW→UPDATE giữ ID; missing attrs không zero metadata; repeated absolute counters không double-count. |
| F05 | DESTROY | Close đúng incarnation, gỡ mọi live index, emit SessionClosed một lần; bounded closed detail. |
| F06 | Bidirectional | Interleaved requests/replies tạo một ID, original-role không bị đảo theo packet đầu receiver thấy. |
| F07 | `flow/nat_test.go`: SNAT | O/T/R và reverse aliases map cùng ID; translated source port lấy từ R. |
| F08 | MASQUERADE | Port rewrite giống SNAT; thiếu rule evidence không tự khẳng định phương thức MASQUERADE. |
| F09 | DNAT/double NAT | Public 8443 và DMZ 443 cùng session; intermediate forward tuple đúng; UPDATE loại old aliases không còn hợp lệ. |
| F10 | `connectivity/evaluate_test.go`: priority/default | First-match theo priority; default deny/allow; duplicate priority invalid; disabled rule bỏ qua. |
| F11 | Matcher truth table | OR trong field, AND giữa field; multiple zones/CIDRs/services, wildcard, port range, case normalization thống nhất. |
| F12 | NAT policy view | Public tuple khác forward view; evaluator/kernel IR đều match server port/address sau DNAT; reply dùng same policy. |
| F13 | `engine/cache_test.go`: cache/generation | Cache reused khi hợp lệ; mismatch generation/epoch làm INVALIDATED và current reevaluation; pending result cũ bị discard. |
| F14 | `dataplane/mark_test.go` | Pack/unpack đúng masks; preserve low 8 bits; stale/unknown epoch không hit; wrong zone pair không hit; khi không sở hữu mark thì không đọc để accept hoặc ghi/clear mark. |
| F15 | `session/store_test.go`: cleanup | Idle valid TCP không bị xóa theo thiếu UPDATE; stale confirmed absent được cleanup; orphan indexes bằng 0. |
| F16 | Capacity | Insert vượt max tăng tracking_drops; existing sessions cập nhật được; không gọi flush/drop firewall. |
| F17 | Reuse/collision | Same 5-tuple new CT incarnation không merge old; scoped CT ID collision/namespace isolation; alias ambiguity trả lỗi rõ. |
| F18 | Deep copy/index consistency | Caller đổi DTO không sửa store; alias replacement atomic; close ring/tombstone/map capacities bounded sau churn. |
| F19 | `engine/invalidation_test.go`: block precedence | Cached ALLOW + source block → effective DROP; nft mutation fail không ACK; TTL removal bỏ block đúng lúc. |
| F20 | `config/activation_test.go`: generation | Commit G→G+1; explicit rollback →G+2; persist fail không publish success; previous config được giữ. |
| F21 | `engineipc/sessions_test.go`: list/get/stats | Round-trip server/client đọc đúng engine store, NAT fields nguyên vẹn; missing ID NOT_FOUND. |
| F22 | `management/sessions_test.go`: pagination | Default size, max size, filter từng field/kết hợp, sort/cursor, tuple_view, invalid query; response không vượt bound. |
| F23 | IPC failures | Dial/read timeout, cancel, wrong version, oversized req/resp, full queue, client không đọc response; không leak goroutine. |
| F24 | API owner outage | Engine unavailable trả 503; không local fallback; API restart reconnect đọc cùng SessionIDs còn ở engine. |
| F25 | `engine/resync_test.go`: restart | Existing kernel records + duplicate buffered NEW không tạo duplicate; old marks untrusted; resync stats đúng. |
| F26 | Lost/delayed events | UPDATE trước NEW, DESTROY trễ, dump cũ sau DESTROY, ENOBUFS, partial dump; không sweep healthy table hoặc hồi sinh old incarnation. |
| F27 | Compiler/evaluator parity | Expected truth table độc lập cho new/reply/NAT/ranges/default; compare shared IR/evaluator và rendered selectors. |
| F28 | Chain order | invalid/block/revoke đứng trước cache; không còn unconditional established/related accept; no flowtable. |
| F29 | Concurrent operations | NEW/UPDATE/DESTROY + List/Get + cleanup + commit + block; race detector sạch; stale ALLOW không overwrite invalidation. |
| F30 | Epoch persistence/recovery | Crash sau reserve token không reuse; same boot rotate; corrupted/missing state disable cache; overflow không wrap. |
| F31 | Activation guard preservation | Block/revoke set còn sau commit/failed commit/rollback/restart; compensation fresh epoch chứ không restore attempted mark. |
| F32 | Events/backpressure | Đủ năm lifecycle event; ID/timestamp/sequence; subscriber/queue đầy tăng dropped, ingestion vẫn tiến; gap được báo. |
| F33 | Idempotency | Timeout sau successful apply rồi retry same operation ID chỉ một committed generation; unknown outcome không trả success giả. |
| F34 | Ownership/legacy compatibility | API deps không runtime/dataplane; old envelope fields derive đúng; existing RBAC/auth/M1 rollback test còn pass. |
| F35 | `conntrack/decode_linux_test.go` | Binary endianness, optional attrs, malformed lengths, ICMP, IPv6, multipart end/error/truncation/cancel; no real NET_ADMIN required. |
| F36 | Revoke versus reevaluate | Revoke giữ guard khi engine down; targeted recheck không được biến thành revoke hoặc grant ALLOW trước fence ACK. |
| F37 | Tracking versus forwarding health | Source/telemetry fail không gọi controller flush/reapply ngẫu nhiên; kernel cache distrust chọn full-policy fallback. |
| F38 | M1 migration | Load prior running/applied snapshot và API-owned files; preserve version/previous/NAT; interrupted migration recover từ backup. |

Race workload phải kiểm tra invariant sau khi quiescent: mỗi live connection có
một record, mỗi index trỏ một record hợp lệ hoặc explicit ambiguity, generation
không giảm, no phantom session sau DESTROY. Không chỉ chạy race trên single-thread
test rồi ghi “concurrency đã được chứng minh”.

## G. Linux integration test matrix và artifacts

### G.1. Files phải bàn giao khi code M2

1. `tests/integration/m2/README.md`: prereqs, NIC mapping, commands từng host,
   expected result, cleanup/restore, evidence paths cho từng scenario.
2. `scripts/verify-m2-linux.sh`: kiểm tra root/Linux/tools; health/source sync;
   sysctl accounting/events/timestamp; API capability boundary; tables/hook order;
   current generation/epoch; pagination limit; không có flowtable. Báo PASS/FAIL/
   SKIP tách biệt, exit nonzero khi required check fail. Thiếu token/endpoint phải
   nói rõ check API chưa chạy, không coi là PASS.
3. `docs/m2-acceptance-matrix.md`: mỗi requirement ID ở I.1 có module/unit/VM
   evidence và trạng thái `NOT_RUN/FAIL/PASS/BLOCKED`. Giữ cột code readiness riêng.

Script default chỉ inspect; `--collect DIR` lưu evidence với mode phù hợp,
không in token trong command log, không tự `conntrack -F` hoặc `nft flush ruleset`.
Traffic generation là bước có chủ ý trong README trên lab, tách với máy production.
Nếu dùng `iperf3`/Python/netcat làm generator phải ghi package cần cài trên từng
host; M2 installer appliance không cần cài detector/security tooling.

### G.2. Topology và đo lường

Giữ bốn zone của M1; tất cả host có clock/timestamp đủ đối chiếu. Example values:
appliance WAN `192.0.2.2`, LAN `192.168.10.1`, DMZ `10.20.0.1`; LAN client
`192.168.10.10`, DMZ server `10.20.0.10`, WAN test host `203.0.113.10` hoặc subnet
routed thực tế. NIC names/gateway phải lấy từ VM, không hardcode eth0 cho mọi máy.
MGMT riêng để commit/collect evidence không đi cùng flow đang revoke.

Forwarded test traffic dùng unique source port/run ID; exclude SSH/API/local
appliance connections khi đếm. API có thể track local CT với zones unavailable,
nhưng không gán chúng vào LAN→WAN để khớp expected count.

Session query eventual-consistent: poll có deadline 5 giây ở lab bình thường;
resync recovery tối đa một successful 30-second resync + processing budget.
Đây là acceptance bounds ban đầu, phải báo observed latency và cấu hình khi fail,
không phải SLA throughput. Kernel revocation có hiệu lực với packet đi qua hook
sau nft commit ACK; không hứa thu hồi bytes đã gửi hoặc packet đã qua hook trước đó.

### G.3. Matrix A–J bắt buộc

| Case | Setup / thao tác | Điều kiện PASS | Evidence tối thiểu |
|---|---|---|---|
| A – LAN→WAN | Route-only TCP allow; WAN host có route trả về LAN. Tạo một connection xác định. | API có đúng O/src port/destination/protocol và zone; cache/policy generation phản ánh kernel. | Config, conntrack JSON/text extended, API detail, nft counters. |
| B – MASQUERADE | Bật M1 LAN MASQUERADE, tạo connection mới. | Một SessionID có O private và T public/translated port đúng tcpdump/CT R; reverse lookup cùng ID. | Capture hai NIC, CT O/R, API NAT object. |
| C – DNAT | WAN→public 8443→DMZ 443 với đúng allow rule cho forward view. | Public tuple và DMZ tuple trong một session; reply đúng; matched policy không nhầm public port. | nft NAT/filter, capture WAN/DMZ, CT dump, API. |
| D – Bidirectional | Gửi nhiều request/response trên connection B/C. | Một live identity/ID, original/reply counters tăng đúng chiều; không có hai records. | Hai thời điểm stats/detail, CT counters, flow-specific list. |
| E – Lifecycle | Giữ TCP đủ lâu thấy handshake, established, FIN/TIME_WAIT rồi DESTROY; thêm UDP/ICMP echo. | State đúng kernel; CLOSED event/detail trong retention; indexes mất sau cleanup. | `conntrack -E`, engine lifecycle log/events, API timeline. |
| F – ALLOW→DROP | Long-lived TCP truyền frame có sequence; commit DROP; thử original và reply traffic. | ACK version mới; cache cũ invalid; không có frame mới gửi sau ACK đi qua old cached ALLOW. Rollback có version cao hơn và policy restored. | Commit response/time, nft cache/slow/drop counters, sequenced receiver log, pcap. |
| G – Temporary block | Established ALLOW; block original source; giữ engine/API stop lần lượt; đợi TTL. | Packet hai chiều bị block sau ACK dù mark ALLOW còn; guard còn khi management down; TTL kernel hoạt động; commit/rollback không xóa block. | Block response/list TTL, ruleset, CT mark, pcap, server log. |
| H – Engine restart | Giữ flows SNAT/DNAT và cached marks; restart engine, kể cả giữa activation với fault injection. | Epoch mới/disabled cache; no duplicate current records; kernel NAT bindings còn; last known-good recovery đúng, no stale ALLOW. | Before/after running/epoch/journal, CT dump, detail IDs/quality, logs. |
| I – Concurrent flows | Tạo 1.000 flows rồi tăng tới configured tracking limit trong giới hạn lab; mix directions/NAT. | Count theo distinct live CT identities; index consistency; tracking capacity không crash firewall; stable memory qua cleanup. | Workload params, CT count, engine metrics, RSS samples, API counts. |
| J – API | Dataset quiescent với nhiều protocol/zone/decision; query mọi filter, nhiều page, invalid params; API restart. | No duplicate page items trên stable dataset, filter đúng tuple_view; ≤500/page, bounded bytes; reads thật từ engine và 503 khi disconnected. | Raw HTTP requests/responses, IPC diagnostics, api PID/capabilities. |

Case A đo không NAT để tách lỗi route khỏi NAT; case B/C dùng connection mới
để NAT rules có hiệu lực. Không dùng `curl` tự mở connection khác rồi cho rằng
đã kiểm tra re-evaluation của long-lived connection cũ.

### G.4. Cases bổ sung để chốt invariants

| Case | Nội dung / tiêu chí |
|---|---|
| K1 – Tracking loss | Force bounded queue overflow hoặc ngắt receiver; degraded + resync counters tăng; no mass-close từ partial dump; traffic vẫn qua kernel. |
| K2 – Manual revoke | DELETE session thật; original/reply bị drop; engine dừng không làm guard tự hết và mở lại flow; không tuyên bố TCP RST. |
| K3 – Counter freshness | Idle TCP không có UPDATE vẫn tồn tại đúng timeout; counters không cộng trùng sau nhiều resync; missing counters là unavailable. |
| K4 – Zone/NAT change | Đổi interface-zone/route/NAT target; epoch đổi, old binding được giữ cho old flow; new connection dùng NAT mới; policy dựa actual post-NAT tuple. |
| K5 – Port range/OR parity | Multiple CIDRs/zones/services/ranges với positive/negative inputs; runtime matched rule và kernel packet result thống nhất. |
| K6 – Epoch/mark errors | Inject stale epoch, wrong zone pair, low user bits; không cache-hit sai, low bits được giữ. Exhaustion giả lập → safe full policy, không modulo. |
| K7 – Management/telemetry outage | Stop API/UI hoặc slow event consumer; M1 forwarding/NAT tiếp tục; drops observable và API reconnect đọc runtime thật. |
| K8 – M1 regression | VLAN create/delete, address/route removal, MTU, SNAT/MASQ/DNAT priority, default deny, failed activation restore, explicit rollback. |
| K9 – RELATED/PMTU | ICMP errors liên quan flow allowed còn đi đúng policy; sau DROP/block không dùng related accept bypass; helper-created flow không tự allow. |
| K10 – Linux adapter/resources | So sánh NEW/dump/endian ICMP/NAT fixtures với kernel; large dump cap/cancel không leak socket/RAM; service CAP_NET_ADMIN boundary đúng. |
| K11 – Conditional IPv6 | Chỉ tracking non-NAT/identity khi có fixture/lab IPv6; không tự bật IPv6 forwarding để làm test này PASS. Nếu chưa có profile dual-stack ghi đúng phạm vi SKIP. |
| K12 – Guard persistence | Thêm block/revoke, commit thành công/lỗi/rollback, engine SIGKILL/restart; table runtime giữ protection, remaining TTL block không bị reset. |

### G.5. Evidence layout

```text
evidence/m2/<run-id>/
  manifest.json          # timestamp, source hash, VM/kernel/nft/Go versions, topology
  config/                # running + versions + nonsecret test config
  commands.log           # redact bearer token/password
  A/ ... J/ K1/ ...      # stdout/stderr, exit code, assertion result
  conntrack/             # events and before/after dumps
  nft/                   # ruleset/counters/current cache epoch
  api/                   # list/detail/stats/commit/block responses
  engine/                # journal, health, resync/invalidation metrics
  pcap/                  # khi scenario cần đối chiếu đường packet
  results.json           # từng case NOT_RUN/FAIL/PASS/SKIP và reason
```

Không lấy test log cũ, JSON fixture hoặc Unit PASS làm packet evidence. Matrix
phải link tới file raw có timestamp/source hash của đúng lần chạy.

## H. Rủi ro và cách kiểm soát

| Rủi ro | Hậu quả nếu bỏ qua | Thiết kế / kiểm thử kiểm soát |
|---|---|---|
| Conntrack event bất đồng bộ/không đầy đủ | Cho rằng đã chặn packet chỉ vì runtime đánh giá DROP sau event. | Kernel verdict trước; event là tracking; expose predicted/effective/verified riêng; F/K capture. |
| Dump multipart gom RAM | Một resync vượt RAM dù SessionStore đã có max. | Bounded datagram streaming, raw bytes/records/time cap; F35/K10. |
| Lost/reordered event, ID/tuple reuse | Duplicate session, DESTROY xóa connection mới, stale session sống mãi. | Scoped identity, start timestamp, tombstones, Get xác minh, partial dump không sweep; F17/F26. |
| SNAT/DNAT và reply normalization | API hiện tuple sai; response của flow allowed bị default deny sau commit. | O/R/T/P rõ ràng; CT fields và two-direction fixtures; B/C/F/K4. |
| Security zone không có trong conntrack | Sai policy do đoán zone theo IP. | Kernel mark có epoch+zone pair từ actual interfaces; stale/unknown zone không coi là verified. |
| Mark bits collision/epoch wrap | Cached ALLOW từ policy cũ được dùng lại. | Reserved mask/owner contract, preserve low bits, durable no-reuse allocator, safe no-cache khi hết token; F14/F30/K6. |
| Rule-set/table mutation thứ tự sai | Hard block/revoke bị bypass hoặc mất khi rollback. | Runtime guard table riêng trước cache; serializer và preservation tests; G/K12. |
| Generation desync API↔engine↔kernel | API báo version mới nhưng engine evaluate config cũ. | One running writer, typed activation metadata, ACK after durable publish, operation receipts; F20/F33/H. |
| Config lock giữ network I/O | Queries/tracking đứng theo nft/ip timeout. | Activation serialization riêng, immutable snapshot, store locks ngắn; controlled slow-adapter race tests. |
| Concurrent result ALLOW cũ | Result chạy chậm ghi đè invalidate/DROP mới. | Revision+generation+epoch+guard CAS, reject stale publish; F29. |
| Policy/compiler semantic drift | Rule range/OR/zone/NAT cho kết quả khác nhau giữa API và kernel. | Shared normalized Program + independent truth table + packet integration; F11/F27/K5. |
| Dynamic revoke TTL | Flow bị revoke tự mở lại khi engine down. | Revoke guard không tự expire khi entry còn sống; bounded GC bằng identity; K2/K12. |
| Migration running state/permissions | API còn sửa authoritative files hoặc service không đọc được snapshot. | Backup + ownership migration, API writes management only, installer re-run tests; F38/K8. |
| Established RELATED tương thích | Blanket allow tạo bypass; blanket drop phá PMTU. | Narrow ICMP related path + tests, không implicit helper allow; K9. |
| Tests Windows che lỗi Linux | Stub pass nhưng netlink decoder/IPC/kernel statements chưa chạy. | Linux unit/race build target riêng; Ubuntu acceptance bắt buộc, không đổi nhãn pending thành pass. |

Nếu spike phát hiện blocker kernel/mark syntax không giải quyết được bằng
representation hiện tại: ghi reproduction/evidence trong ADR, chọn safe
kernel-only fallback trong phạm vi M2 và cập nhật kế hoạch. Không tự mở thêm DPI,
NFQUEUE inspection, eBPF dataplane hoặc redesign UI để vòng qua blocker.

## I. Compatibility M1, traceability và Definition of Done

### I.1. Map yêu cầu người dùng → plan → verification

| Yêu cầu | Phần thiết kế | Verification |
|---|---|---|
| 1 – Architecture | A, B.1, C | F24/F34, K7 |
| 2 – Session model | B.3–B.4, D | F01–F09/F18 |
| 3 – Conntrack adapter | B.2/B.4 | F25/F26/F35, K1/K10 |
| 4 – Store | B.10–B.11, D.2 | F15–F18/F29, I |
| 5 – Normalized flow | B.3, D.1 | F01/F02/F17, conditional K11 |
| 6 – NAT tracking | B.3/B.5 | F07–F09/F12, B/C |
| 7 – Policy | B.5 | F10–F12/F27, K5 |
| 8 – Policy generation | B.7 | F13/F20/F33, F/H |
| 9 – Decision cache | B.10 | F13/F29, F/G |
| 10 – Kernel fast path | B.6/B.8 | F14/F28/F30, F/K6 |
| 11 – Chain invariant | B.9 | F19/F28/F31, G/K12 |
| 12 – Invalidation | B.9–B.10 | F13/F19/F29/F36, F/G/K2/K4 |
| 13 – Restart/recovery | B.4/B.8 | F25/F26/F30, H |
| 14 – Ownership/IPC | B.1/B.7/B.12 | F21/F23/F24/F34, J/K7 |
| 15 – Session API | B.12 | F21/F22, J |
| 16 – Events/telemetry | B.11–B.12 | F32/F37, E/K7 |
| 17 – Concurrency | B.10, E10 | F29 + race logs, I |
| 18 – Failure behavior | B.8/B.11 | F16/F23/F30/F37, H/I/K1/K7 |
| 19 – Unit tests | F | Tất cả F rows + E10 command logs |
| 20 – Integration | G | A–J + applicable K cases |
| 21 – DoD | I.4 | Code log khác VM acceptance evidence |
| 22 – Non-goals | Mở đầu, A.2, C | Changed-file/dependency review |
| 23 – Output plan A–I | Toàn tài liệu | Audit evidence, decisions, inventory, staged verification |

### I.2. Những gì giữ từ M1 và bằng chứng cần có

| M1 behavior | Cam kết compatibility | Chứng minh |
|---|---|---|
| Linux route/interface/VLAN/MTU | Reuse NetworkReconciler, không chuyển userspace. | Existing tests + cùng scenarios M1 trước/sau M2. |
| Stateful routing/NAT | Conntrack vẫn sở hữu translation và TCP state. | LAN→WAN, WAN→DMZ, replies, O/R binding giữ qua restart. |
| NAT update | Default chỉ new connection nhận NAT config mới. | Old flow giữ binding; new flow target mới; không global conntrack flush. |
| Atomic firewall replacement | Giữ validation/apply transaction cho policy table. | `nft -c`, injected apply fail và ruleset readback. |
| Rollback | Restore old network/policy content; running version vẫn tiến. | Existing rollback tests, fresh epoch, runtime blocks không mất. |
| Startup reconcile | Running config durable áp xuống kernel; thêm cache recovery. | M1 restart scenario + H, không reset counters/session bằng local API. |
| Privilege boundary | API không CAP_NET_ADMIN, engine là network writer. | Unit service/dependency assertions + `/proc/<pid>/status` trên VM. |
| Management outage | Kernel forwarding/NAT không phụ thuộc API/UI/telemetry. | Long-lived flow khi stop từng process, K7. |

M2 chủ ý thay một hành vi: established flow không còn được ALLOW vô điều kiện
sau policy change. Đây là yêu cầu thu hồi policy của M2; thay đổi phải đo trên
case F và giữ return traffic của policy vẫn ALLOW hoạt động đúng. Không gọi
packet loss do return-direction bug là “bảo mật hơn” để bỏ qua regression.

### I.3. Điểm kiểm tra trước khi agent kết thúc

- Không còn constructor session engine trong API startup hoặc fallback ở query.
- Không còn production flow path qua Risk/IDS/ML/Application evaluator.
- Không còn unconditional established/related accept trong M2 active compiler.
- Mọi mutation block/revoke/commit có kernel result thật, không chỉ Memory update.
- Mọi generation/epoch/file-schema transition có recovery và bounded failure path.
- Không có `conntrack -F`, `nft flush ruleset`, offload, API CAP_NET_ADMIN hoặc
  toàn bộ session list trong response như shortcut triển khai.
- Chỉ thay M1 network implementation nếu có regression/blocker tái hiện được.

### I.4. Hai mức hoàn thành phải báo tách biệt

**Được ghi “M2 code complete, ready for VM acceptance” chỉ khi:**

- Session lifecycle, typed tuples, scoped identity, NAT aliases và indexes đã
  implement; one connection = one live session với ambiguity được biểu diễn rõ.
- Conntrack Linux adapter thật, startup/lost-event bounded resync, cleanup,
  max session/index/queue/response limits đã implement.
- Shared L3/L4 matcher/compiler, monotonic policy generation, decision cache,
  explicit invalidation và ct-mark fast path có code thật.
- Chain invariant, dynamic blocks/revoke thật, generation change/restart không
  trust stale ALLOW; safe fallback không phụ thuộc userspace packet verdict.
- Engine sở hữu runtime/running authority; API query qua IPC v2; pagination,
  filter, NAT detail và bounded stats/events chạy với integration fake client.
- Unit matrix F đã thực hiện với failures được xử lý; focused tests, Linux
  fake-source race tests và go vet trong E10 pass; Linux cross-build pass.
- Ba artifacts M2, OpenAPI, ADR, migration/installer và M1 regression tests đầy
  đủ; VM cases chưa chạy còn ghi NOT_RUN. Known blocking bug không được giấu dưới
  nhãn limitation để ghi code complete.

**Được ghi “M2 completed” chỉ khi:** toàn bộ A–J, applicable K cases và M1
regression trên Ubuntu VM có evidence PASS, mọi SKIP có scope condition hợp lệ
(ví dụ IPv6 chưa thuộc profile hỗ trợ), không có blocker trong phạm vi M2.

Source hiện đã có implementation M2 tương ứng với các module được liệt kê ở
ma trận `docs/m2-acceptance-matrix.md`; các hàng packet-path vẫn `NOT_RUN` cho
đến khi chạy trên Ubuntu VM. Tài liệu này vẫn là kế hoạch chuẩn để review và
không thay thế bằng chứng nghiệm thu. Một điểm cần kiểm tra trên VM là cú pháp
kernel nft cho `ct mark`/runtime guard và giới hạn bộ nhớ của thư viện
ctnetlink khi dump lớn; nếu fail phải ghi evidence và sửa trước khi claim code
complete.

Implementation note: the E0-E11 modules described above are now present in the
workspace and the unit/race/static checks are maintained in the acceptance
matrix. This does not change the required Ubuntu VM packet-path acceptance.

Additional implementation note: a successful bounded conntrack resync now
reconciles the observed identity set and closes active sessions absent from the
kernel dump, while preserving events observed after the dump began. On engine
startup the privileged nft adapter clears the conntrack-ID `revoked_ctids` set so a
reused conntrack ID cannot inherit an old revoke fence; timed source blocks are
left in the kernel runtime table. The nft command syntax and the behaviour of
large ctnetlink dumps still require Ubuntu VM evidence. The production M2
compiler rejects enabled application/profile/risk/request predicates and
renders `DefaultDeny=false` as an explicit final allow rule behind a drop
base-chain policy, keeping the guard-before-policy invariant.
