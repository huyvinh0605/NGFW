# M3 — Đặc tả code để agent triển khai

Ngày audit: 2026-09-22. Trạng thái: **SPECIFICATION READY; CHƯA TRIỂN KHAI M3**.

Đọc cùng [CODING_TASKS.md](m3/CODING_TASKS.md),
[CODE_CONTRACTS.md](m3/CODE_CONTRACTS.md),
[ma trận nghiệm thu](m3-acceptance-matrix.md) và
[hướng dẫn kiểm thử Linux](../tests/integration/m3/README.md).
Các tên file/hàm ghi là **mới** dưới đây là sản phẩm cần viết, không phải tính năng
đã tồn tại. Không lấy việc tài liệu có ví dụ code làm bằng chứng implementation.

Agent cần chỉ dẫn ngắn để vào việc: [START_HERE.md](m3/START_HERE.md).

## 0. Cách agent sử dụng bộ chỉ dẫn

1. Đọc phần 1–5 trước khi sửa code; đọc lại source ở các điểm tích hợp.
2. Thực hiện task T00 → T31 trong `m3/CODING_TASKS.md` đúng dependency.
3. Một task chỉ xong khi có implementation, test hành vi tương ứng, và kết quả
   lệnh thực tế. Ghi vào `docs/m3/IMPLEMENTATION_STATUS.md` khi bắt đầu code.
4. Không tự chọn kiến trúc khác khi khó triển khai. Nếu probe Linux bác bỏ một
   quyết định, lưu lệnh/output, đánh dấu task BLOCKED và sửa ADR/spec trước khi
   sửa phần phụ thuộc. Tiếp tục task độc lập được.
5. Không xóa test M1/M2 để làm xanh M3. Không mock kernel rồi báo IPS đã chạy.
6. Các giá trị mặc định trong tài liệu phải thành constant có test; không rải
   magic number. Không có yêu cầu nào bảo đảm phần mềm tuyệt đối không lỗi.
7. Chỉ báo `M3 CODE COMPLETE / VM ACCEPTANCE PENDING` sau checklist phần 19.
   Chỉ báo `M3 ACCEPTED` sau khi ma trận Linux có evidence thật.

## 1. Phạm vi đã chốt và quan hệ với roadmap

Tài liệu này cụ thể hóa `M3_AGENT_IMPLEMENTATION_MASTER_PLAN.txt` do người dùng
cung cấp, đồng thời thay thế **phạm vi M3 cũ** ở `PLAN.md`. Không thay mục tiêu
cuối cùng của dự án.

| Phần | Bắt buộc trong M3 |
|---|---|
| M3-A | App-ID HTTP, TLS, DNS, SSH, UNKNOWN; EVE alert/flow/http/dns/tls/ssh/stats; correlation NAT; IDS thụ động; API/WS/UI thật |
| M3-B | IPS DROP qua NFQUEUE; chọn inspection theo policy; application restriction trên ALLOW; invalidation; recovery; packaging/tests |
| Chuẩn bị để nghiệm thu | Fixture, script, ma trận và raw evidence format cho cả hai phần |
| Bổ sung sau lõi | SMTP/FTP enrichment nếu fixture + sensor chứng minh; không là điều kiện đóng MVP |

ICMP được hiển thị là network protocol đã quan sát, không gọi là DPI/App-ID L7.
IPv4 là phạm vi enforcement/NAT acceptance; giữ model IPv6, không bật thêm IPv6
forwarding. Không có TLS decryption, HTTP request gate, WAF, URL filtering,
TI, scan/DoS detector, ML, Risk Engine, nDPI, flowtable offload, UI redesign,
HA, tự cập nhật rules qua Internet hoặc quản lý custom rules từ UI trong M3.
Các hạng mục URL/TI/behavior/nDPI của roadmap cũ được **hoãn**, không tự coi như
đã hoàn thành. HTTP/2 request/stream gate vẫn thuộc M4.

M1/M2 hiện có implementation nhưng chưa có xác nhận acceptance Ubuntu VM trong
lượt audit này. Có thể viết/test logic M3 ngay. Trước kiểm thử IPS traffic phải
chạy baseline M1/M2 trên cùng topology; lỗi nền tảng phải được tách evidence.

## 2. Audit source hiện tại và ranh giới tái sử dụng

Audit này là đọc source; không chạy lại test và không xác nhận firewall VM.

| File/package hiện có | Phân loại | Cách dùng trong M3 |
|---|---|---|
| `cmd/ngfw-engine/main.go` | Đường production M1/M2 | Wire M3 vào `Runtime`; giữ startup reconcile/IPC |
| `internal/engine/runtime.go` | Owner runtime M2 | Nối observation, invalidation, effective decision; giữ conntrack nguồn lifecycle |
| `internal/session/runtime_store.go` | Store M2 + indexes + CAS decision | Thêm context bằng clone/CAS; không tạo store session khác |
| `internal/domain/session_m2.go` | Canonical `RuntimeSession` | Thêm `Inspection *SessionInspection` |
| `internal/flow/tuple.go` | Tuple/NAT aliases | Tái sử dụng `Key`, `Scope`, `Aliases`; không ghép string tùy ý |
| `internal/connectivity/program.go` | Matcher L3/L4; `CompileM2` từ chối M3 | Giữ API M2; thêm entrypoint compile theo capability M3 |
| `internal/dataplane/compiler.go`, `compiler_m2.go` | Firewall/NAT/cache thật | Tái dùng render NAT và match; thêm inspection sau forward, không thay routing stack |
| `internal/dataplane/mark.go`, `epoch.go` | Layout mark M2 | Giữ nguyên upper 24 bits và lower byte; M3 không lấy thêm bit |
| `internal/dataplane/runtime_guards.go` | Source block/session revoke thật | Tái dùng NftRunner/owner enforcement; thêm adapter guard M3 có identity đầy đủ |
| `internal/dataplane/controller.go` | Apply + journal + compensating rollback | Mở rộng snapshot của compiler; rollback phải phục hồi cả inspection chain |
| `internal/config/manager.go` | Candidate/version/validation/activation | Thêm validation M3; giữ revision, idempotency, monotonic rollback |
| `internal/config/policy_canonical.go`, `policy_reachability.go` | Duplicate/shadow validation | Bổ sung semantics profile/app; không bỏ hardening đã có |
| `internal/engine/runtime_service.go` | Running owner + management surface | Thêm query health/security; compile mới ở commit **và** rollback |
| `internal/engineipc/runtime.go` | IPC version 2, bounded | Nâng version có thông báo mismatch; thêm operation M3 |
| `internal/management/runtime_client.go`, `api.go` | API proxy runtime | Production lấy M3 từ engine; legacy `API.events` không làm nguồn M3 |
| `internal/engine/runtime_events.go` | Ring runtime bounded | Reuse lifecycle/cursor; thêm notification M3 có payload nhỏ |
| `internal/inspection/suricata.go` | Partial/prototype, chưa wire production | Adapter hiện chỉ alert; thay live reader bằng package mới; giữ `RunPCAP` cho legacy lab |
| `internal/inspection/http.go` | Parser helper/partial | Tái dùng khi có bytes hữu hạn; không tự coi là live App-ID |
| `internal/inspection/dns.go`, `tls.go` | Parser helper/partial | Test parser có thể reuse; metadata production từ Suricata EVE |
| `internal/inspection/behavior.go`, `reputation.go` | Helper cho milestone sau | Không wire M3 |
| `internal/inspection/mitm.go`, `ml.go` | Prototype/future | Không wire M3 |
| `internal/engine/engine.go`, `session/store.go`, `policy/evaluator.go` | Đường legacy risk/security | Không làm owner M3; không reuse evaluator risk cho connectivity |
| `cmd/ngfw-proxy`, `internal/proxy` | Prototype tương lai | Không install/start trong M3 |
| `internal/enforcement/enforcer.go` | Interface + Memory test double | Không gọi Memory trong production M3 |
| `internal/events/bus.go`, `telemetry/writer.go` | Helper; chưa đủ đảm bảo retention M3 | Không dựa vào writer hiện tại để cam kết disk bound |
| `web/src/{App,runtimeData,wsLifecycle,policy,...}` | UI M1/M2 có hardening | Mở rộng adapter/component; giữ shared Candidate workflow |
| `configs/examples/m2-lab.json` | Baseline M2 | Giữ nguyên để regression |
| `configs/examples/lab.json` | Fixture tương lai có risk/TLS/REQUEST | Không dùng làm default M3 |

Các điểm cụ thể phải sửa khi code:

- `EVEAdapter.publishEVE` hiện bỏ qua `app_proto`/`alert.action`, dùng giờ ingest
  làm event ID; reader không xử lý rotation/truncate đầy đủ.
- M2 mark chỉ chứa epoch + zone pair; **không chứa policy ID hoặc cờ đã inspect**.
- M2 fast path accept ở forward priority 0; inspection phải có base chain sau
  nó, không thêm queue rule sau một `accept` trong cùng chain rồi cho là chạy.
- `NftRunner` chỉ tạo `ngfw_runtime` nếu chưa có: thêm schema/set trong string
  compiler sẽ không tự nâng schema một table đã tồn tại.
- Controller hiện compile snapshot cũ bằng closure options của lần apply mới.
  M3 phải tách options/artifact của old/target; không để rollback dùng profile,
  epoch hoặc zone slots của target cho config cũ.
- `RuntimeStore.setDecision` đang gán `EffectiveDecision=Action`: cần reducer
  để conntrack UPDATE không xóa kết quả enforcement M3 mới.
- `docs/architecture.md` mô tả activation M1 lịch sử; ownership hiện tại phải
  theo `runtime_service.go` và ADR 0002, không theo mô tả API giữ Running cũ.

## 3. Kiến trúc chốt: dữ liệu traffic, IDS và IPS

### 3.1. Ai sở hữu gì

| Owner | Trách nhiệm |
|---|---|
| Linux | Routing/NAT/conntrack và các verdict nftables |
| `ngfw-engine` | Running generation, session/context, correlation, policy, engine-owned nft mutations, events |
| Hai instance Suricata được systemd quản lý | Capture/reassembly/App-ID/signature; IPS instance phát NFQUEUE verdict |
| `ngfw-api` | Auth/RBAC/candidate/API/WS proxy; không đọc EVE, không CAP_NET_ADMIN |
| UI | Hiển thị backend evidence; không tạo App-ID, risk, success hoặc validation giả |

Tối đa hai sensor cố định: `ids` và `ips`. Đây là hai inspection process, không
phải hai NGFW session database. Khi cùng bật cần đo RAM của cả hai instance.
Không chạy sensor theo từng policy/session.

### 3.2. Đường packet và đường metadata

```text
                    LINUX PACKET PATH
prerouting DNAT -> forward guards -20/-15 -> DNAT zone guard -5
 -> M2 L3/L4 + epoch cache priority 0
 -> M3 selection priority +10:
      no profile: return
      IDS: NFLOG copy group 100; return             -> packet tiếp tục
      IPS: NFQUEUE 100 (bypass khi không listener)   -> Suricata accept/drop
 -> postrouting SNAT/MASQUERADE -> destination

                   ASYNCHRONOUS METADATA PATH
conntrack -> M2 RuntimeStore
Suricata -> EVE -> reader -> typed parser -> correlation -> same RuntimeStore
                                                   -> security event store
                                                   -> app policy invalidation
                                                   -> engine IPC -> API/WS -> UI
```

**Conntrack không có application payload.** Không implement `Inspect(session)`
bằng cách giả định Session có bytes. Production App-ID lấy `app_proto` và
protocol events từ Suricata. Pure-Go làm parsing/normalization EVE và các helper
bytes hữu hạn; không dựng packet capture/TCP reassembly thứ hai trong Go.
Parser HTTP/DNS/TLS có unit test chưa chứng minh live DPI độc lập hoạt động.

Chọn NFLOG cho IDS vì copy ở cùng vị trí forward với IPS, tránh capture cả LAN
và WAN làm một NAT flow xuất hiện thành hai Suricata flows. NFLOG không giữ
packet để chờ engine. Chọn NFQUEUE cho IPS; Go engine **không nhận packet để
trả verdict**. Kiểm tra support NFLOG/NFQ của binary trong T01. CLI IDS dùng
`--nflog`, group lấy từ YAML; không giả định argument `--nflog=100` chọn group.
[Source Suricata NFLOG](https://raw.githubusercontent.com/OISF/suricata/suricata-7.0.15/src/suricata.c).

Base chain sau firewall vẫn được đánh giá dù base chain trước trả `accept`;
`drop` kết thúc packet. Đây là cơ sở để M2 cached allow không bỏ qua M3.
[nftables verdict semantics](https://netfilter.org/projects/nftables/manpage.html#lbAL).

Không copy `iptables -F`, `nft flush ruleset` từ ví dụ Internet vào installer.
Chỉ sửa các table do NGFW sở hữu.

### 3.3. Chọn inspection theo policy

1. Dùng cùng priority tăng dần, OR trong services/addresses, AND giữa fields.
2. Xác định **policy L3/L4 của original direction**. Với reply, đảo field/zone
   về original view; không chọn một profile khác chỉ vì IP/port bị đảo.
3. Policy `ALLOW` có `security_profile_id` hợp lệ chọn đúng một sensor.
4. Policy ALLOW không profile và default allow đều kết thúc selection không
   inspect. Không fall through vào profile của rule phía sau.
5. DROP/REJECT của M1/M2 chặn trước chain M3; không được queue để Suricata allow
   ngược lại. Default deny tiếp tục deny.
6. `ct state invalid`, local INPUT/OUTPUT, loopback không thuộc M3 forward.
7. Khi policy inspection có source/destination zone để trống và có thể bao gồm
   interface `MANAGEMENT`, validation yêu cầu `include_management=true`; mặc
   định false. Không tự suy ra MGMT từ tên NIC. Packet tới chính appliance vẫn
   ngoài forward dù include_management=true.
8. Selection áp dụng packet đầu và mọi packet hai chiều, kể cả established.
   Không chỉ inspect NEW, không dùng `ct mark != 0` để bỏ inspect.

M3 không thêm bit vào ct mark. Post-filter selection thêm chi phí rule lookup
cho packet inspected, chấp nhận ở MVP và phải đo; không công bố fast path đồng
nghĩa traffic được miễn inspection. `KernelCacheVerified` chỉ xác nhận L3 cache.

## 4. Config và policy: contract cố định

### 4.1. Schema mới

Thêm `Config.Inspection *InspectionConfig` với JSON `inspection,omitempty`.
Thêm `SecurityProfile.Inspection *InspectionProfile` cùng tên JSON `inspection`.
Thêm `SecurityPolicy.ApplicationMatchMode string` JSON
`application_match_mode,omitempty`. Không tạo `inspection_profiles` registry
thứ hai; dùng `security_profiles` và `security_profile_id` hiện có.

```json
{
  "inspection": {
    "enabled": true,
    "include_management": false,
    "limits": {
      "eve_line_bytes": 1048576,
      "normalized_event_bytes": 8192,
      "observation_queue_items": 4096,
      "observation_queue_bytes": 8388608,
      "security_events": 5000,
      "security_event_bytes": 16777216,
      "correlation_pending": 2048,
      "correlation_wait_ms": 2000,
      "recent_sessions": 5000,
      "recent_session_ttl_seconds": 60,
      "app_detection_timeout_ms": 5000
    }
  },
  "security_profiles": [{
    "id": "m3-ips-basic",
    "name": "M3 IPS basic",
    "dpi_enabled": true,
    "ids_ips_enabled": true,
    "tls_mode": "METADATA_ONLY",
    "inspection": {
      "mode": "IPS",
      "fail_mode": "OPEN",
      "ruleset_id": "m3-builtin-v1"
    }
  }],
  "policies": [{
    "id": "allow-lan-web",
    "name": "LAN web with IPS",
    "priority": 10,
    "source_zones": ["lan"],
    "destination_zones": ["wan"],
    "services": ["tcp:80", "tcp:443"],
    "applications": ["HTTP", "TLS"],
    "application_match_mode": "RESTRICT_L3_ALLOW",
    "security_profile_id": "m3-ips-basic",
    "action": "ALLOW",
    "scope": "SESSION",
    "enabled": true,
    "log_start": true,
    "log_end": true
  }]
}
```

Đây là fragment để ghép vào `m2-lab.json`, không phải config appliance đầy đủ.
Mode hỗ trợ `IDS`/`IPS`; fail_mode chỉ `OPEN` trong M3. `CLOSED` phải lỗi rõ
`unsupported_in_m3`, không nhận rồi âm thầm dùng OPEN.

Default inspection nil/disabled giữ hành vi M2. Không ghi default mới vào
Running chỉ vì đọc JSON. `EffectiveInspectionConfig` tạo defaults trên bản
copy. Không thay checksum/version khi load file cũ. Clone phải deep-copy mọi
pointer/slice mới của config, profile, session, DTO.

Binary path, queue/group, EVE path, systemd unit và rules root là **deployment
settings root-owned**, không cho JSON editor chọn arbitrary executable/path.
Candidate chọn ruleset ID trong allowlist cài sẵn. Tất cả profile M3 dùng cùng
`m3-builtin-v1`; không nhận profile rules khác nhau trong cùng instance rồi
giả vờ Suricata đã phân biệt chúng.

### 4.2. Application policy semantics — cố ý giới hạn và hiển thị rõ

Trong M3, `applications` là **danh sách ứng dụng được phép trên rule ALLOW L3/L4
đã trúng**. Nó không tạo một vòng first-match L7 có thể chọn sang rule khác.
Field `application_match_mode=RESTRICT_L3_ALLOW` bắt buộc khi list không rỗng,
để không âm thầm đổi ý nghĩa một field legacy trước đây chưa được M2 hỗ trợ.

| Bước | Xử lý |
|---|---|
| L3 rule DROP/REJECT/default deny | Dừng; application không thể mở lại |
| ALLOW, list apps rỗng | Kết quả M2; inspection vẫn chạy nếu có profile |
| ALLOW, apps khác rỗng, app chưa biết | `PENDING`; traffic theo base ALLOW; đây là phân loại bất đồng bộ |
| Quan sát HIGH/VERIFIED và app nằm trong list | `MATCHED`; tiếp tục inspection trên packet sau |
| HIGH/VERIFIED, app không nằm trong list | `MISMATCH`; invalidate và yêu cầu session guard; chỉ báo blocked sau ACK kernel |
| Hết 5 giây hoặc sensor mất | `UNKNOWN_ALLOWED`; health/reason thể hiện thiếu classification, không CLEAN |
| App biết sau timeout | Vẫn đánh giá lại; timeout không khóa kết quả UNKNOWN vĩnh viễn |
| App đổi hợp lệ, ví dụ STARTTLS | Revision mới, reevaluate; guard deny đã áp dụng không tự gỡ trong cùng generation |
| Commit/rollback | Generation mới; tính lại rule/restriction; chỉ gỡ guard APP_POLICY khi reconcile chứng minh target cho phép |

Giới hạn bắt buộc ghi ở UI/USE: một số bytes/request có thể đi qua trước khi
metadata tới engine. Không tuyên bố đây là allowlist ứng dụng chặn trước packet
đầu tiên hoặc WAF. IPS signature DROP trực tiếp là đường khác, không chờ EVE.

Apps chỉ được cấu hình trên enabled `ALLOW`, `SESSION`, profile `IPS`; IDS giữ
nguyên nghĩa chỉ cảnh báo, nên apps restriction trong IDS phải validate lỗi.
Giá trị cho phép MVP: HTTP, TLS, DNS, SSH; UNKNOWN không phải selector cho phép.
Nếu phát hiện unsupported app, giữ raw name, normalized OTHER; nó không trúng
allowlist trên. Không đổi TLS thành HTTPS và không coi HTTP/2 mã hóa là HTTP.

Hai rule cùng L3 match nhưng khác apps vẫn có rule sau **unreachable** theo
semantics này. Backend từ chối, chỉ rõ rule che phủ. Không bỏ duplicate/shadow
validation khi thêm profile hoặc App-ID. Tên/ID/priority không làm hai rule
effective giống nhau thành khác. Canonical key phải chứa normalized app list,
application_match_mode và profile semantics hash, không chỉ display name.

### 4.3. Validation checklist cụ thể

- Global disabled + enabled policy reference inspection: lỗi; không ignore.
- Profile thiếu nested inspection/mode, ID không tồn tại, ruleset lạ: lỗi.
- Profile M3: DPI/IDSIPS true; legacy DNS security/URL/TI/behavior/ML false;
  TLS chỉ empty/BYPASS/METADATA_ONLY; DECRYPT/risk thresholds không được dùng.
- Profile M3 được reference không được mang legacy `inspection_required=true`
  hoặc `inspection_failure_action` đòi DROP/REJECT; trả lỗi unsupported thay
  vì chạy OPEN trái với cấu hình. Unknown keys trong object `inspection` cũng
  bị từ chối; không áp schema mới làm file M2 cũ bị rewrite.
- Không tự kích hoạt profile legacy có `minimum_block_risk`, `REQUEST` scope.
  Unreferenced legacy profile giữ như annotation, như M2.
- Unknown enum/negative limit/overflow vượt bound: lỗi gắn JSON field path.
- Limits chỉ cho phép giảm/tăng trong trần phần 12; zero/missing lấy default,
  negative không lấy default. ID matching case-sensitive theo existing IDs;
  chỉ normalize app/mode enums. Không lowercase profile ID để lookup nhầm.
- API validate chỉ tính toán; engine commit validate lại; không service restart,
  nft, version tăng hoặc file deploy mutation trong thao tác Validate.
- Sửa bất kỳ field M3 nào làm Candidate revision/validation stale như field M2.

## 5. Data model: khai báo trong domain, không import engine

### 5.1. Application và inspection

Tạo `internal/domain/inspection.go`; tất cả enums là typed string, hàm `Valid`
explicit switch. JSON enum không hợp lệ không biến thành success/clean.

```go
type ApplicationIdentity struct {
    Name string                         `json:"name"` // UNKNOWN/HTTP/TLS/DNS/SSH/OTHER
    RawName string                      `json:"raw_name,omitempty"`
    Source ApplicationSource            `json:"source"`
    Confidence ApplicationConfidence    `json:"confidence"`
    FirstSeen *time.Time                `json:"first_seen,omitempty"`
    LastSeen *time.Time                 `json:"last_seen,omitempty"`
    Revision uint64                     `json:"revision"`
    Conflicted bool                     `json:"conflicted"`
    EvidenceID string                   `json:"evidence_id,omitempty"`
}
```

Source: UNKNOWN, SURICATA_APP_PROTO, DPI_PARSER, TLS_METADATA, PORT_HEURISTIC.
Confidence: UNKNOWN, LOW, MEDIUM, HIGH, VERIFIED. MVP sensor normally HIGH;
VERIFIED chỉ khi policy evidence contract/test chứng minh tiêu chí, không tự
gán vì port hoặc có một field bất kỳ. Port heuristic tắt mặc định.

`SessionInspection` phải có chính xác các nhóm field sau; mỗi nhóm là struct
value hoặc pointer optional, không `map[string]any`:

| Field / JSON | Type / nội dung |
|---|---|
| `generation` | uint64 running generation của việc chọn profile |
| `revision` | uint64 riêng của inspection; không CAS theo counter update M2 |
| `profile_id`, `mode` | string + OFF/IDS/IPS |
| `state`, `reason` | NOT_REQUESTED/QUEUED/INSPECTING/DEGRADED/ERROR/COMPLETE |
| `coverage` | NONE/OBSERVED/PARTIAL/UNAVAILABLE; OBSERVED không phải đã kiểm tra toàn flow |
| `application` | ApplicationIdentity |
| `app_policy_state` | NOT_APPLICABLE/PENDING/MATCHED/MISMATCH/UNKNOWN_ALLOWED |
| `app_deadline` | *time.Time; dùng monotonic clock trong runtime timer, wall time để API |
| `threat_count`, `last_event_id` | uint64 + string; count security alerts, không count discovery |
| `max_severity`, `latest_verdict` | severity + UNKNOWN/ALERT/DROP/ERROR |
| `enforcement` | EnforcementResult bên dưới |
| `sources` | tối đa 2 source ID (ids/ips + sensor epoch) |
| `first_observed_at`, `last_observed_at` | *time.Time |
| `missing_evidence` | tối đa 8 reason codes; sort/dedup |

COMPLETE chỉ dùng khi session đã đóng và stream observation đã kết thúc;
session đang sống phải tiếp tục INSPECTING. COMPLETE không có nghĩa CLEAN.
Session không chọn inspect có OFF/NOT_REQUESTED/NONE, không phải lỗi sensor.
Sensor health là state riêng, không trộn vào enum SessionState M2.

### 5.2. ThreatEvent và EnforcementResult

Tạo `internal/domain/security_event_m3.go`. Event chi tiết mới có:

```text
event_id string; sequence uint64; observed_at time; ingested_at time
event_class="security"; source="SURICATA"; sensor_id; sensor_epoch
sensor_config_hash; ruleset_id; capture_mode IDS|IPS
suricata_flow_id string; transaction_id *string
observed_tuple *Tuple; flow_tuple *Tuple; protocol_raw string
session_id optional; session_identity optional; policy_id optional
policy_generation optional; correlation_state CORRELATED|UNCORRELATED|AMBIGUOUS
correlation_reason; correlation_revision uint64
signature_id uint32; signature_revision uint32; signature string
category string; source_severity *int; severity UNKNOWN|LOW|MEDIUM|HIGH
app ApplicationIdentity optional
signature_action raw allowed|blocked|unknown; packet_verdict optional raw
verdict UNKNOWN|ALERT|DROP|ERROR; enforcement EnforcementResult
```

Suricata uint64 flow IDs xuất JSON ra UI dưới dạng **string**, tránh JS mất
precision ở >2^53. Go decode typed uint64/json.Number, không đi qua float64.
Thiếu timestamp không bịa observed_at=now; lưu nil/missing + ingested_at và
không dùng event ấy làm automatic enforcement.

EnforcementResult: `mechanism=NONE|SURICATA_NFQUEUE|NFT_SESSION_GUARD`,
`scope=PACKET|SESSION`, `requested_action`, `status=NOT_REQUESTED|PENDING|
REPORTED|APPLIED|FAILED|UNAVAILABLE`, `reason`, `observed_at`, `operation_id`.
NFQUEUE DROP do EVE báo là REPORTED, không bịa ACK từ nft. `APPLIED` dành cho
mutation được adapter xác nhận/readback. Không đổi packet drop thành toàn
connection đã reset. `REJECT`/`RESET` không expose trong M3 IPS selector.

Severity mapping: raw 1→HIGH, 2→MEDIUM, 3→LOW; absent/invalid→UNKNOWN. Không tự
nâng tất cả thành CRITICAL. Giữ raw severity để audit.

`alert.action` không luôn là final packet verdict; parse `verdict.action` nếu
có, giữ hai giá trị riêng. IDS capture không có quyền drop packet; event
blocked bất thường ở IDS tạo health diagnostic, không hiển thị kernel block.
[EVE action/verdict](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-format.html#action-field).

### 5.3. DTO tương thích

`RuntimeSession` thêm pointer `Inspection`; update `Clone()` deep copy.
Legacy `domain.Session` chỉ là DTO ở API: map application/confidence từ M3
snapshot nếu có; không khôi phục legacy session engine. `security_context`
projection lấy từ RuntimeSession + bounded detail, risk/ML vẫn unavailable.
Session list chỉ summary, tối đa 1 KiB inspection summary/item; detail tối đa
16 KiB, không nhét toàn alert history vào mỗi session.

Confidence enum HIGH không phải xác suất0.95. Nếu legacy numeric confidence
không có measurement tương ứng, giữ compatibility field nhưng thêm availability
false và dùng enum mới làm dữ liệu hiển thị; không tạo số xác suất giả.

## 6. Suricata package và cấu hình triển khai

### 6.1. Version/build gate

Template tham chiếu Suricata 7.x, tài liệu/source 7.0.15 đã đối chiếu khi viết
spec. **Chưa xác nhận version package trên VM người dùng**. T01 ghi chính xác
Debian package version, kernel, nft, `suricata --build-info`, template hash và
ruleset SHA-256 vào manifest/evidence. Không dùng `latest`, không lặng lẽ nâng
major version. Khác major cần chạy lại probe/fixture rồi cập nhật ADR.

Build Go tiếp tục `CGO_ENABLED=0` cho appliance binaries; Go race test trên
Linux dùng compiler/CGO theo yêu cầu race, không nhầm hai chế độ.

### 6.2. Hai sensor cố định

| Thuộc tính | IDS | IPS |
|---|---|---|
| Unit | `ngfw-suricata-ids.service` | `ngfw-suricata-ips.service` |
| CLI | `suricata -c <ids.yaml> -l <epoch-dir> --nflog` | `suricata -c <ips.yaml> -l <epoch-dir> -q 100 --runmode workers` |
| Capture | NFLOG group 100 | một NFQUEUE 100; không fanout/multi-queue MVP |
| YAML | `stream.inline: no`; chỉ alert discovery/threat rules | `stream.inline: yes`; `nfq.mode: accept`, `nfq.fail-open: yes` |
| EVE | `/var/log/ngfw/suricata/ids/<epoch>/eve.json` | `/var/log/ngfw/suricata/ips/<epoch>/eve.json` |
| Socket health | `/run/ngfw-suricata/ids/command.sock` | `/run/ngfw-suricata/ips/command.sock` |

Sensor epoch là UUID mới mỗi process start do root-owned launcher tạo. Epoch
directory và manifest được công bố atomically; reader không trộn flow IDs giữa
hai lần Suricata chạy. Engine restart giữ epoch nếu sensor không restart.
Launcher chỉ nhận literal `ids|ips`, không execute input từ Candidate.

Root sở hữu launcher và static artifacts. Runtime epoch/log/manifest do user
sensor tạo trong thư mục riêng có engine read access; API không có quyền đọc
hoặc ghi. Không nhầm quyền sở hữu script với user đang chạy script.

YAML dùng `unix-command.enabled` + fixed socket path cho live control; không
chạy `--unix-socket` PCAP-job mode thay cho capture production. Bật EVE types
alert/flow/http/dns/tls/ssh/stats. Stats heartbeat 2s, output flush hữu hạn.
Không log body/cookies/Authorization/TLS keys; URL query có thể chứa secret:
UI/API chỉ giữ path đã bỏ query/fragment, metadata tối thiểu cần hiển thị.

Không `copy-mode: ips`, không bridge NIC, không disable checksum toàn cục.
Tắt rule `pass`/`bypass`, capture-bypass và tự ghi nfq marks trong managed ruleset.
Giữ `nfq.mode=accept`, không repeat/route. nft queue `bypass` xử lý **không có
listener**; `nfq.fail-open` xử lý **queue đầy** là hai cơ chế khác nhau.
[Suricata NFQUEUE](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html),
[queue overflow flag](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html).

Một queue và một worker là baseline để tránh tự đưa packet cùng flow sang
nhiều queue. Không cam kết mọi packet tuyệt đối không reorder khi fail-open;
đo retransmission/latency ở load test.

### 6.3. Ruleset và early application signals

Đóng gói `m3-builtin-v1`: discovery rules + các signature demo an toàn, có
manifest SID/revision/action/checksum. Không tuyên bố đây là bộ signature bảo
vệ enterprise đầy đủ. Threat demo có cặp IDS alert và IPS drop riêng.

- SID 9900001..9900004: HTTP/TLS/DNS/SSH discovery, class internal metadata.
- SID 9900100: benign marker `NGFW_M3_TEST_<nonce>` để kiểm thử alert/drop.
- SID discovery chỉ chuyển thành ApplicationObserved, **không** SecurityAlert,
  không cộng threat_count. Verify SID/rev trong manifest của sensor epoch;
  không phân loại dựa vào chuỗi `msg` do event cung cấp.
- Dùng protocol-detection rule `app-layer-protocol` để có tín hiệu trước khi
  flow đóng. Kiểm thử PCAP và TCP keepalive bắt buộc; EVE `flow` cuối connection
  không đáp ứng App-ID live. Không khẳng định một rule mẫu luôn chạy nếu chưa
  `suricata -T` + replay với binary đã khóa.
- Mỗi protocol/direction chỉ emit discovery hữu hạn; dedup discovery theo
  `(sensor_epoch,flow_id,app,direction)`. Discovery duplicate không dedup alert
  tấn công. Tránh `dsize` làm trễ phát hiện protocol.
[Protocol detection rules](https://docs.suricata.io/en/suricata-7.0.15/rules/app-layer.html).

Suricata chính thức nhận diện payload/reassembly; Go normalization không gọi
raw TLS parser lên JSON EVE hoặc lên TLS ciphertext.

## 7. EVE reader/parser — thuật toán bắt buộc

Package mới `internal/inspection/eve`; không dùng generic map cho core fields.

### 7.1. Parser

`ParseLine(line []byte, source SourcePosition) (Observation, error)`:

1. Reject vượt max line trước decode; strip CR ở CRLF, bỏ blank line.
2. Decode typed envelope; unknown JSON fields chấp nhận, unknown event_type
   đếm ignored và không sinh ERROR session. JSON lỗi có counter + rate-limited log.
3. Parse timestamp RFC3339Nano **và** Suricata offset `+0000` (layout có
   `-0700`); test microsecond/no colon, không chỉ `time.Time.UnmarshalJSON`.
4. Parse flow_id chính xác uint64; flow_id=0/absent khác một ID hợp lệ. Proto
   TCP/UDP/ICMP parse explicit; validate family/IP/port 0..65535 và presence.
5. Alert thiếu signature ID vẫn lưu diagnostic event nếu có phần còn lại,
   `missing_evidence` và không auto-enforce; tuple thiếu → UNCORRELATED.
6. Lấy `alert.action`, top-level `verdict`, `app_proto`, `flow.start/end`,
   `flow.src/dest`, direction; không dùng packet tuple thay client/server role.
7. Normalize bounded metadata; không mang raw line/HTTP headers vào queue.
8. Return immutable value; caller owns buffers, không retain scanner.Bytes().

### 7.2. Reader

`Reader.Run(ctx, Sink)` với FileSource interface để fake file rotation:

1. Resolve epoch manifest ở fixed root; symlink/path target phải nằm trong
   root, regular file, không đọc path do EVE khai báo.
2. Khi epoch mới: đọc từ byte 0 của file mới để giữ first events; giới hạn
   catch-up 8 MiB/10.000 lines. Khi attach historical file không checkpoint:
   mặc định tail tại EOF và báo coverage PARTIAL; không quét GB lịch sử.
3. Checkpoint chứa epoch, device/inode (hoặc identity fake portable),
   file generation, committed byte offset, prefix fingerprint. Chỉ resume nếu
   identity còn đúng; mismatch → tail/reset có diagnostic.
4. Dùng bounded line reader, không Scanner xử lý EOF partial như complete line.
   Giữ partial tới newline. Offset committed chỉ tiến qua newline hoàn chỉnh.
5. Oversize line: discard đến newline có budget; ghi lost counter; sau đó vẫn
   nhận line tốt. Buffer tối đa 1 MiB; không tăng vô hạn theo input.
6. EOF: chờ poll 200ms bằng timer/cancel, tiếp tục append. Không spin-loop.
7. Rename rotate: drain old open file trong budget, rồi new inode từ offset 0;
   new file absent dùng retry backoff 200ms→5s. Không dùng offset inode cũ cho inode mới.
8. Copytruncate: size nhỏ hơn offset hoặc fingerprint thay → new file generation
   và offset 0. Recommend rename rotation; copytruncate có thể mất bytes giữa
   copy/truncate, phải báo loss, không hứa exactly-once.
9. Enqueue không chờ vô hạn: bounded queue đầy → counter + coverage gap;
   checkpoint advance sau quyết định accepted/dropped explicit. Không block sensor.
10. Checkpoint atomic mỗi 1s hoặc 100 lines; crash có thể replay vài lines.
    Event identity loại duplicate replay, không hứa durable exactly-once.
11. Cancel đóng fd/timer và return, không leak goroutine/retry goroutine mỗi line.

### 7.3. Identity/dedup

ID = hash của `sensor_id, sensor_epoch, file_generation, byte_start, raw_hash`.
Nhờ byte_start khác nhau, hai alert giống nội dung nhưng thật sự emit hai lần
không bị nuốt. Re-read cùng physical record giữ ID. UI dedup theo event_id.
Không dùng `time.Now()` tạo alert ID; không dedup chỉ theo SID+5tuple.

Dedup LRU 20.000 IDs/10 phút có count và memory cap. Reader reconnect cùng epoch
phải giữ checkpoint/dedup. Process engine restart mất security ring được công bố
qua `stream_id` mới; không giả vờ có lịch sử bền vững.

## 8. Correlation với session, NAT và sự kiện trễ

### 8.1. Index và khóa

- Reuse `flow.Key{Scope, Tuple}` của M2. Scope sensor M3 là current netns,
  conntrack zone 0; nonzero CT zone không được auto-correlate khi thiếu evidence.
- Suricata flow ID khác conntrack ID và NGFW SessionID. Mapping key bắt buộc
  `(sensor_id, sensor_epoch, suricata_flow_id)`; verify tuple/time mỗi lần reuse.
- Original `O`, reply `R`, translated `T=Reverse(R)`, forward view
  `P=(O.src, T.dst, protocol)` và Reverse(P) cùng session. Tái dùng Aliases.
- Closed session lookup đọc bounded closed records M2, tối đa 5.000/60s, không
  tạo một session table khác. Bổ sung index closed có TTL gắn cùng cleanup.

### 8.2. Resolve algorithm

```text
valid flow binding + same incarnation + time interval -> CORRELATED
else current aliases for observed_tuple AND flow_tuple:
    exactly one strong identity + compatible time -> CORRELATED
    multiple valid identities -> AMBIGUOUS
else recent closed aliases (same time verification):
    one -> CORRELATED_CLOSED metadata only
    multiple -> AMBIGUOUS
else queue retry up to 2 seconds while waiting conntrack event:
    still none -> UNCORRELATED
```

Time window: sensor event must fit session kernel start/known lifetime ±2s;
với missing trustworthy start, không chọn gần nhất theo giờ ingest. Nếu tuple
reuse làm có hai candidate hợp lệ → AMBIGUOUS. Missing counter không có nghĩa
timestamp đủ tin cậy. Closed correlation không reopen session.

Lưu SecurityEvent ngay ở trạng thái hiện tại, không làm mất alert vì chưa có
session. Pending retry giữ event_id, khi correlate sau thì update cùng record,
tăng correlation_revision và emit SecurityEventUpdated; không tăng threat_count
lần hai. Pending quá tải giữ UNCORRELATED + counter.

Ví dụ test bắt buộc:

| NAT | O | P quan sát tại forward | T |
|---|---|---|---|
| MASQUERADE | `192.168.10.10:50000→203.0.113.10:443` | như O | `192.0.2.2:61000→203.0.113.10:443` |
| DNAT | `198.51.100.20:51000→192.0.2.2:8443` | `198.51.100.20:51000→10.20.0.10:443` | như P nếu không SNAT |
| Double NAT | source O private, destination O public | source O + destination T | source T translated + destination T |

Tuple không đủ không được đoán bằng IP pair. ICMP thiếu ID/type/code trong EVE
có thể hiển thị uncorrelated; không nhập tất cả ping vào cùng SessionID.

## 9. Orchestrator, store update và concurrency

Đặt coordinator trong `internal/engine/inspection_runtime.go`. Package
inspection không import engine; domain không import session/dataplane.

```go
// internal/inspection/source.go — parser/reader không biết RuntimeStore
type ObservationSink interface { TrySubmit(Observation) bool }
type EventSource interface {
    Run(context.Context, ObservationSink) error
    Snapshot() SourceHealth
}

// internal/session/inspection.go — dưới lock chỉ update RAM
func (s *RuntimeStore) UpdateInspection(
    id string, identity domain.ConntrackIdentity,
    expectedGeneration, expectedInspectionRevision uint64,
    next domain.SessionInspection,
) (domain.RuntimeSession, error)
```

RuntimeSession inspection revision độc lập với revision counter session để
counter update không làm mọi EVE CAS fail. Kiểm tra incarnation/generation vẫn
bắt buộc. CAS fail retry bằng snapshot mới tối đa 2 lần; sau đó count stale,
giữ alert event, không ghi đè state mới. Context generation lấy tại lúc
correlation; event config cũ không được enforce vào target mới.

Reducer pure `ReduceInspection(current, observation, now)` trả next context,
notifications và **intent**; không IO bên trong reducer. Chu trình:

1. Reader → bounded observation queue. Một worker xử lý tuần tự mỗi source;
   coordinator merge bằng observed time + application revision.
2. Ghi security event (nếu alert) độc lập correlation.
3. Correlate; read session clone; verify selection/profile/generation.
4. Merge app/coverage/threat summary; CAS context.
5. Publish bounded notifications ngoài store lock.
6. Nếu có enforcement intent: enqueue bounded worker, không gọi nft trong lock.
7. Worker recheck generation/incarnation trước và sau IO; stale intent bỏ.
8. Sau nft success + readback mới ghi APPLIED/invalidate effective allow.
9. Failure → FAILED/UNAVAILABLE, giữ reason, không nói blocked. Retry hữu hạn
   (3 lần, backoff 100/300/1000ms, tổng deadline 2s), không loop vô tận.

App merge: same app tăng LastSeen, first_seen giữ earliest; lower confidence
không overwrite high; same time/confidence mâu thuẫn → conflicted và không
auto-enforce dựa vào mâu thuẫn. Newer sensor protocol transition có evidence
được thay app, tăng revision. Dữ liệu muộn không downgrade. Port heuristic
không bao giờ đủ authority cho application block.

Lock order: activation mutex → coordinator mutation gate → short runtime/store
locks. Không acquire activation mutex khi đang giữ store lock. IO chỉ được giữ
mutex chuyên serialization mutation, không global session lock. Publish/IPC/
netlink/file waits luôn ngoài global locks. Fake clock cho timeout tests;
không dựa vào `sleep(1s)` để test race.

`EffectiveDecision` reducer phải giữ base `Decision` riêng: applied session
guard thắng base allow; packet DROP reported chỉ ảnh hưởng evidence packet,
không gắn cả flow `Revoked=true`. Conntrack UPDATE không xóa threat summary
hoặc app restriction. M2 manual revoke vẫn có ưu tiên cao nhất.

## 10. Compiler, kernel guard và failure behavior

### 10.1. Tables và transaction

Giữ `inet ngfw` và `inet ngfw_runtime` M2. Thêm table **`inet ngfw_inspection`**
do engine sở hữu, gồm:

- `guard` base chain forward priority -15, chỉ drop exact application guards.
- `inspect` base chain forward priority +10, policy accept, selected rules.
- `app_denied_v4` timeout set identity compound cho TCP/UDP.
- `ips_ready` timeout set `nf_proto . inet_proto` chứa IPv4/TCP và IPv4/UDP
  khi queue có liveness lease. Không dùng `type integer` vô định.
- User chains `selected_ids`, `selected_ips`, `select_original`, `select_reply`.

Sets nằm cùng table với chain dùng chúng; nft không lookup set cross-table.
Mode OFF dùng empty selection chains, không xóa table rồi mất pending guard
trong một mutation không có kế hoạch.

`RulesetBundle` mới tách `EnsureSchema`, `PolicyTransaction`, `ExpectedObjects`.
Schema tạo atomically nếu absent; nếu tồn tại validate type/hook/ownership,
migrate có version và tests. Không suy ra table tồn tại là schema đã đúng.
PolicyTransaction thay `ngfw` và các static chain M3 trong **cùng nft batch**;
không flush dynamic M2 sets. Không chain string.Replace thêm tầng compiler M3.
Extract typed render helpers, thêm regression cho output/semantics M1/M2.

### 10.2. Selection renderer

`CompileInspectionPlan(config, connectivityProgram)` tạo immutable ordered
selection rules. `RenderInspectionRules(plan)` dùng shared service/address
parsing, zone-interface mapping và direction view:

- original: iif source zones, oif destination zones, ip saddr source,
  ip daddr destination sau DNAT, service dport.
- reply: iif destination zones, oif source zones, ip daddr source,
  ip saddr destination, service sport; established/related như M2.
- Dùng `ct direction` phân nhánh, không queue reply một lần cho original rule
  rồi queue lại cho reverse rule. RELATED chỉ được inspect nếu có match đủ;
  không tự gán application của parent connection.
- Mỗi match nhảy đến terminal action riêng; IDS `log group 100 snaplen 65535
  queue-threshold 1` rồi accept trong base-chain context; IPS queue nếu lease
  có hiệu lực, nếu không thì accept với counter bypass. OFF accept.
- Cẩn thận `return` trong user chain sẽ quay về caller và có thể match rule
  sau: test first-match terminal behavior, không chỉ kiểm tra có chuỗi queue.
- M2 cache hit chỉ bỏ L3 rules; base chain M3 vẫn chọn inspection hiện tại.

Đây là quy ước render; mọi cú pháp phải qua `nft -c` và network namespace probe.
Đặc biệt test reverse NAT + overlapping directional policies: nếu compiler
M2 hiện tại và canonical connection view khác nhau, phải ghi reproducer, sửa
shared semantics ở phạm vi blocker, thêm M1/M2 regression; không đoán policy ID.

### 10.3. Application guard

Không thêm automatic application deny vào set ID-only của M2: tuple reuse và
source epoch cần scope rõ. Extend `RuntimeGuardManager` bằng companion
`InspectionGuardManager` dùng cùng NftRunner, mutation serialization và
`Runtime.Invalidate`; không tạo một firewall owner mới.

Key v4 TCP/UDP gồm `ct zone`, `ct id`, `ct original ip saddr`,
`ct original proto-src`, `ct original ip daddr`, `ct original proto-dst`,
`meta l4proto`. Dùng `typeof` đúng expression cho set; verify nft/kernel trong
T01. Cả hai chiều có cùng key. CT ID missing/namespace không current thì
enforcement UNAVAILABLE, không mở rộng drop thành toàn source IP.

Guard giữ claim `(SessionID, incarnation, generation, reason=APP_POLICY)`;
TTL 60s, refresh mỗi 20s chỉ sau targeted Get xác nhận cùng incarnation.
Max 10.000 guards. DESTROY/cleanup gỡ đúng key; lỗi cleanup giữ TTL và metric.
Restart engine clear chỉ **M3 app guards** trước rebuild; không flush source
blocks/manual revoke M2. Recovery tạm UNKNOWN_ALLOWED theo fail-open, ghi reason.
Sau commit guard cũ được giữ đến re-evaluate target rồi gỡ có điều kiện; không
gỡ M2 manual block. Nếu guard reconcile lỗi activation phải report/rollback,
không âm thầm publish successful final state.

### 10.4. Suricata DROP

IPS packet verdict do Suricata trực tiếp quyết định; EVE có thể đến sau, mất
hoặc không correlate. Không chờ engine event rồi gọi nft thay cho inline DROP.
Event drop correlated: update latest verdict, invalidate explanatory cache,
record scope PACKET. Không tự block toàn IP, không tự TCP reset, không xóa
conntrack để giả làm reset. Session guard APP_POLICY chỉ dùng cho restriction
được mô tả ở phần 4, tách khỏi signature packet verdict.

### 10.5. Fail-open và liveness lease

- Base firewall deny vẫn deny khi Suricata chết. Fail-open chỉ bỏ **inspection**
  trên traffic đã được base policy cho phép.
- No listener: nft queue bypass. Queue full: Suricata NFQA fail-open flag.
- Listener treo: bypass flag một mình không giải quyết. Engine health monitor
  không renew `ips_ready` (timeout 3s, renew mỗi 1s) khi sensor capture liveness
  không được chứng minh. Probe mỗi 1s, timeout 500ms; heartbeat stale 6s.
  Packet mới ngừng queue tối đa khoảng 9s sau mất liveness; expose measured gap.
- Lease test dùng key `meta nfproto . meta l4proto`; không dùng ct mark làm cờ
  lease hoặc app result. Engine chết lease tự hết; forwarding M1/M2 tiếp tục.
- EVE quiet không đồng nghĩa sensor chết. Probe unix socket, process epoch và
  capture counters; queue backlog không tiến cùng capture counter stale là
  stalled. EVE disk error là observability degraded, không tự suy là packet sạch.
- Khi stalled engine yêu cầu systemd restart đúng fixed unit với timeout;
  packet đã ở queue có thể mất/timeout khi unbind. Không hứa fail-open zero-loss
  hoặc reset được mọi packet đã queued. Ghi counter và đo scenario failure.
- M3 không hỗ trợ fail-close; không nhận cấu hình đòi guarantee này.

## 11. Activation, rollback, restart

Sensor YAML/rules là immutable artifacts do installer quản lý; candidate không
thay arbitrary Suricata rules. Đổi policy/profile chỉ đổi selection/context;
không restart sensor trên mỗi commit. Ruleset update tùy ý là non-goal.

Create `ActivationSnapshot{Config, Generation, M2Options, InspectionPlan,
ArtifactHash, StaticRulesetHash}` và persist checksum cùng activation journal.
Compiler nhận snapshot target; rollback nhận snapshot previous độc lập.

Commit sequence trong cùng serialization M1/M2:

1. Verify candidate revision/expected version; duplicate/shadow/schema validate.
2. Compile complete target (L3 + inspection); compare old snapshot; kiểm tra
   manifest/capability root-owned đã cài. Không có files/packages cần thiết thì
   trả actionable error trước mutation. Sensor đang dừng nhưng artifact hợp lệ
   cho commit OPEN với `inspection_health=UNAVAILABLE`, không bịa healthy.
3. Set coordinator `ACTIVATING`; dừng phát intent mutation mới, không dừng CT
   tracking. Existing observations vẫn vào queue bounded.
4. Allocate fresh M2 epoch; prepare snapshot/journal. Route/interface M1 vẫn
   theo existing reconciler và compensation.
5. Apply nft full target transaction; verify static rules/sets/epoch.
6. Reconcile app guards target dưới mutation gate; prepare context deltas.
   Chưa publish Running nếu bước này còn có thể lỗi IO.
7. Publish running version bằng manager; swap prepared program + inspection
   selection/context cùng generation. Swap RAM không gọi IO; replay queued
   results chỉ khi còn đúng incarnation/source và re-evaluate target policy.
8. Persist finalized snapshot, remove journal, unpause mutation. Mọi error sau
   mutation phục hồi previous artifacts/network bằng recovery context riêng.

Thứ tự và failure-before/after-publish chi tiết ở
[CODE_CONTRACTS phần 10](m3/CODE_CONTRACTS.md#10-quy-ước-commit-coordinator-để-không-tạo-backend-thứ-hai).

Giữ commit receipt/idempotency. Timeout HTTP không có nghĩa engine không apply;
API phải đọc receipt/current version, không tự retry tạo activation mới.
Rollback vẫn tạo generation lớn hơn, restore inspection mode/selection/rules
thật. Profile OFF/IDS/IPS đổi qua rollback phải có test riêng.

Startup: recover journal → reconcile Running/static M3 chain với new epoch →
clear untrusted M3 app guards/leases → init store → M2 subscribe/resync → attach
current sensor epoch/reader → health monitor renew lease → begin correlation.
Không restore cached app ALLOW như proof sau restart. Recovered sessions có
coverage PARTIAL cho tới evidence mới. Suricata absence khi disabled không
khiến engine crash loop. API/UI outage không dừng sensors/firewall.

## 12. Limits, retention, health

| Tài nguyên | Default | Hard cap / hành vi |
|---|---:|---|
| EVE line | 1 MiB | tối đa 4 MiB; discard oversize đến newline |
| Normalized event | 8 KiB | tối đa 16 KiB; truncate metadata có flag |
| Observation queue | 4096 / 8 MiB | tối đa 10.000 / 32 MiB; full → loss metric |
| Security ring | 5000 / 16 MiB | tối đa 10.000 / 32 MiB; O(1) oldest eviction |
| Pending correlation | 2048 / 2s | tối đa 4096 / 5s; keep unmatched event |
| Recent closed | 5000 / 60s | reuse M2 retention, không copy full histories |
| Flow bindings | max sessions + max closed | TTL lifetime/60s, scope sensor epoch |
| Dedup | 20.000 / 10 min | capped bytes; không pin vô hạn |
| Enforcement intents | 1024 | dedup by session/generation, retry deadline 2s |
| HTTP query page | 50 | max 200, max response 1 MiB |
| IPC query timeout | 2s | commit giữ contract dài hơn riêng |
| Rule selector expansion | 10.000 rendered rules | reject trước kernel khi vượt |

Security ring in-memory trong M3, không hứa SQL/durable history. Expose oldest
sequence, gap và engine stream_id. EVE disk retention bắt buộc: mỗi sensor tối
đa 256 MiB tổng, rotate 32 MiB, giữ 1 ngày hoặc byte cap chạm trước; timer 1
phút; read-only/ENOSPC → degraded. Dung lượng có thể overshoot giữa hai lần
rotate, dùng systemd/filesystem quota nếu đòi hard disk cap; không gọi logrotate
là hard real-time cap. Rotation không xóa file đang reader drain trước grace.

`InspectionHealth`: DISABLED/STARTING/HEALTHY/DEGRADED/UNAVAILABLE/ERROR cùng
sensor enabled/process status/capture mode/ruleset hash/epoch/reader active,
heartbeat age/last event/lost counters/reason/lease state. HEALTHY cần source
đúng mode/artifact và monitoring đủ evidence; không cần có alert gần đây.

Metrics riêng: parsed/invalid/ignored/oversize/queue_dropped/reader_gap,
correlated/uncorrelated/ambiguous/late/duplicates, app changes,
packet_drop_reported, app_guard_applied/failed, selected_ids/ips_packets,
inspection_bypass/stall/queue overflow nếu kernel quan sát được. Counter không
quan sát được là null/unavailable, không bịa 0.

## 13. IPC/API/WebSocket contract

Giữ public `/api/v1` và response envelope. Runtime IPC tăng **2→3**; old binaries
gặp mismatch trả error/HTTP503 actionable `rebuild ngfw-engine and ngfw-api`,
không fallback local Engine. Capability endpoint/version trong health.

| Operation IPC mới | HTTP | Kết quả |
|---|---|---|
| `inspection.health` | GET `/api/v1/inspection/health` | InspectionHealth |
| `inspection.capabilities` | GET `/api/v1/inspection/capabilities` | modes/apps/rulesets/fail modes/limits/semantics/version |
| `security.list` | GET `/api/v1/security/events` | SecurityEventPage |
| `security.get` | GET `/api/v1/security/events/{id}` | ThreatEvent |
| Existing sessions.list/get | existing `/sessions` | thêm inspection summary/detail |

Read-only role VIEWER trở lên; config ADMIN như cũ. Không tạo endpoint ingest
EVE cho frontend. Không expose paths/command socket hoặc full raw event.

Event query: `after_sequence`, `stream_id`, `limit=50`, optional severity,
session_id, signature_id, mode, correlation_state. Validate invalid filter→400;
limit>200→400. Sort sequence tăng dần cho cursor. Response `items`, `next_cursor`,
`has_more`, `oldest_sequence`, `stream_id`, `gap`, `evicted_count`.
Scan budget ring capacity; cursor phải tiến qua record không trúng filter để
không đọc mãi cùng range. Unknown id→404, engine unavailable→503, timeout→504.
Một alert có tuple thiếu vẫn hiển thị record và dấu unavailable.

Không đổi `/api/v1/events` đang dùng runtime telemetry thành threat-only.
Giữ endpoint cũ; view Threats chuyển sang endpoint security mới.

Reuse `/ws/events`, không mở thêm socket cho mỗi component. Message mới có
`schema_version`, `kind`, `event_class`, `stream_id`, `sequence`, timestamp và
payload nhỏ theo typed union:

- `ApplicationIdentified` (inspection class), `InspectionStateChanged`;
- `SecurityAlert`/`SecurityEventUpdated` (security class + event_id);
- `InspectionHealthChanged` (inspection class).

Lifecycle class runtime/policy cũ giữ nguyên. WS notification là hint; REST
cursor là cách catch up khi gap/reconnect. Engine restart stream_id đổi → reset
cursor/dedup và fetch page; không chờ sequence mới vượt sequence engine cũ.
Single writer/connection, write deadline, close/cancel, bounded channel, backoff
có jitter. Reuse `wsLifecycle.ts`; preserve EPIPE/StrictMode regression tests.

## 14. UI: component phải có và dữ liệu phải dùng

Không redesign layout. Tách component M3 nhỏ khỏi `App.tsx` nếu cần.

| Component | Input/hiển thị | Quy tắc |
|---|---|---|
| `ApplicationBadge` | normalized app + source/confidence | missing→Unknown; TLS hiển thị TLS |
| `InspectionBadge` | mode/state/coverage | OFF→Not inspected; sensor down→Unavailable |
| `InspectionHealthPanel` | health/reason/heartbeat/lease | không dùng màu xanh chỉ vì HTTP health 200 |
| `ThreatEventTable` | security page/cursor | severity UNKNOWN trung tính; source/dest thiếu dùng — |
| `SessionInspectionDetails` | detail summary + event links | counters lifecycle không gọi threat; packet drop khác session guard |
| Policy editor extension | profile + app whitelist | label “Ứng dụng cho phép sau nhận diện”; hiển thị delay/fail-open |

`runtimeData.ts` validate unknown input trước render; helpers nhận unknown rồi
normalize, không gọi toLowerCase trên optional raw field. Backend empty/malformed
record không làm crash page. Không tính risk từ severity; risk remains unavailable.
App selector capability-driven; unsupported feature disabled kèm lý do.

Giữ form raw string cho Services/Priority; parse khi submit để không tái lỗi
không gõ được dấu phẩy/không xóa 0. Candidate JSON giữ “Nạp Running vào trình
soạn thảo” không commit; confirm dirty; Back/browser navigation vẫn chạy.
Profile/app round-trip phải giữ nguyên qua save→GET→edit, validation stale khi
sửa. Commit chỉ enabled theo current candidate revision + valid + dirty.

## 15. Installer/systemd và script verification

`install-linux.sh` thêm `--with-inspection`; default cũ vẫn chỉ M1/M2. Với flag:

1. Cài/pin package Suricata theo T01 manifest; probe NFLOG/NFQ/control socket.
2. Cài root-owned YAML/rules/manifest tại `/etc/ngfw/inspection`; preserve user
   files, không ghi đè `/etc/suricata/suricata.yaml` hoặc unit distro.
3. Cài launcher, sensor units và log retention timer; không cài proxy/ML.
4. Sensor user riêng `ngfw-inspect`; grant capability tối thiểu thực sự cần để
   bind NFLOG/NFQUEUE, verify sau drop privileges. API user không đọc EVE/rules
   private và không có quyền systemctl. Không dùng chung group API để ghi assets.
5. Systemd sensor `Type=simple`, foreground, Restart=on-failure, không
   `PartOf=ngfw-api`/`Requires=ngfw-api`. Engine đọc log/socket; không có dependency
   cycle. Health/error của sensor không restart cả engine.
6. `--start` với `--with-inspection` cho phép start sensor units; traffic chỉ
   đi inspection sau config commit enabled. Không tự enable IPS trong running.
7. Verify scripts cài mode 0755; gọi installed absolute path hoặc `bash path`,
   không phụ thuộc executable bit của bản copy Windows.
8. Preserve `/etc/ngfw/lab.json`, `.env`, candidate/running và M2 sysctls.

Ownership mặc định khi implement: static assets `root:ngfw-inspect` 0640,
launcher `root:root` 0755; runtime/log directories `ngfw-inspect:ngfw-inspect`
0750 và files0640. Thêm **SupplementaryGroups=ngfw-inspect chỉ cho engine unit**
để đọc, không thêm API user/group vào nhóm này. Suricata units chạy
User/Group=ngfw-inspect, Ambient/Bounding CAP_NET_ADMIN cho NFLOG/NFQUEUE;
capability bổ sung chỉ khi probe binary chứng minh cần và ghi lại lý do.
Engine vẫn là nơi duy nhất chạy `ip`/`nft`; Suricata có quyền queue verdict.
Installer kiểm tra quyền traverse toàn bộ parent path; không `chown -R` thư mục
state/log M1 để chữa permission. Sensor không được ghi Running/candidate/API data.

`scripts/verify-m3-linux.sh`: default read-only preflight, lưu outputs dưới
evidence dir; traffic/mutation chỉ khi `--traffic --lab` và topology explicit.
Dùng bash strict mode, trap phục hồi config/service trong tests có fault, không
flush host networking. Không chứa hard-coded token; đọc env và redact log.
Exit 0 PASS, 1 FAIL, 2 prerequisites/NOT_RUN. SKIP không tính PASS.

## 16. File map khi triển khai

Danh sách đầy đủ theo task ở [CODING_TASKS](m3/CODING_TASKS.md). Quy tắc phân chia:

| Nhóm | File mới |
|---|---|
| Domain | `inspection.go`, `inspection_config.go`, `security_event_m3.go` |
| Config | `inspection.go`, `inspection_test.go` |
| Inspection contracts | `internal/inspection/source.go`, `application.go` |
| EVE | `internal/inspection/eve/{types,parser,reader,checkpoint,identity}.go` |
| Correlation | `internal/inspection/correlation/{resolver,bindings}.go` |
| Suricata control | `internal/inspection/sensor/{manifest,health,control}.go` |
| Session | `internal/session/inspection.go`, `recent_lookup.go` |
| Runtime | `internal/engine/{inspection_runtime,inspection_reducer,inspection_enforcement,security_events}.go` |
| Program | `internal/connectivity/inspection.go`, `selectors.go` |
| Dataplane | `internal/dataplane/{compiler_m3,inspection_plan,inspection_guards,inspection_schema,ruleset_bundle}.go` |
| API | `internal/management/inspection_api.go` |
| Web | `web/src/inspectionData.ts`, `web/src/components/inspection/*.tsx` |
| Deploy | `deploy/inspection/*`, `deploy/ngfw-suricata-{ids,ips}.service`, log retention timer/service |
| Scripts | `start-suricata-sensor.sh`, `rotate-suricata-logs.sh`, `verify-m3-linux.sh` |
| Fixtures | `tests/fixtures/suricata/*`, `tests/fixtures/m3/*` |

Mỗi file logic có `_test.go` hoặc test qua boundary cụ thể được task chỉ định.
Không tạo file trống/package stub chỉ để đủ danh sách; tên hàm public phải khớp
contract trước khi wiring. Source hiện tại của người dùng có thay đổi ngoài
M3; không reset/stash/xóa chúng khi code.

## 17. Lệnh kiểm thử và tiêu chí báo cáo

Mỗi task chạy targeted tests ghi trong task. Full gate sau khi hoàn tất các
package liên quan, không cần chạy toàn bộ suite sau mỗi dòng code:

```bash
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./internal/engine/... ./internal/session/... \
  ./internal/inspection/... ./internal/dataplane/... ./internal/config/... \
  ./internal/engineipc/... ./internal/management/...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/...
cd web
npm ci
npm test
npm run build
```

PowerShell dùng command riêng, không copy `VAR=x cmd` từ Bash. Race bắt buộc
chạy trên Linux đủ compiler; Windows build/unit pass không thay Linux race.
Thiếu môi trường race ghi NOT_RUN và chưa qua gate CODE COMPLETE theo spec này.

Parser fuzz smoke trên Linux (mỗi target riêng):

```bash
go test ./internal/inspection/eve -run '^$' -fuzz FuzzParseLine -fuzztime 30s
go test ./internal/inspection -run '^$' -fuzz FuzzApplicationBytes -fuzztime 30s
```

Replay PCAP dùng signature marker an toàn trong isolated lab; lưu pcap hashes,
EVE raw, normalized expected result và Suricata version. `nft -c` kiểm tra cú
pháp chưa chứng minh hook/NAT/forwarding; phải chạy ma trận packet thật.

## 18. Rủi ro phải có test đối ứng

| Rủi ro | Cách khóa |
|---|---|
| App-ID chỉ có sau connection close | Discovery signature + long-lived live test |
| Cached allow bỏ IPS | Base chain +10; test mark hiện tại + payload marker về sau |
| IDS vô tình block | NFLOG copy; không gọi guard khi mode IDS; backend từ chối app restriction IDS |
| NFQUEUE treo/đầy | bypass + fail-open flag + lease + stall test; công bố in-flight loss |
| Port inference giả | Source/confidence model + wrong-port/random bytes fixtures |
| Flow ID reuse/NAT collision | Sensor epoch + M2 incarnation + strict time/alias; ambiguous không enforce |
| Delayed old alert block connection mới | Generation/incarnation recheck trước/sau IO; stale test |
| Mixed UDP/TCP same tuple | Protocol trong mọi key; uint64 không qua JS number |
| Partial line/rotation replay | Reader state machine + source-position IDs + overflow metrics |
| Commit/rollback bỏ inspection | Full RulesetBundle snapshots + failure injection từng stage |
| Counter update xóa verdict | Inspection revision CAS + effective-decision reducer |
| VM dùng binary cũ | IPC v3 mismatch + build/ruleset hashes health/evidence |
| Two matching app policies không reachable | Explicit RESTRICT_L3_ALLOW + backend shadow tests |
| UI crash/WS EPIPE cũ quay lại | Existing regression giữ + bad-record/StrictMode/reconnect tests |
| Disk/event queues tăng vô hạn | Byte cap + count cap + retention + saturation tests |
| Phiên bản sensor không support option | Capability probe/rules syntax/config tests trước activation |

## 19. Definition of done và handoff

**M3 CODE COMPLETE / VM ACCEPTANCE PENDING** chỉ khi:

- [ ] T00–T31 đã hoàn tất phần code/local verification, không còn TODO trong runtime path.
- [ ] Session ownership giữ tại Runtime M2; API không có session fallback M3.
- [ ] App-ID production có nguồn traffic, early observation, honest confidence.
- [ ] EVE lifecycle/dedup/NAT correlation/limits/concurrency triển khai đủ.
- [ ] IDS thật và IPS kernel path thật đã có code; thiếu VM được ghi pending.
- [ ] Config/policy/compiler/cache/invalidation/recovery cùng semantics.
- [ ] API/WS/UI hiển thị evidence và mất inspection chính xác.
- [ ] Installer artifacts/scripts/docs đủ; không chỉ config mẫu không có service.
- [ ] Full Go/web/build/vet/race gates có output thực tế, không lấy log cũ.
- [ ] M1/M2 regressions pass; mọi fail còn lại được sửa hoặc rõ blocker chưa đóng.
- [ ] Ma trận VM có commands/evidence path, tất cả row chưa chạy là NOT_RUN.

**M3 ACCEPTED** thêm điều kiện: các VM criterion bắt buộc PASS, baseline M1/M2
PASS cùng topology, NAT/both-directions/late attack/drop/failure/rollback/restart
có evidence thật. Không cộng fixture PASS vào live IPS PASS.

Báo cáo cuối gồm commit/worktree hash, files sửa/tạo, versions, commands và
exit codes, pass/fail/not-run, known limitations, units cần rebuild/restart,
config migration và vị trí evidence. `npm run dev` chỉ reload frontend; thay
Go hoặc services/rules artifacts phải build/install tương ứng.
