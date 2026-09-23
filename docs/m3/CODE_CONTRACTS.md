# M3 — Contract code, dữ liệu mẫu và thuật toán tại các boundary

Đọc sau [master spec](../M3_IMPLEMENTATION_PLAN.md), dùng cùng
[CODING_TASKS](CODING_TASKS.md). Các snippet là **contract cần implement**, không
phải code đã được build. Package/import dùng tên hiện có trong `go.mod`.
Không copy chữ `...`/placeholder vào production rồi đánh dấu task xong.

## 1. Dependency graph: tránh import cycle

```text
domain                           # chỉ stdlib + types của domain
flow -> domain
conntrack -> domain
session -> domain, flow, conntrack
connectivity -> domain
inspection (contracts/reducers) -> domain
inspection/eve -> inspection, domain
inspection/sensor -> inspection, domain
inspection/correlation -> inspection, domain, flow (SessionLookup interface)
dataplane -> domain, config, connectivity
engine -> session, connectivity, inspection/*, domain
engineipc -> domain + service interface (không import management)
management -> domain + RuntimeClient interface (không đọc EVE)
cmd/ngfw-engine -> tất cả concrete adapters để wire
```

Không để `inspection` import `inspection/eve` nếu eve đã import inspection.
`ApplicationFromObservation` dùng kiểu Observation của parent; parser child
chỉ xây kiểu đó. Sensor manifest DTO không được tham chiếu engine type.

## 2. Config types đầy đủ của phần mới

Đặt trong `internal/domain/inspection_config.go`:

```go
type InspectionConfig struct {
    Enabled bool `json:"enabled"`
    IncludeManagement bool `json:"include_management"`
    Limits InspectionLimits `json:"limits"`
}

type InspectionLimits struct {
    EVELineBytes int `json:"eve_line_bytes"`
    NormalizedEventBytes int `json:"normalized_event_bytes"`
    ObservationQueueItems int `json:"observation_queue_items"`
    ObservationQueueBytes int `json:"observation_queue_bytes"`
    SecurityEvents int `json:"security_events"`
    SecurityEventBytes int `json:"security_event_bytes"`
    CorrelationPending int `json:"correlation_pending"`
    CorrelationWaitMillis int `json:"correlation_wait_ms"`
    RecentSessions int `json:"recent_sessions"`
    RecentSessionTTLSeconds int `json:"recent_session_ttl_seconds"`
    AppDetectionTimeoutMillis int `json:"app_detection_timeout_ms"`
}

type InspectionProfile struct {
    Mode InspectionMode `json:"mode"`
    FailMode string `json:"fail_mode"` // chỉ OPEN
    RulesetID string `json:"ruleset_id"`
}
```

Không thêm đường dẫn binary/EVE hoặc shell command vào các structs này.
Deployment settings riêng do cmd đọc root-owned manifest. Profile setting bị
thiếu không tự suy từ boolean legacy `ids_ips_enabled`.

Default/upper bounds của trường chưa ghi hard cap trong bảng master:
`app_detection_timeout_ms=5000`, range1000..30000;
`recent_session_ttl_seconds=60`, range1..60;
`recent_sessions<=5000`; queue/security byte caps như master12.
Giá trị normalized event bytes phải <= queue byte cap và security byte cap.
Một event vượt cap không được append rồi mới evict (tạm vượt mọi giới hạn).

## 3. Typed observation — đầu vào duy nhất từ sensor

Đặt `SourcePosition`, `Observation`, `SourceHealth` trong
`internal/inspection/source.go`, không trong engine/domain:

```go
type SourcePosition struct {
    SensorID string
    SensorEpoch string
    SensorConfigHash string
    RulesetID string
    Mode domain.InspectionMode
    FileGeneration string
    ByteStart int64
    ByteEnd int64
}

type Observation struct {
    ID string
    Source SourcePosition
    Kind string // alert, flow, http, dns, tls, ssh, stats, discovery
    ObservedAt *time.Time
    IngestedAt time.Time
    FlowID uint64
    HasFlowID bool
    TransactionID *uint64
    Tuple *domain.Tuple
    FlowTuple *domain.Tuple
    FlowStart *time.Time
    FlowEnd *time.Time
    Direction string // to_server, to_client hoặc unknown
    App domain.ApplicationIdentity
    Alert *AlertObservation
    Protocol *ProtocolMetadata
    Stats *SensorCounters
    MissingEvidence []string
    Truncated bool
}

type AlertObservation struct {
    SignatureID uint32
    HasSignatureID bool
    SignatureRevision uint32
    Signature string
    Category string
    Severity *int
    SignatureAction string
    PacketVerdict *string
    InternalDiscovery bool
}

type ProtocolMetadata struct {
    HTTPHost string
    HTTPMethod string
    HTTPPath string // đã bỏ query/fragment
    TLSSNI string
    TLSVersion string
    ALPN []string
    DNSQuery string
    DNSRecordType string
    SSHBanner string
}

type SensorCounters struct {
    UptimeSeconds *uint64
    CapturedPackets *uint64
    CaptureDrops *uint64
    NFQueueDrops *uint64
    SourceTimestamp *time.Time
}
```

`SourceHealth` chứa state/reason/lastRead/lastHeartbeat/counters và không chứa
live file/socket pointers. Stats field thiếu không gán zero. Các metadata
string tối đa1024bytes, HTTPPath4096bytes; tổng observation vẫn theo size cap.
ALPN max8, missing evidence max8. Cắt UTF-8 ở rune boundary để UI JSON hợp lệ.
API JSON field names của metadata dùng snake_case và omit empty.

`RawEnvelope` private trong eve parser dùng:

```text
timestamp string; event_type string; flow_id *uint64; tx_id *uint64
src_ip/dest_ip strings; src_port/dest_port *uint32; proto string
app_proto string; direction string
alert *RawAlert; verdict *RawVerdict; flow *RawFlow
http *RawHTTP; dns json.RawMessage; tls *RawTLS; ssh *RawSSH; stats *RawStats
```

DNS EVE có khác schema version: decoder riêng chỉ support fixture/version đã
lock; unknown shape giữ App DNS nhưng metadata unavailable. Không decode mọi
DNS structure thành cùng giả định `answers` array. RawMessage phải bỏ ngay sau
normalize, không giữ vào ring.

## 4. Error codes và ai xử lý

Error dùng typed sentinel hoặc `errors.Is`; field error giữ path. Không string
contains cả thông báo để quyết định control flow.

| Code | Producer | Consumer xử lý |
|---|---|---|
| `EVE_MALFORMED` | parser | reader count+skip, không stop process |
| `EVE_TOO_LARGE` | line reader | drain đến newline + gap counter |
| `EVE_UNKNOWN_TYPE` | parser | ignored counter, không threat/error verdict |
| `SOURCE_UNAVAILABLE` | file/control | bounded retry + health |
| `SOURCE_EPOCH_CHANGED` | monitor | reset bindings/pending eligibility, giữ event history |
| `SESSION_MISSING` | store | giữ event uncorrelated; không tạo session từ EVE |
| `SESSION_AMBIGUOUS` | resolver | AMBIGUOUS; không enforcement |
| `STALE_INSPECTION` | store CAS | retry tối đa2 với snapshot mới |
| `STALE_GENERATION` | mutation gate | bỏ intent hoặc reevaluate current policy, không apply old intent |
| `UNSUPPORTED_IN_M3` | config | HTTP400 validation field error |
| `INSPECTION_CAPACITY` | bounded queue/store | counter+degraded; forwarding tiếp tục |
| `ENFORCEMENT_UNAVAILABLE` | guard adapter | context UNAVAILABLE, không fake success |
| `ENFORCEMENT_FAILED` | nft apply/verify | context FAILED, bounded retry |
| `IPC_VERSION_MISMATCH` | engineipc | HTTP503 kèm version/build requirement |

CLI diagnostics không return raw `exec` command chứa token hoặc arbitrary EVE
signature để shell evaluate. Logging struct fields qua slog, no interpolation
vào nft identifiers/command args từ unvalidated strings.

## 5. Snapshot/CAS algorithm của session context

Implementation `UpdateInspection`:

```text
lock store
find active session by SessionID; absent -> SESSION_MISSING
compare supplied incarnation with stored identity (not only ct_id)
if mismatch -> STALE_INSPECTION
if runtime/stored policy generation is newer -> STALE_GENERATION
if current inspection revision != expectedInspectionRevision -> STALE_INSPECTION
validate next.generation == expectedGeneration
nextCopy = DeepClone(next)
nextCopy.revision = expectedInspectionRevision + 1 (check overflow)
stored.inspection = nextCopy
stored.revision++ ; store.revision++
recompute EffectiveDecision from base + active applied guard
copy stored snapshot
unlock
return copy
```

Runtime/coordinator gate kiểm tra `expectedGeneration==CurrentGeneration`
trước gọi store; store không import engine để đọc current generation. Commit
và observation publication cùng serialization gate, tránh check-then-CAS race.
Revision nil inspection quy ước0. Không bump `LastSeen` traffic hoặc byte counters
chỉ vì EVE/health/candidate thay đổi. Event quan sát không làm session sống lâu
hơn kernel timeout trong M2.

`ResolveCandidates` chỉ copy tối đa8 candidates. Nếu index có nhiều hơn8,
trả truncated/AMBIGUOUS; không chọn một trong8 vì số9 bị bỏ. Missing trusted
kernel start không chuyển raw `KernelStart` sang wall-time bằng đoán đơn vị;
adapter CT phải cung cấp provenance thời gian; không có thì quality PARTIAL.

## 6. Orchestrator algorithm chi tiết

```text
HandleObservation(obs):
  reject wrong/expired source epoch for automatic effects
  classify discovery using trusted manifest; not msg text
  if threat: store.Add(event normalized from obs) idempotently
  if no observed timestamp/tuple: keep event uncorrelated; return
  resolution = resolver.Resolve(obs)
  if unresolved: schedule bounded retry; return
  if recent closed: update correlation only; return
  read current session clone and current program under mutation gate
  selection = SelectInspection(currentProgram, sessionForwardView)
  if local/ambiguous zones/selection unresolved:
      attach only safe metadata; enforcement UNAVAILABLE; return
  if obs capture mode/source no longer corresponds to current selection:
      keep historical event; mark coverage PARTIAL; no automatic guard
  next,intents,notifications = ReduceInspection(...)
  CAS next; stale -> up to2 bounded re-reads
  emit notifications only after success; failed CAS still keeps threat event
  queue intents using unique key(session,incarnation,generation,reason)
```

Mode context chuyển IDS→IPS không được đổi alert IDS cũ thành IPS verdict.
Event tới sau commit phải reevaluate **current** restriction; không giữ policy
ID từ event như authority. Automatic guard chỉ từ observation hợp lệ sau
activation fence hoặc từ previously trusted app snapshot được explicit
reevaluate trong activation. Không phát lại old-generation enforcement intent.

Correlation revision update không trigger `threat_count++` lần hai. Count
theo `event_id` attached; context giữ bounded recent IDs hoặc store cung cấp
attach idempotency record, không tạo unbounded map per session.

Enforcement worker:

```text
take activation/mutation gate (not global session lock)
read session; verify incarnation/generation/current selection
targeted conntrack.Get -> same identity or abandon
build exact key; preflight capacity
perform nft add+verify with2s context
read session again; verify still same target
success: record APPLIED SESSION guard, invalidate base explanatory cache
failure: record FAILED/UNAVAILABLE; keep desired denial separate from applied
stale after IO: cleanup only owned key, do not remove other owner's block
release gate
publish event outside locks
```

Kernel compound key không chứa full `kernel_start`; không có transaction chung
cho netlink Get + nft mutation. Key/TTL và before/after checks giảm khả năng
apply nhầm; phải test CT-ID/tuple reuse và công bố giới hạn khi identity không
đủ, không tự hứa một guard ID-only là proof incarnation. Missing/conflicting
identity phải không auto-enforce. M3 không tạo source-IP blanket block để né lỗi.

## 7. Truth table: state hiển thị và action thực tế

| Mode/source | Observation | UI verdict | Kernel action do M3 engine |
|---|---|---|---|
| OFF | none | Not inspected | none |
| IDS | signature allowed | ALERT | none |
| IDS | unexpected blocked/action | UNKNOWN + diagnostic | none |
| IPS | allowed, no packet verdict | ALERT; packet action unknown | none |
| IPS | allowed + packet verdict drop | DROP, REPORTED/PACKET | none thêm; Suricata đã quyết định |
| IPS | blocked + missing final verdict | DROP reported by signature, final_packet_verdict unavailable | none thêm |
| IPS/app restriction | known mismatch, nft pending | MISMATCH; enforcement pending | enqueue exact guard |
| IPS/app restriction | guard ACK/readback | DROP, APPLIED/SESSION | exact guard |
| IPS/app restriction | nft failed | MISMATCH; enforcement FAILED | không giả success |
| IDS/IPS | sensor down, no app evidence | Unavailable; UNKNOWN_ALLOWED nếu pending timeout | base policy vẫn quyết định |

`latest_verdict=DROP` là bằng chứng detector từng báo drop; không thay thế
current effective connectivity decision. Threat details phải ghi thời gian và
scope để UI không hiểu session hiện còn block khi đó chỉ là packet cũ.

## 8. API JSON mẫu để viết contract tests

### 8.1. Session inspection fragment

```json
{
  "session_id": "session-opaque-id",
  "inspection": {
    "generation": 12,
    "revision": 3,
    "profile_id": "m3-ids-basic",
    "mode": "IDS",
    "state": "INSPECTING",
    "coverage": "OBSERVED",
    "reason": "protocol observed by Suricata",
    "application": {
      "name": "HTTP",
      "source": "SURICATA_APP_PROTO",
      "confidence": "HIGH",
      "revision": 1,
      "conflicted": false
    },
    "app_policy_state": "NOT_APPLICABLE",
    "threat_count": 0,
    "latest_verdict": "UNKNOWN",
    "enforcement": {
      "mechanism": "NONE",
      "status": "NOT_REQUESTED"
    },
    "missing_evidence": []
  }
}
```

SessionResponse public giữ existing envelope và original/reply/translated NAT
fields; fragment này không thay whole RuntimeSession JSON. Test normalized
missing inspection bằng null/absent; không assume tất cả session đã inspect.

### 8.2. Security cursor payload

```json
{
  "items": [],
  "next_cursor": "engine-stream-uuid:100",
  "has_more": false,
  "oldest_sequence": 80,
  "stream_id": "engine-stream-uuid",
  "gap": true,
  "evicted_count": 79
}
```

Canonical wire cursor dùng string `<stream_id>:<sequence>`; request có thể gửi
`after_sequence` + `stream_id` như master. Decoder validates decimal unsigned,
unknown stream→reset_required/gap response, không 500. Internal Go uint64;
client không convert opaque cursor thành JS number. `sequence` numeric field
hiện có giữ compatibility, add opaque cursor cho mọi tính toán mới.

### 8.3. WebSocket envelope mới

```json
{
  "schema_version": 1,
  "kind": "SecurityAlert",
  "event_class": "security",
  "stream_id": "runtime-stream-uuid",
  "sequence": 47,
  "timestamp": "2026-09-22T12:00:00Z",
  "payload": {
    "event_id": "source-record-hash",
    "session_id": "session-opaque-id",
    "correlation_revision": 1
  }
}
```

Runtime ring và security store là hai sequence domains khác nhau: **không** dùng
WS sequence47 làm after_sequence47 cho security REST. Dùng event_id lookup hoặc
security cursor lưu riêng. Nếu cần một cursor xuyên hệ thống, phải thiết kế
explicit; MVP giữ hai cursor và một engine boot UUID làm prefix khác loại.

## 9. Test factories: fixture nhỏ dễ dùng

Tạo helper chỉ trong `_test.go`:

- `testSession(id, original, reply, kernelStart)` dùng domain.Tuple thật.
- `testObservation(sensor, epoch, offset, flowID, tuple, observedAt)` không dùng
  `time.Now()`; fixed clock `2026-09-22T12:00:00Z`.
- `newFakeClock()`, `Advance(duration)`, signal barrier để tránh sleeps.
- `fakeSink` records accepted/dropped and bytes budget.
- `fakeNft` records transactions, can fail call N/apply/verify separately.
- `fakeCT` returns targeted identity, supports replace between first/second Get.
- `fakeFileSource` script open/read/rename/truncate/errors; retains file IDs.
- `fakeSensorControl` expected handshake and responses+deadline.
- `assertNoActivation` checks apply count0, version unchanged, audit noCOMMIT,
  not merely HTTP status200.

Factory không tự gán unknown field thành known; mỗi testcase explicit missing
fields để phát hiện regression “zero nghĩa success”. Không export fake constructors
vào cmd để chạy demo giả như real runtime.

## 10. Quy ước commit coordinator để không tạo backend thứ hai

Vẫn duy nhất RuntimeServiceAdapter + config.Manager giữ activation contract.
Không thêm endpoint commit riêng cho M3 hoặc service viết running.json ngoài
Manager. Có thể refactor nội bộ Manager thành prepare/publish để chốt thứ tự:

```text
validate expected/current generation + candidate
prepare target Program + Selection + compiler options + journal snapshot
acquire activation gate, pause automatic M3 intents
apply target network + nft static bundle using existing Controller
reconcile target app guard claims (manual M2 guards untouched)
persist authoritative Running through config.Manager
publish prepared runtime snapshot (no further external IO)
finalize journal + receipt, unpause; return success
```

Allocation/validation có thể lỗi phải làm trước kernel mutation. Runtime publish
cuối là swap snapshot đã kiểm tra dưới lock, không gọi detector/systemctl/network.
Nếu publish vẫn có error vì invariant, coi là activation failure, không bỏ qua.

Error trước Running publish: restore previous kernel/config authority; không
làm version lùi. Error sau Running publish: restore via new generation, ghi
receipt/error rõ; request retry không thực hiện lại như một commit mới.
Rollback dùng cùng coordinator với previous config làm target và fresh monotonic
generation; không chỉ restore file. Journal outer activation giữ tới khi Running
và runtime đều finalize, không để Controller tự xóa bằng chứng quá sớm.

Thứ tự phần này là phiên bản chi tiết của master11. Tests phải cover crash ngay
trước/sau Running publish và guard reconcile; chỉ restore nft mà quên guard
claim/context là FAIL.

## 11. Mỗi task hoàn tất phải trả báo cáo này

```text
Task ID:
Files created/modified:
Contract/functions implemented:
Behavior changed:
Commands actually executed:
Exit codes + test counts:
Evidence files:
Remaining blocker/NOT_RUN:
Next eligible task:
```

Nếu task dài hơn khả năng context của agent, dừng ở boundary function+test đã
build được và ghi chính xác function còn thiếu. Không dùng “đã hoàn thành phần
lớn” thay cho status từng function/task; không tự đánh dấu milestone complete.

## 12. Signature seed cho T16 và assertions cụ thể

Các rule sau là input khởi đầu để T16 syntax-test/replay với pinned binary,
**chưa được chạy Suricata trong bước viết tài liệu**. Không bỏ bước kiểm chứng.

`app-discovery.rules` seed:

```text
alert tcp any any -> any any (msg:"NGFW metadata HTTP"; app-layer-protocol:http; sid:9900001; rev:1;)
alert tcp any any -> any any (msg:"NGFW metadata TLS"; app-layer-protocol:tls; sid:9900002; rev:1;)
alert udp any any -> any any (msg:"NGFW metadata DNS"; app-layer-protocol:dns; sid:9900003; rev:1;)
alert tcp any any -> any any (msg:"NGFW metadata SSH"; app-layer-protocol:ssh; sid:9900004; rev:1;)
```

Nếu binary emit discovery nhiều lần thì giới hạn bằng strategy đã syntax-test
(protocol detection state/flowbits) và parser dedup discovery. Không dùng generic
suppression theo source IP vì sẽ nuốt discovery của connection khác. TCP DNS
lấy EVE DNS metadata; nếu cần thêm discovery SID, thêm manifest entry/test,
không hardcode toàn khoảng SID là trusted internal trong parser.

`ids-demo.rules` seed và bản IPS chỉ đổi action literal đầu rule:

```text
alert tcp any any -> any any (msg:"NGFW safe integration marker"; content:"NGFW_M3_TEST_"; sid:9900100; rev:1;)
drop tcp any any -> any any (msg:"NGFW safe integration marker"; content:"NGFW_M3_TEST_"; sid:9900100; rev:1;)
```

Hai dòng ở trên thuộc **hai file/instance khác nhau**, không load cùng một SID
hai lần trong một sensor. Fixture chuyển nonce ASCII theo pattern vào stream.
Không chạy rule test trên traffic ngoài lab; đây là marker dễ cố ý trùng, không
được quảng cáo như signature phát hiện tấn công thực tế.

Expected assertions cho fixture có one HTTP connection:

1. Before FIN: ít nhất một HTTP application observation của đúng sensor flow.
2. Discovery record không xuất hiện trong SecurityEventStore.
3. Khi gửi marker: alert9900100 xuất hiện, app HTTP nếu đã được xác định.
4. Replay cùng source file offset: same event_id và count không tăng.
5. Gửi marker lần hai (physical event mới): different event_id, count tăng.
6. IDS real capture: marker đến server. IPS offline simulation chỉ parse action;
   phải có NFQUEUE traffic test riêng mới chứng minh marker bị drop.
7. Split marker trên2 TCP segments: reassembly behavior được test và ghi rõ;
   không “sửa” test thành one-packet chỉ để rule dễ pass.

Nguồn keyword đã đối chiếu: [Suricata app-layer-protocol](https://docs.suricata.io/en/suricata-7.0.15/rules/app-layer.html).
