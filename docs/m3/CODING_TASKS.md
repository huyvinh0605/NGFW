# M3 — Các task code nhỏ, thực hiện tuần tự

Contract gốc: [M3_IMPLEMENTATION_PLAN.md](../M3_IMPLEMENTATION_PLAN.md).
Types/algorithms/JSON/error codes chi tiết: [CODE_CONTRACTS.md](CODE_CONTRACTS.md).
Đây là chỉ dẫn triển khai, không phải báo cáo các task đã hoàn tất.

## Quy tắc dùng cho tất cả task

- Làm một task một lần. Không đọc một task rồi viết toàn bộ M3 theo suy đoán.
- Chạy test hành vi của task trước khi nối task tiếp theo. Chưa có Linux thì
  code/test fake được, nhưng đánh dấu probe Linux `NOT_RUN` và chưa mở gate phụ thuộc.
- Tên hàm dưới đây là contract dự kiến. Nếu tên có sẵn, mở rộng hoặc viết adapter,
  không tạo hai implementation với cùng trách nhiệm.
- Dùng Clock interface ở timeout code, CommandRunner ở exec code, FileSource ở
  reader, fake NftApplier ở enforcement. Fake không được thay production adapter.
- Test phải assert output/state/side effect/không có side effect; tránh chỉ
  assert function đã được gọi hoặc snapshot chứa chữ `queue`.
- Record lỗi dùng error code ổn định; text thêm session/policy ID nhưng không
  payload/token. Không nuốt lỗi bằng `return nil` để suite xanh.
- Mỗi task cập nhật status: `NOT_STARTED`, `IN_PROGRESS`, `LOCAL_PASS`,
  `LINUX_PROBE_PASS`, `BLOCKED`; live acceptance dùng ma trận riêng.

## T00 — Chụp baseline và tạo sổ triển khai

**Dependency:** không có.

**Files:** tạo `docs/m3/IMPLEMENTATION_STATUS.md`; đọc toàn bộ file trong bảng
audit master; không sửa production.

1. Ghi `git rev-parse HEAD`, `git status --short`, Go/Node/npm/OS versions.
2. Ghi những file có thay đổi trước M3 để không reset/overwrite việc người dùng.
3. Chạy Go tests/vet và web tests/build hiện tại một lần. Lưu raw output và exit
   code vào evidence baseline; không commit dependency cache.
4. Tạo bảng T00–T31 với dependency, status, command, evidence, ghi chú.
5. Nếu baseline fail, phân loại reproducer (source/platform/missing dependency),
   sửa blocker có test trong thay đổi riêng. Không gọi fail cũ là lỗi M3.
6. Tạo `docs/adr/0003-m3-inspection-pipeline.md` bằng quyết định master: NFLOG IDS,
   NFQUEUE IPS, engine ownership, RESTRICT_L3_ALLOW, fail-open, no new mark bits.

**Check:** `go test -count=1 ./...`, `go vet ./...`, web `npm test`, `npm run build`.
**Done:** có baseline thật hoặc blocker cụ thể; chưa claim VM đã pass.

## T01 — Probe khả năng Linux trước khi code compiler IPS

**Dependency:** T00. Cần Ubuntu isolated VM/netns; có thể viết domain trong khi chờ.

**Files mới:** `tests/integration/m3/probe-capabilities.sh`,
`deploy/inspection/compatibility.json` (manifest phiên bản đã test, không placeholder PASS).

1. Script đọc version/package/build-info; không tự install/upgrade.
2. Kiểm tra NFLOG, NFQ, Unix socket và supported protocols của binary đã cài.
3. Trong temporary network namespace có trap delete đúng namespace vừa tạo,
   chạy `nft -c` cho set compound app guard và lease set master đã quy định.
4. Probe thật: two forward base chains priority 0/+10, chain trước accept,
   chain sau drop; traffic phải bị drop. Làm lại với mark cache và runtime block.
5. Probe NFLOG group 100 nhận hai chiều, cùng tuple trước SNAT/sau DNAT.
6. Probe NFQUEUE 100 listener absent + bypass: base allow đi được; base deny
   vẫn không đi. Probe listener chạy, verdict marker drop, counters thật.
7. Check `nfq.fail-open: yes` được binary/kernel chấp nhận. Test queue saturation
   trong isolated lab; không chỉ grep YAML. Ghi giới hạn quan sát kernel.
8. Ghi exact Suricata distro version/hash và template/rule compatibility.
   Thiếu support → BLOCKED capture/IPS; không tự đổi sang mirror AF_PACKET.

**Tests:** namespace trap chạy khi command fail; preflight không đổi host config;
missing binary → exit 2; probe fail → exit 1, không PASS.
**Done:** G-LINUX-CAPABILITY PASS trước nối queue compiler và service production.

## T02 — Domain enums, zero values và clone

**Dependency:** T00.

**Tạo:** `internal/domain/inspection.go`, `security_event_m3.go`,
`inspection_test.go`. **Sửa:** `session_m2.go`, `runtime_events.go`.

**Symbols:** `ApplicationSource`, `ApplicationConfidence`, `InspectionMode`,
`InspectionState`, `CoverageState`, `AppPolicyState`, `CorrelationState`,
`EnforcementStatus`; `Valid()` cho từng enum; `UnknownApplication()`;
`SessionInspection.Clone()`, `ThreatEvent.Clone()`.

1. Khai báo field đúng bảng master phần 5, JSON tags snake_case.
2. Không zero-value thành HIGH/ALLOW/CLEAN; `NormalizeZero` chỉ chuẩn hóa UNKNOWN.
3. Thêm `RuntimeSession.Inspection *SessionInspection` và deep clone pointers,
   sources/missing_evidence/metadata. Không giữ map/slice chia sẻ giữa callers.
4. Threat severity UNKNOWN là giá trị explicit; không sửa `Severity.Weight`
   của legacy risk để phát triển risk M3.
5. Thêm runtime event kinds, class `inspection`, optional `event_id`,
   `inspection_revision`; không nhét whole ThreatEvent vào mỗi notification.

**Tests:** zero/nil safe, JSON round-trip all enums, invalid enum rejected ở
validator, clone isolation, flow_id lớn dạng string còn nguyên, optional
timestamp/packet verdict không thành giá trị giả.
**Check:** `go test -count=1 ./internal/domain/...`.

## T03 — Config schema/defaults/validation

**Dependency:** T02.

**Tạo:** `internal/domain/inspection_config.go`, `internal/config/inspection.go`,
`internal/config/inspection_test.go`. **Sửa:** domain/types.go, config/file.go,
manager.go và config clone helpers nếu có.

**Symbols:** `InspectionConfig`, `InspectionLimits`, `InspectionProfile`,
`DefaultInspectionLimits()`, `EffectiveInspectionConfig(config)`,
`ValidateInspection(config) []string`, `UsesM3(config) bool`.

1. Defaults trên copy; không mutate Config khi Validate/GET/Load.
2. Explicit application_match_mode, profile mode/fail_mode/ruleset allowlist.
3. Validate dependency global/profile/policy theo master 4.3.
4. Enforce limits cả count và bytes; invalid/negative phải có field path.
5. Profile legacy unreferenced vẫn lưu được; policy enabled reference legacy
   DECRYPT/risk/profile thiếu M3 config bị từ chối.
6. API validator và engine validator gọi cùng hàm. `UsesM3` dựa vào effective
   inspection/profile usage, không dựa vào file Suricata có tồn tại.
7. Đừng xóa `CompileM2` milestone checks; entrypoint M3 sẽ được thêm T05.

**Tests:** all validation errors phần 4; m2-lab JSON load→save semantics unchanged;
disabled config không cần sensor; validate không gọi command/file mutation;
candidate edit invalidates old validation revision; bounds+overflow.
**Check:** domain + config tests.

## T04 — Duplicate/shadow validation có application restriction

**Dependency:** T03.

**Sửa:** `internal/config/policy_canonical.go`, `policy_reachability.go`, tests.
**Symbols mới:** `ProfileEffectiveKey(profile)`,
`EffectivePolicyKey(config, policy)`, `M3UnreachablePolicyErrors(config)`.

1. Reuse canonical services/CIDR/zone sets; sort/dedup enum apps uppercase.
2. Key bao gồm action/scope/app mode/apps/profile semantics; bỏ ID/name/priority.
3. Profile ID khác nhưng effective profile bằng nhau không giúp né duplicate.
   Resolve ID case-sensitive; không lowercase ID rồi tìm nhầm.
4. Shadow theo **L3 first-match** của RESTRICT_L3_ALLOW: rule sau cùng L3 dù app
   list khác cũng unreachable; subset services/address dùng existing cover logic.
5. Phân biệt lỗi exact duplicate với unreachable, trả cả policy IDs.
6. Giữ existing M2 entrypoints wrapper để tests/callers cũ build được; production
   Validator/RuntimeService sử dụng config-aware validation mới.

**Test mẫu:** LAN→WAN tcp80 apps HTTP priority10, cùng L3 apps TLS priority20
→ unreachable; tcp80 rule rồi tcp443 rule → valid; reorder service list vẫn
duplicate; disabled semantics như M2; hai profile có name khác vẫn duplicate.
**Check:** `go test -count=1 ./internal/config/...`.

## T05 — Shared connectivity selectors và compile dispatch

**Dependency:** T03/T04.

**Tạo:** `internal/connectivity/selectors.go`, `inspection.go`, tests.
**Sửa:** program.go; dataplane render helpers chỉ refactor khi tests chứng minh.

**Symbols:** `CompileForCapabilities(config,generation,caps)`,
`CompileM3(config,generation)`, `SelectInspection(program,view)`,
`InspectionSelection{PolicyID,ProfileID,Mode,AllowedApps,Generation}`.

1. `CompileM2` giữ reject M3. `CompileForCapabilities` chọn CompileM2 khi OFF;
   M3 unsupported capability → error, không silently discard fields.
2. CompileM3 validate restriction rồi tạo connectivity program base bằng cùng
   parser/matcher; giữ source config nguyên vẹn, không strip fields ở Manager.
3. `Program` chứa immutable lookup profile/selection, Clone đủ map/slices.
4. Empty apps→no app restriction. L3 deny không có selection.
5. Infer zones/NAT view dùng existing function, không copy thêm evaluator ở API.
6. CPU matching và nft render cùng service selector output; OR semantics giữ.

**Tests:** M2 golden behavior; all zone/address/service/priority/default deny;
source/dest reverse + NAT; apps không mở L3 deny; unsupported fields fail.
**Check:** connectivity + config + dataplane existing tests.

## T06 — Fixture EVE thật, typed parser và timestamp

**Dependency:** T02.

**Tạo:** `internal/inspection/eve/types.go`, `parser.go`, `parser_test.go`,
fixtures `tests/fixtures/suricata/{alert,flow,http,dns,tls,ssh,stats,...}.jsonl`.

**Symbols:** `SourcePosition`, `RawEnvelope` private,
`ParseLine([]byte, SourcePosition) (inspection.Observation,error)`,
`ParseTimestamp(string)`, `ParseProtocol(string)`, `NormalizeTuple`.
Contracts Observation/SourceHealth đặt `internal/inspection/source.go` để
eve import inspection mà inspection không import eve (tránh cycle).

1. Parser decode fields typed; null/missing optional dùng pointer/presence.
2. Tests timestamp offset +0000, Z, +07:00, fractions và timestamp sai.
3. Decode uint64 flow ID 9007199254740993 chính xác; export string.
4. Event alert.action khác packet verdict phải giữ riêng.
5. Ignore unsupported event type, không count như malformed JSON.
6. Bound string/metadata và mark truncation; don't retain raw payload.
7. Protocol/port malformed → tuple unavailable, không cast int sang uint16 trước
   range check. Valid alert tuple hỏng vẫn thành event uncorrelated.
8. Stats không có tuple/flow_id là bình thường. Flow record không có alert
   không sinh security event.

**Tests:** valid all types, absent/invalid required fields, IPv4/IPv6 parsing,
mixed family, multiline caller misuse, bad JSON→error, long strings, unknown
severity, allowed+verdict drop, blocked in IDS diagnostic, no panic.
**Check:** `go test -count=1 ./internal/inspection/...`.

## T07 — Event identity và dedup

**Dependency:** T06.

**Tạo:** `eve/identity.go`, `identity_test.go`.
**Symbols:** `EventID(SourcePosition, []byte) string`, `Deduper.SeenOrAdd(id,now)`.

1. Key serialize length-delimited/binary struct hoặc canonical JSON rồi SHA-256,
   không concat raw fields có delimiter collision.
2. Include sensor epoch, file generation và byte offset, không ingestion time.
3. LRU bounded count/bytes + TTL; cleanup budget, no per-event timers.
4. Separate discovery dedup key `(sensor,epoch,flow,app,direction)`.
5. Threat IDs preserve repeated attack occurrences dù SID/timestamp cùng nhau
   khi source record offset khác.

**Tests:** replay ID stable, different offset→different ID, different sensor/
epoch→different ID, count limit, TTL, discovery repeated, concurrency nếu share.
**Check:** eve tests.

## T08 — File reader, rotation và checkpoint

**Dependency:** T06/T07.

**Tạo:** `eve/reader.go`, `checkpoint.go`, `file_linux.go`,
`file_portable.go`, lifecycle tests; OS-specific file identity behind interface.

**Symbols:** `FileSource`, `OpenedFile`, `CheckpointStore`, `Reader.Run`,
`readCompleteLine`, `handleRotation`, `saveCheckpoint`.

1. Implement state machine master 7.2; test each transition bằng fake clock/files.
2. Reader emits complete line với offset đầu và generation trước increment.
3. Reader quá line limit discard cho tới newline; không kill ingestion mãi.
4. Checkpoint persist atomic temp+fsync+rename; fail→degraded, continue bounded,
   không làm firewall fail. Fake checkpoint error có test.
5. Linux check inode/device; portable tests mô phỏng identity, không mock bằng
   filename cố định làm rotation tests vô nghĩa.
6. Start EOF historical vs new epoch from0; catch-up budget, loss reason explicit.
7. Ensure file descriptors/timers closed on all error/cancel branches.

**Tests:** append partial newline, CRLF, rename while old fd has tail, absent new
file, copytruncate, inode reused/fingerprint mismatch, oversize then good,
checkpoint replay, permission denied/backoff, cancellation during idle/backoff,
queue overflow counter, goroutine exit barrier (không đếm runtime goroutines tùy ý).
**Check:** eve unit + `go test -race ./internal/inspection/eve` trên Linux.

## T09 — Sensor manifest và health/control client

**Dependency:** T02/T06; control probe thực tế phụ thuộc T01.

**Tạo:** `internal/inspection/sensor/manifest.go`, `control.go`, `health.go`, tests.

**Symbols:** `SensorManifest`, `LoadManifest`, `ControlClient.Probe(ctx)`,
`HealthReducer`, `CaptureLive(now)`, `HealthSnapshot()`.

1. Fixed sensor IDs ids/ips, fixed managed root; manifest version/checksum/epoch.
2. JSON malformed/path escapes/symlink ngoài root rejected. Read max64KiB.
3. Unix control client obey documented handshake/command-list for pinned binary;
   commands fixed allowlist, response cap64KiB, deadline500ms.
4. Derive process/liveness/reader health separately. Zero alert count không down.
5. New manifest epoch resets flow bindings eligibility, không xóa security history.
6. Stats heartbeat stale6s, hysteresis recovery 2 successful probes tránh flapping.
7. Capture stalled detection cần backlog evidence + no progress; no traffic idle
   healthy. Failed control alone reports uncertainty; lease policy theo master.

**Tests:** absent disabled→DISABLED, enabled absent→UNAVAILABLE, reader parse
burst→DEGRADED, quiet healthy, stale heartbeat, wrong artifact mode, reconnect,
epoch changes, timeout/bounded reply, unknown control command gracefully error.

## T10 — Application identity normalization/reducer

**Dependency:** T06/T09.

**Tạo:** `internal/inspection/application.go`, `application_test.go`.
**Symbols:** `NormalizeApplication(raw)`, `ApplicationFromObservation`,
`MergeApplication(previous,next)`, `InspectBoundedBytes(protocolHint,bytes)`.

1. app_proto http/tls/dns/ssh → enums; failed/unknown→UNKNOWN; others→OTHER+raw.
2. EVE metadata map to HTTP host/method, TLS SNI/version/ALPN, DNS query/type,
   SSH banner (bounded). Cert absent stays unavailable; no TLS decryption claim.
3. Discovery SID map from manifest; not security events.
4. Merge deterministic source/confidence/time, conflict handling master9.
5. BoundedBytes helper reuse DNS/TLS/HTTP parser only when bytes provided;
   no socket capture, no reader of conntrack payload. It is helper capability,
   not production fallback when Suricata is dead.

**Tests:** HTTP request/response, real ClientHello fixture, malformed/truncated
TLS, DNS req/resp, SSH banner, random/empty bytes, wrong port, parser error→UNKNOWN,
TLS remains TLS, lower-confidence no downgrade, late out-of-order, STARTTLS
transition, same-time contradiction marks conflicted, flow source confidence.

## T11 — Session context update và recent lookup

**Dependency:** T02/T10.

**Tạo:** `internal/session/inspection.go`, `recent_lookup.go`, tests.
**Sửa:** runtime_store.go merge/close/cleanup clone boundaries.

**Symbols:** `UpdateInspection` (signature master9),
`ResolveCandidates(key,observedAt,limit)`, `ResolveRecent(key,time,limit)`.

1. Store lock: verify session exists, incarnation same, generation not stale,
   expected inspection revision đúng; then clone next and bump revisions.
2. Không reject chỉ vì packet counter revision đổi; không overwrite counters.
3. Merge conntrack record giữ pointer context bằng copy; raw CT không author M3.
4. Recent lookup/index nằm trong RuntimeStore và cleanup M2, not second DB.
5. Active alias ambiguity trả candidates/error, không choose first map iteration.
6. Destroy record không bị EVE cập nhật thành active; recent update chỉ metadata
   ở closed record hoặc event correlation, không reinsert active indexes.

**Tests:** CAS stale gen/inspection rev; CT update keeps context; clone mutation
doesn't leak; NEW/UPDATE/DESTROY concurrent observation; closed TTL removes index;
max closed bound; API Query copy safe during merge.
**Check:** session tests + race.

## T12 — Correlation và bounded pending retry

**Dependency:** T07/T11.

**Tạo:** `internal/inspection/correlation/resolver.go`, `bindings.go`, tests.
**Symbols:** `SessionLookup` interface, `Resolver.Resolve(obs)`,
`BindingKey`, `PendingCorrelations.Add`, `RetryDue(now,budget)`.

1. Follow master8 exactly. Binding stores SessionID+incarnation, not full session.
2. Sensor source scope explicitly current namespace/ctzone0; no IP-only guesses.
3. Check observed event lifetime against original identity, not ingestion time.
4. Try observed tuple and flow tuple; contradictions→AMBIGUOUS.
5. Active/recent matches compete if time overlaps; active alone không được
   tự ưu tiên bỏ late event của closed session cùng tuple.
6. Pending retry same event ID, bounded2s/2048; expiration preserves alert.
7. Before enforcement only CORRELATED active strong identity qualifies.

**Test matrix:** plain/reverse/SNAT/MASQ/DNAT/doubleNAT; UPDATE-before-NEW;
event-before-CT then match; destroyed/reused tuple; same flow_id new sensor epoch;
two matching aliases; time outside interval; missing kernel start; CT zone
mismatch; ICMP incomplete; pending capacity/expiry; replay count once.

## T13 — Bounded security event store và query

**Dependency:** T02/T07.

**Tạo:** `internal/engine/security_events.go`, tests.
**Symbols:** `SecurityEventStore.Add`, `UpdateCorrelation`, `Get`, `Query`,
`Stats`, `SecurityQuery`, `SecurityEventPage` (DTOs trong domain).

1. O(1) circular ring, ID→slot index; evict removes index and byte accounting.
2. Enforce count **và** bytes. Normalize event size trước insert.
3. stream_id random once/engine boot; monotonic sequence local store.
4. Add duplicate same source ID idempotent, repeated physical occurrences not
   collapsed. Correlation update giữ event ID/sequence, tăng revision.
5. Query snapshot/copy under short lock, filtering/cursor outside heavy lock.
6. Filter/cursor semantics master13; no whole-ring response; report gap.
7. Không ghi toàn raw payload vào disk để làm event persistence vội.

**Tests:** capacity/bytes eviction, ID removal, duplicate, pagination across
nonmatching records, invalid/oversized limit, cursor gap/reset, concurrent
Add/Get/List/update, malformed display strings retained as text.

## T14 — Pure orchestrator reducer và intent model

**Dependency:** T05/T10/T12/T13.

**Tạo:** `internal/engine/inspection_reducer.go`, tests;
`internal/domain/inspection_intent.go` nếu contract cần share.

**Symbols:** `ReduceInspection`, `EvaluateAppRestriction`,
`ComputeEffectiveDecision`, `InspectionIntent`.

1. Inputs immutable session+selection+observation+time. Returns next context,
   event changes, zero/more bounded intents. Không IO/log/file/socket.
2. State transitions master4/5; IDS alert cannot create guard intent.
3. Threat count increments once per unique event; discovery không increment.
4. UNKNOWN/high-source missing/ambiguous cannot automatic guard.
5. app mismatch only requires guard for same generation selected ALLOW + IPS.
6. Packet verdict DROP recorded separate; no automatic IP block.
7. EffectiveDecision preserves applied session restrictions and manual revoke,
   but never turns failed guard request into enforced DROP.

**Tests:** toàn decision table master4, pending timeout with fake time, late app,
newer gen, conflicting evidence, repeated event, IDS/IPS same alert behavior,
old CT cached allow cannot overwrite applied guard, failed guard honest state.

## T15 — Wire coordinator vào Runtime

**Dependency:** T08/T09/T11/T12/T13/T14.

**Tạo:** `internal/engine/inspection_runtime.go`, tests.
**Sửa:** runtime.go, runtime_events.go; chưa wire Linux commands.

**Symbols:** `InspectionRuntime.Start/Stop`, `TrySubmit`,
`OnSessionChanged`, `OnSessionClosed`, `BeginActivation/EndActivation`,
`Health`, `HandleObservation`.

1. Construct nil/disabled coordinator safe với M2. One bounded queue + byte budget.
2. Session callbacks from applyRecord/close only enqueue lightweight reference,
   no blocking file/netlink. Handle overflow telemetry + periodic bounded sweep.
3. Single coordinator processing loop reads/merges; workers riêng cho IO enforcement.
4. Per-session deadline map bounded by MaxSessions; cleanup on close/invalidate;
   no timer goroutine per flow. Sweep budget512 mỗi tick.
5. CAS retries2; preserve event on stale merge; no resuscitation closed session.
6. Notify bus/rings ngoài global lock; shutdown cancel readers/workers and Wait.
7. Activate gate prevents stale-generation intent apply while commit in progress.

**Tests:** fake EVE→same runtime session; API kill simulation doesn't stop
tracking; consumer slow/full; same generation counter updates; session removed
during processing; resync+commit+EVE concurrent; cancellation/no goroutine leak.

## T16 — Capture YAML, builtin rules và offline replay

**Dependency:** T01/T06/T10.

**Tạo:** `deploy/inspection/{ids.yaml,ips.yaml,manifest.json,app-discovery.rules,
ids-demo.rules,ips-demo.rules}`; safe fixtures/PCAP builder dưới `tests/fixtures/m3`.

1. Use pinned package template includes/paths; HOME_NET reflect lab via validated
   deployment settings, not hard-code prod networks. EXTERNAL_NET=any khi demo
   cần inside-to-DMZ; document rule scope. Không feed download implicit.
2. One group100 in IDS YAML, full capture copy range; correct EVE/control config.
3. IPS queue100 + workers + fail-open flag; no pass/bypass/repeat/mark writes.
4. Discovery early signals HTTP/TLS/DNS/SSH, bounded per direction; verify actual
   EVE app_proto before close. Không áp test fixture giả thay output sensor.
5. Demo marker exact match with URI/body marker controlled; no exploit payload
   cần remote target. IDS alert file, IPS drop file, same SID semantics manifest.
6. `suricata -T` both configs; offline PCAP replay có checksum/stream đúng.
   PCAP simulation IPS output **không** phải proof kernel inline drop.
7. Test expected EVE record modes/action/source SID; normalize parser matching.

**Done:** real binary replay + hashes. Nếu capture source chỉ có flow-close
event, App-ID LIVE gate fail; sửa discovery trước task app-policy acceptance.

## T17 — nft table schema + RulesetBundle

**Dependency:** T01/T05.

**Tạo:** `dataplane/inspection_schema.go`, `ruleset_bundle.go`, tests.
**Sửa:** nft.go interfaces/adapters; giữ wrappers ApplyRuleset M1/M2.

**Symbols:** `RulesetBundle`, `EnsureInspectionSchema(ctx)`,
`ApplyBundle(ctx,bundle)`, `VerifyBundle(ctx,expected)`.

1. New ngfw_inspection only; schema ownership/version recorded comment metadata.
2. Create sets and chains -15/+10 empty in one batch, verify typed schema readback.
3. Existing schema mismatch returns actionable error unless explicit migration
   with tests; do not flush unknown table on first load.
4. Compose policy transaction across inet ngfw + static inspection chains; don't
   run independent apply nft batches for two policy halves.
5. Dynamic M2 source/revoke and M3 lease/guard sets survive static replacement.
6. Root-owned namespace table operations scoped. Runtime mutation mutex shared
   with bundle apply; no apply/query global engine lock.
7. nft verify output uses JSON bounded decode or exact commands, not grep accept
   and assume generation correct.

**Tests:** absent/present/old/malformed schema; nft -c failure no target apply;
atomic transaction content, no runtime sets flush; preserve block timeout;
partial ensure cleanup only created objects; readback error returned.

## T18 — Inspection selector compiler

**Dependency:** T05/T16/T17.

**Tạo:** `dataplane/inspection_plan.go`, `compiler_m3.go`, tests.
**Symbols:** `CompileInspectionPlan`, `RenderInspectionRules`,
`CompileM3Bundle(config,options,inspectionPlan)`.

1. OFF delegates exact M2 behavior and leaves static inspection selection empty.
2. Implement original/reply matching from same normalized L3 selectors.
3. Terminal first-match selection. Profile OFF/no profile must terminate too.
4. IDS copies group100 once; IPS queues100 once only if ips_ready valid;
   bypass path counted; default return allowed only after base policy.
5. Include all configured zones/networks/protocol/ports, priority and NAT view.
6. No new ct/meta mark bits; no established/related blanket inspection bypass.
7. Bound generated rules 10.000, reject expansion before apply.
8. Write exact minimal nft integration fixtures for each branch; don't rely on
   unit string regex to prove chain semantics.

**Tests:** multi services OR, IPv4 CIDR, UDP/TCP same port, first uninspected
ALLOW shadows inspected later rule, reverse accepted flow, DNAT port8443→443,
SNAT both directions, current/stale mark, block before M3, MGMT opt-in,
default allow/deny, disabled policy/profile, unsupported scope/app enum.
**Linux gate:** nft syntax + namespace packets, per-branch counters.

## T19 — Scoped app guards và kernel readback

**Dependency:** T11/T14/T17.

**Tạo:** `dataplane/inspection_guards.go`, tests;
`engine/inspection_enforcement.go`, tests.
**Symbols:** `InspectionGuardKey`, `BuildInspectionGuardKey`,
`InstallAppGuard`, `RemoveAppGuard`, `RenewAppGuard`,
`ExecuteInspectionIntent(ctx,intent)`.

1. Key uses full original tuple + CT ID/zone; source scope current netns only.
2. Verify same incarnation via conntrack Source.Get before IO; expected gen and
   selection still valid. Serialize mutation with activation; no store lock IO.
3. Add timeout element idempotently via correct nft operation, verify element
   exists/matches. Generic type integer is forbidden.
4. Success update enforcement APPLIED, invalidate M2 cache, effective DROP.
   Failure keep base action + FAILED/unverified, don't say block succeeded.
5. Recheck after IO; stale result removes only its exact owned key, no new
   session with reused CT ID affected. Pending result CAS retry bounded.
6. Owner APP_POLICY distinct from M2 manual/IP blocks. Config relaxation only
   releases app guards; never clears manual block as a side effect.
7. Refresh TTL60/interval20 only strong still-live identity; cleanup failures
   logged+expiry. No CT destroy just to make a fake reset.

**Tests:** same CT ID different tuple protected; same tuple different start
stale event denied eligibility; missing ID→UNAVAILABLE; failure rollback,
duplicate idempotence, delayed ACK after commit, close during IO, max guards,
retry bounded, M2 manual block preserved after app guard removal.

## T20 — IPS liveness lease và fail-open behavior

**Dependency:** T09/T17/T18.

**Sửa:** sensor health; inspection_guards; thêm `sensor/recovery.go` nếu cần.
**Symbols:** `RenewIPSLease`, `StopIPSLease`, `LeaseState`, `RecoverSensor`.

1. TTL3s, refresh1s key IPv4/TCP+UDP; only capture liveness qualifies.
2. Health event includes requested/configured/live queue states separately.
3. Capture stopped/stalled → no renew; unit fixed systemctl restart with
   timeout/readback. No shell from user/EVE, no generic arbitrary service name.
4. Reader failure alone doesn't fabricate capture death; health DEGRADED,
   queue behavior explicitly derives capture evidence, not threat-event quiet.
5. Engine exit lease expires without requiring cleanup daemon; packet base
   allow continues. Queued packets may fail and must be measured/reported.
6. Source recover requires2 successful probes before renew; no flapping loop.

**Tests:** fake time lease expiry, no renew absent/wrong manifest, quiet healthy,
stalled backlog, restart bounded; new listener epoch clears old flow binding.
**Linux:** stop, SIGSTOP and queue saturation are separate scenarios; record
allowed traffic recovery time and M1 deny still denied in all three.

## T21 — Activation/rollback snapshots và recovery

**Dependency:** T15/T18/T19/T20.

**Sửa:** controller.go, runtime_service.go, config manager activation,
cmd/ngfw-engine/main.go (compile/apply dispatch); tests.
**Tạo:** `dataplane/activation_snapshot.go` nếu tách dễ review.

**Symbols:** `ActivationSnapshot`, `PrepareM3Activation`,
`ApplySnapshot`, `RestoreSnapshot`, `VerifyActivation`, journal version migration.

1. Persist target+previous compiler options riêng; never previous config plus
   target epoch/zone slots/inspection plan. Missing legacy options → safe
   reconstruction with fresh epoch, documented migration/checksum.
2. Follow master11 ordering; no generation publish before all required stages.
3. Coordinator gate during mutations; CT tracker remains nonblocking.
4. Error at each stage triggers restore with fresh bounded recovery context,
   not canceled HTTP ctx. Preserve journal when rollback fails.
5. Verify rollback mode selection/guards plus route/NAT/address, not JSON only.
6. Commit duplicate operation id returns existing receipt, no two activations.
7. Recovery old schema unit tests; engine restart no trust app ALLOW/old lease.
8. Config before M3 uses old M2 compiler path; compiler bundle cleanup removes
   static inspection rules when turning off, doesn't alter unrelated nft tables.

**Tests:** fault before/after network/nft/write running/runtime activate/guard
reconcile; rollback itself fails; crash journal each stage; rollback increments
generation; stale result after rollback; API timeout operation receipt;
M1 address/route/VLAN cleanup preserved; SNAT/DNAT bindings not flushed.

## T22 — Production startup and IPC v3

**Dependency:** T15/T21.

**Sửa:** cmd/ngfw-engine, engine/runtime_service, engineipc/runtime,
management/runtime_client, corresponding fakes/tests.

1. Wire real readers/sensor monitor/coordinator/event store/guard adapter after
   recovery and M2 setup; Start errors degrade inspection, never invent mock runtime.
2. Disabled doesn't spawn reader/process or require Suricata installed.
3. Add IPC operations master13, typed DTOs and max payload/reply bounds.
4. Protocol v3, old version returns clear mismatch. No accidental v2 request
   decoded with wrong struct defaults.
5. Query timeout2s, commit timeout existing long contract; decode limit enforced
   even when peer replies infinite JSON. Error codes preserved API boundary.
6. `ListSessions/GetSession` query same RuntimeStore with context fields.
7. API binary no new network capabilities, no Suricata executable invocation.

**Tests:** IPC health/list/get/security/cursor/errors; oversized payload;
timeout peer; v2/v3 mismatch; disabled; production wiring no local engine fallback;
API restart reads same engine SessionIDs; engine absent→503.

## T23 — REST và capability endpoint

**Dependency:** T22.

**Tạo:** `management/inspection_api.go`, tests.
**Sửa:** api.go route registration/session DTO, docs/openapi.yaml.

1. Endpoints master13 with existing auth/envelope/error mapping.
2. Capabilities advertise only completed supported apps/modes/fail modes,
   semantics RESTRICT_L3_ALLOW, runtime IPC version, build/ruleset hash.
3. Validate query; cap response1MiB, page200; no fetching all sessions to compute
   UI application chart from one page. Aggregates from bounded engine stats.
4. New `/security/events` separate existing `/events` lifecycle semantics.
5. Session detail projection legacy compatibility: risk etc unavailable;
   field presence false distinct0. Never access a.Engine in runtime mode.
6. RBAC read viewer, mutations ADMIN existing routes; no EVE ingestion route.

**Tests:** role denied/allowed, malformed filters400, notfound404, timeout504,
unavailable503, old API response missing fields normalizes UI later;
large event/string max bound; IPv4 NAT original+translated still present.

## T24 — WebSocket notifications và reconnect

**Dependency:** T22/T23.

**Sửa:** runtime_events/store DTO, management/api.go WS handlers/tests;
web types/wsLifecycle tests only extension.

1. Emit new typed notification after state commit, once logical change, no
   complete raw alert payload broadcast to every client.
2. Event ring cursor includes stream_id; restart resets client cursor correctly.
3. Single WS writer; cancel fetch goroutine on close; write deadlines and bound.
4. Gap→explicit message+REST catchup, not silent loss/success.
5. Mixed lifecycle/security kinds cannot be misclassified based on optional severity.

**Tests:** disconnect during fetch/write, StrictMode mount/unmount handshake,
rapid token change, proxy/client closes, slow browser, server shutdown, reconnect
same ID no duplicate, engine new stream lower seq catchup, health-only update.
**Check:** Go WS regression + `npm test` WS suite.

## T25 — Frontend normalization và read-only components

**Dependency:** T23/T24.

**Tạo:** `web/src/inspectionData.ts`, components ApplicationBadge,
InspectionBadge, InspectionHealthPanel, ThreatEventTable, SessionInspectionDetails.
**Sửa:** types.ts, runtimeData.ts, api.ts, App.tsx; focused tests.

1. Normalize input unknown with explicit types; parse strings/numbers safely,
   uint64 IDs remain strings; invalid enum→Unknown.
2. Attach session fields and event API, typed notifications update/fetch only
   relevant page; no second polling source producing duplicates.
3. One bad record shows unavailable cell, not entire page blank.
4. Display packet DROP REPORTED separately from session guard APPLIED and IDS ALERT.
5. Show security event correlation and app source/confidence; absent stats use —.
6. Preserve existing pages/navigation/styles; no full layout replacement.
7. Counters have defined interval/cumulative scope; zero threats not “Safe”.

**Tests:** helper unknown cases, render arrays with missing severity/application,
TLS not HTTPS, lifecycle not threat, risk unavailable, sensor down visible,
API 500 no fake success, event pagination and reconnect dedup.

## T26 — Policy/profile editor và JSON round-trip

**Dependency:** T04/T23/T25.

**Sửa:** web/src/policy.ts, App.tsx policy dialog/status; add small profile
editor component rather than duplicating config state/backend. Tests.

1. Profile selector reads server capabilities/config; supports IDS/IPS/OPEN
   only. Reference disabled legacy profile shows validation message.
2. Add apps whitelist + application_match_mode automatically only upon explicit
   user selection; explain asynchronous restriction and unknown fail-open.
3. Keep unsupported Risk/ML/WAF fields unavailable; don't call them M3-ready.
4. Save form→candidate endpoint only. Validate checks current revision. Commit
   activates only current valid dirty revision. Load Running edits buffer only.
5. Raw Services/Priority string state retained; parse on submit with inline error.
6. Policy↔JSON shared candidate state and dirty warning/Back navigation retained.
7. Profile change invalidates previous validation even if policy reference same ID.

**Tests:** apps/profile/mode roundtrip save→GET→edit; duplicate/shadow backend
error visible; same L3 different apps unreachable; dirty load confirm; load/save
never commit; Commit activates; HTTP409 stale; no whitespace/comma/0 regression.

## T27 — Sensor launcher và systemd files

**Dependency:** T09/T16/T20.

**Tạo:** scripts/start-suricata-sensor.sh, deploy sensor units,
retention service/timer, scripts/rotate-suricata-logs.sh; script tests.

1. Launcher arg allowlist ids/ips, creates sensor UUID epoch log dir/manifest
   atomically, exact argv; exec foreground Suricata. No eval/sh -c config text.
2. Unit config sets ownership/capabilities/UMask/read-write paths; sensor cannot
   write running.json or engine socket. Separate inspector account from API.
3. Root-owned config/manifest immutable to API; fixed runtime socket path.
4. Logrotate rename+reopen via documented signal; reader drains old fd; daily
   and byte retention, timer1min. No delete outside managed root.
5. Test `systemd-analyze verify` and real minimal unit launch on Ubuntu; check
   socket/EVE permission as engine and inability as API user.
6. Missing binary fails sensor unit with clear reason but not engine crash loop.

**Tests:** invalid arg rejects, paths with spaces quote correctly, epoch new
per sensor restart, rotation open fd, permissions, no credentials in logs.

## T28 — Installer và deployment examples

**Dependency:** T21/T22/T27.

**Sửa:** scripts/install-linux.sh, deploy/ngfw.env.example, README.md.
**Tạo:** configs/examples/m3-ids-lab.json, m3-ips-lab.json, optional app-policy
fixture cùng NIC mapping với m2-lab; don't change m2-lab default.

1. Parse --with-inspection explicit; absent uses old M1/M2 dependency set.
2. Resolve pinned package manifest, verify support, install assets+units+scripts.
3. Preserve user config/env; reinstall safe. --skip-apt still verifies missing
   binaries/dependencies and returns clear actionable error.
4. Sensor services start only explicit --with-inspection --start; Running config
   not silently altered. Never start legacy proxy.
5. Verification invokes installed0755 or bash script. Preserve previous fix
   Permission denied when source copied Windows executable bits missing.
6. Document backend rebuild vs Vite dev; engine+API both needed IPCv3 update.

**Tests:** dry/fake command runner install branches, preserve sentinels, repeat
install, skip-apt missing Suricata, sensor failure diagnostic, script permissions.
**Linux:** clean VM install + reinstall + OFF existing M2 config still forwards.

## T29 — Linux verification runner và acceptance fixtures

**Dependency:** T18/T19/T20/T21/T28.

**Tạo:** scripts/verify-m3-linux.sh; fixtures/helper server/client nếu cần.
**Cập nhật:** tests/integration/m3/README.md theo actual CLI contract.

1. Implement scenario IDs trong ma trận, no PASS for SKIP.
2. Baseline nontraffic default; --traffic --lab opt-in mutation/fault only.
3. Save before/after nft JSON, CT, config/gen/hash, API JSON, EVE, journals,
   stdout/stderr, pcap hash; redact tokens.
4. Safe HTTP marker, HTTP server counts nonce, client response timing; TLS
   identification doesn't need MITM/CA generated appliance.
5. Long-lived TCP benign phase then marker attack; capture same conntrack ID,
   existing cache mark, drop after marker. Don't open a new connection secretly.
6. Failure trap tries restore previous config/Suricata service and records restore
   result; rollback target generation still monotonic. Never flush whole conntrack.
7. Preflight is not acceptance; stdout summary marks exact tests run.

**Check:** `bash -n` scripts, targeted tests of parser/evidence/redaction; shellcheck
if available (absence report, không cài ngẫu nhiên dependency).

## T30 — Full regression, race, fuzz và giới hạn tài nguyên

**Dependency:** T02–T29 code done; Linux required for actual race/probes.

1. Run exact full gate master17; store complete output+versions+exit codes.
2. Race storm NEW/UPDATE/DESTROY + EVE + commit+cleanup+API+WS with deterministic
   barriers; no test solely designed to race unsafe map without asserting results.
3. Fuzz ParseLine/bounded bytes, invalid/truncated/oversize corpus.
4. Saturate internal queues/ring/pending/guard cap; forwarding mock not blocked,
   counters loss correct, bounded allocations after cleanup. Linux forwards too.
5. Soak minimum30min mixed TCP/UDP in lab; record memory trend, max sessions,
   sensor CPU/RAM and event volume. No absolute throughput claim without data.
6. Performance compare inspection OFF/IDS/IPS same topology/workload; warmup,
   3 runs; throughput/latency/loss/CPU/RAM/correlation lag/queue health.
7. Any failure → fix focused task + rerun affected and final gate, not blanket
   retry until flaky test happens green.

**Done:** local code-complete requirements pass; VM acceptance separate row states.

## T31 — Final documentation/evidence/handoff

**Dependency:** T30 code gates; live acceptance may still NOT_RUN.

**Sửa:** USE.md, README.md, docs/architecture.md, docs/openapi.yaml,
docs/m3-acceptance-matrix.md, IMPLEMENTATION_STATUS.md.

1. Mark only actually built features in USE; explain each new field/count/badge,
   IDS vs IPS, delayed app restriction, unknown fail-open, no TLS decryption.
2. Exact rebuild/install/start/verify commands from tested scripts, prerequisites
   and permissions. All links/files actually exist.
3. List source changes, evidence tests, failures/not-run/limits.
4. Copy matrix planned rows to executed status only from evidence, attach path.
5. Use `M3 CODE COMPLETE / VM ACCEPTANCE PENDING` only when master19 satisfied.
6. No claim M3 ACCEPTED without live matrix PASS incl M1/M2 baseline.
7. Leave operator recovery instructions for service stop/stall, replay gaps,
   rollback failed journal and no active Suricata listener.

## Checkpoints để agent yếu không đi lạc

| Checkpoint | Task cần qua | Kiểm tra quyết định |
|---|---|---|
| C0 | T00/T01 | Source baseline và capture/kernel capabilities có bằng chứng |
| C1 | T02–T05 | Schema/app semantics/duplicates/shared match đã nhất quán |
| C2 | T06–T13/T16 | Real EVE parsing, reader, App-ID, NAT correlation và storage |
| C3 | T14/T15 | EVE đổi context của đúng M2 session, không có engine thứ hai |
| C4 | T17–T21 | Kernel selection/guards/fail-open/activation có regression |
| C5 | T22–T26 | IPC/API/WS/UI thật, old workflow không regress |
| C6 | T27–T31 | Deployment, full test gate, acceptance evidence trạng thái thật |

Nếu chưa qua C2 không bật application form cho người dùng. Nếu chưa qua C4
không expose IPS capability=true. Có thể code UI bằng fixture test trước,
nhưng production capability vẫn false đến khi backend được wire đầy đủ.
