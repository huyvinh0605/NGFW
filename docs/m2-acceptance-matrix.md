# M2 acceptance matrix

Đợt nghiệm thu Ubuntu VM ngày 2026-10-23 đã chạy các case A–J. Raw evidence và
phân tích từng case nằm tại
[`artifacts/m2-acceptance-20261023T0455Z/RESULTS.md`](../artifacts/m2-acceptance-20261023T0455Z/RESULTS.md).
Các case còn lỗi đã được sửa/chạy lại; bằng chứng bổ sung ở
[`artifacts/m2-fix-20261023/RESULTS.md`](../artifacts/m2-fix-20261023/RESULTS.md).

| ID | Requirement | Module/code | Test/evidence | Status |
|---|---|---|---|---|
| F01 | Typed tuple canonicalization | `internal/domain/flow.go`, `internal/flow/tuple.go` | `go test ./internal/flow ./internal/session` | PASS (unit) |
| F02 | Original/reply resolve one flow | `internal/session/runtime_store.go` | `runtime_store_test.go`, cases A–C | PASS (unit), PASS (VM, A–C; C rerun with corrected untagged DMZ Running config) |
| F03 | NEW/UPDATE/DESTROY lifecycle | `internal/conntrack`, `internal/engine/runtime.go` | `runtime_test.go`, case E | PASS (unit), PASS (VM, E) |
| F04 | SNAT/MASQUERADE aliases | runtime store + Linux adapter | store NAT tests, case B | PASS (unit), PASS (VM, B) |
| F05 | DNAT aliases | runtime store + Linux adapter | store NAT tests, case C | PASS (unit), PASS (VM, C with persistent DMZ L3 on `ens38`) |
| F06 | Bounded session/index store | `internal/session/runtime_store.go` | capacity/cleanup tests, case I | PASS (unit), PASS (VM, I; giới hạn tạm 128, engine restart) |
| F07 | L3/L4 priority/default deny | `internal/connectivity/program.go` | `program_test.go`, F07 retest | PASS (unit), PASS (VM: DROP priority 10, ALLOW priority 20, default deny) |
| F08 | Monotonic generation/rollback | config + runtime service | config/runtime tests, case F/H | PASS (unit), PASS (VM, F) |
| F09 | Decision cache and generation invalidation | `internal/engine/runtime.go` | `runtime_test.go`, case F | PASS (unit), PASS (VM, F) |
| F10 | ct-mark fast path / epoch | `internal/dataplane/compiler_m2.go`, `mark.go`, runtime service | compiler/mark tests, `nft -c`, F10 retest | PASS (unit), PASS (VM: mark in conntrack, current epoch/zone verification, nft trace of established cache accept) |
| F11 | Hard guard before cached allow | runtime guard table | compiler tests, case G | PASS (unit), PASS (VM, G) |
| F12 | Temporary block/session revoke | `runtime_guards.go`, engine runtime | runtime tests, cases G/K2 | PASS (unit), PASS (VM, G) |
| F13 | Restart/resync, stale-session cleanup and stale mark safety | conntrack source + epoch allocator + runtime reconciliation | source/epoch/resync cleanup tests, case H | PASS (unit), PASS (VM, H; session ID rebuilt, NAT survived, no stale mark trusted) |
| F14 | Engine-only runtime ownership | engine IPC v2, API runtime client | IPC test, service capability evidence | PASS (unit), PASS (VM preflight) |
| F15 | Pagination and filters | API + runtime service | IPC/API tests, case J | PASS (unit), PASS (VM, J) |
| F16 | Bounded event bus/stats | runtime event ring | runtime/IPC tests, case E/J/K7 | PASS (unit), PASS (VM, E/J) |
| F17 | Race safety | all M2 stores/runtime | `go test -race ./...` | PASS (Windows host race run) |
| F18 | Static validation | all Go packages | `go vet ./...`, Linux cross-build | PASS (`go vet`, `GOOS=linux CGO_ENABLED=0 go build`) |
| A–J | Linux topology acceptance | services/kernel/nft/conntrack | `tests/integration/m2/README.md`, [initial VM results](../artifacts/m2-acceptance-20261023T0455Z/RESULTS.md), [retest](../artifacts/m2-fix-20261023/RESULTS.md) | PASS for tested functional scenarios after D/C/F07/F10 retest; I exercised at limit 128, not a 50,000-flow stress test |

Các lỗi nghiệm thu D/C/F07/F10 đã có bằng chứng chạy lại trên Ubuntu VM. Dùng
`GetSession` hoặc tám mục đầu mỗi trang danh sách để làm mới counter; các mục
khác vẫn lấy snapshot theo chu kỳ. Chưa đo tải 50.000 session và chưa nghiệm
thu dual-stack. Xem giới hạn từng bản binary trong báo cáo retest.
