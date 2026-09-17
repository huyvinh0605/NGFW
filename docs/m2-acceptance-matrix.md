# M2 acceptance matrix

Trạng thái ban đầu của các kiểm tra packet-path là `NOT_RUN`. Người nghiệm thu
đổi trạng thái cùng đường dẫn evidence sau khi chạy trên Ubuntu 24.04 VM.

| ID | Requirement | Module/code | Test/evidence | Status |
|---|---|---|---|---|
| F01 | Typed tuple canonicalization | `internal/domain/flow.go`, `internal/flow/tuple.go` | `go test ./internal/flow ./internal/session` | PASS (unit) |
| F02 | Original/reply resolve one flow | `internal/session/runtime_store.go` | `runtime_store_test.go`, case D | PASS (unit) |
| F03 | NEW/UPDATE/DESTROY lifecycle | `internal/conntrack`, `internal/engine/runtime.go` | `runtime_test.go`, case E | PASS (unit) |
| F04 | SNAT/MASQUERADE aliases | runtime store + Linux adapter | store NAT tests, case B | PASS (unit), NOT_RUN (VM) |
| F05 | DNAT aliases | runtime store + Linux adapter | store NAT tests, case C | PASS (unit), NOT_RUN (VM) |
| F06 | Bounded session/index store | `internal/session/runtime_store.go` | capacity/cleanup tests, case I | PASS (unit), NOT_RUN (VM) |
| F07 | L3/L4 priority/default deny | `internal/connectivity/program.go` | `program_test.go`, cases F/J | PASS (unit), NOT_RUN (VM) |
| F08 | Monotonic generation/rollback | config + runtime service | config/runtime tests, case F/H | PASS (unit), NOT_RUN (VM) |
| F09 | Decision cache and generation invalidation | `internal/engine/runtime.go` | `runtime_test.go`, case F | PASS (unit), NOT_RUN (VM) |
| F10 | ct-mark fast path / epoch | `internal/dataplane/compiler_m2.go`, `mark.go` | compiler/mark tests, `nft -c`, cases F/G/H | PASS (unit), NOT_RUN (VM) |
| F11 | Hard guard before cached allow | runtime guard table | compiler tests, case G | PASS (unit), NOT_RUN (VM) |
| F12 | Temporary block/session revoke | `runtime_guards.go`, engine runtime | runtime tests, cases G/K2 | PASS (unit), NOT_RUN (VM) |
| F13 | Restart/resync, stale-session cleanup and stale mark safety | conntrack source + epoch allocator + runtime reconciliation | source/epoch/resync cleanup tests, case H | PASS (unit), NOT_RUN (VM) |
| F14 | Engine-only runtime ownership | engine IPC v2, API runtime client | IPC test, service capability evidence | PASS (unit), NOT_RUN (VM) |
| F15 | Pagination and filters | API + runtime service | IPC/API tests, case J | PASS (unit), NOT_RUN (VM) |
| F16 | Bounded event bus/stats | runtime event ring | runtime/IPC tests, case J/K7 | PASS (unit), NOT_RUN (VM) |
| F17 | Race safety | all M2 stores/runtime | `go test -race ./...` | PASS (Windows host race run) |
| F18 | Static validation | all Go packages | `go vet ./...`, Linux cross-build | PASS (`go vet`, `GOOS=linux CGO_ENABLED=0 go build`) |
| A–J | Linux topology acceptance | services/kernel/nft/conntrack | `tests/integration/m2/README.md` | NOT_RUN |

The repository must not label M2 “completed” while any required VM row remains
`NOT_RUN`, `FAIL`, or an unexplained `SKIP`.
