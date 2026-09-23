# Agent triển khai M3 bắt đầu tại đây

Trạng thái: bộ đặc tả đã viết; **chưa có implementation M3**.

## Đọc theo thứ tự

1. [Master spec](../M3_IMPLEMENTATION_PLAN.md): đọc phần 0–5 để biết scope,
   architecture, semantics và domain model. Đây là quyết định đã chốt.
2. [Code contracts](CODE_CONTRACTS.md): type/interface/algorithm/error codes,
   import direction, JSON examples và concurrency/activation boundaries.
3. [Coding tasks](CODING_TASKS.md): thực hiện T00–T31 theo dependency.
4. [Acceptance matrix](../m3-acceptance-matrix.md): test expected/evidence;
   [Linux runbook](../../tests/integration/m3/README.md) mô tả packet tests.

Không cần load lại toàn bộ tài liệu cho mỗi task. Dùng bảng sau để lấy đúng
phần cần thiết; các contract có ưu tiên hơn ví dụ/pseudocode cục bộ.

| Task | Master spec cần đọc | Code contracts |
|---|---|---|
| T00–T01 | 0–3, 6, 10, 17–19 | 1, 11 |
| T02–T05 | 4–5 | 1–4, 7 |
| T06–T10 | 5–7, 12 | 3–4, 9 |
| T11–T15 | 8–9, 12 | 5–7, 9 |
| T16–T20 | 3, 6, 10, 12 | 4, 6–7, 12 |
| T21–T22 | 9, 11, 13 | 5–6, 10 |
| T23–T26 | 4, 13–14 | 7–9 |
| T27–T31 | 6, 15, 17–19 | 10–11 |

## Các điều không được tự diễn giải khác

- Existing `engine.Runtime` là owner session; legacy `engine.Engine`/proxy không
  trở lại production vì có sẵn helper thuận tiện.
- IDS = bản sao NFLOG. IPS = Suricata NFQUEUE verdict trực tiếp. EVE là metadata
  bất đồng bộ, không phải verdict callback giữ request.
- App-ID live phải có traffic source. Conntrack không chứa payload. Go raw
  parser fixture pass không đồng nghĩa live classification chạy.
- `applications` trong M3 là RESTRICT_L3_ALLOW, giới hạn matched base ALLOW
  sau nhận diện; UNKNOWN fail-open, không hứa chặn request đầu. UI ghi rõ.
- Existing cache mark giữ nguyên; base chain inspection sau L3/cache. Guard
  trước cache. Không thêm queue sau terminal accept trong cùng chain.
- No new M4+/Risk/ML/TLS/WAF/nDPI. Không làm UI mock để trông như đã có backend.
- Không build xong rồi claim Ubuntu packet path đã pass. Trạng thái được phép
  dùng nằm ở master19 và acceptance matrix.

## Prompt có thể giao trực tiếp cho coding agent

> Triển khai M3 theo docs/M3_IMPLEMENTATION_PLAN.md và docs/m3/CODE_CONTRACTS.md.
> Bắt đầu bằng audit/baseline T00 trong docs/m3/CODING_TASKS.md, sau đó thực hiện
> tuần tự các task còn lại theo dependency. Mỗi task chỉ sửa phạm vi file cần
> thiết, implement cả production path lẫn tests hành vi, ghi kết quả lệnh thật
> vào docs/m3/IMPLEMENTATION_STATUS.md. Không đổi architecture/semantics đã chốt
> hoặc xóa test cũ để pass. Giữ các thay đổi hiện có của người dùng. Nếu Linux
> chưa sẵn sàng, code/test phần độc lập, ghi probe/traffic NOT_RUN và không claim
> code-complete khi thiếu required gate. Khi một contract không thể chạy trên
> binary/kernel thực tế, ghi reproducer và blocker trước khi thay thiết kế.
> Hoàn tất mọi task đủ điều kiện; bàn giao file list, commands, output, known
> limitations và acceptance status. Không mở feature ngoài M3.

## Khi hết context hoặc chuyển model

Ghi task hiện tại, functions đã xong/chưa xong, tests đang fail, files đang sửa,
command tiếp theo và evidence path trong status. Agent mới đọc status + task
đó + các phần contract liên quan trước khi tiếp tục. Không chạy lại mọi task
từ đầu hoặc tin câu “đã pass” nếu không có command/output tương ứng.
