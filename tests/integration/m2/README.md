# M2 Linux acceptance

Bộ này kiểm tra trên Ubuntu 24.04 VM sau khi M1 đã đạt acceptance. M2 dùng
topology M1: WAN, LAN, DMZ và MGMT; API chỉ đọc session qua Unix socket của
`ngfw-engine`. Unit test trên Windows không thay thế được các bước bên dưới.

## Chuẩn bị

1. Cài appliance bằng `sudo bash scripts/install-linux.sh --start` và kiểm tra
   `sudo /usr/local/lib/ngfw/verify-m1-linux.sh`.
2. Đặt `NGFW_API_URL` (mặc định `http://127.0.0.1:8080`) và bearer token trong
   shell kiểm thử. Không ghi token vào evidence.
3. Chụp manifest trước mỗi lần chạy:

```bash
mkdir -p evidence/m2/$(date -u +%Y%m%dT%H%M%SZ)
sudo conntrack -L > evidence/m2/<run>/conntrack-before.txt
sudo nft list ruleset > evidence/m2/<run>/nft-before.txt
curl -fsS "$NGFW_API_URL/api/v1/health" > evidence/m2/<run>/health-before.json
```

`scripts/verify-m2-linux.sh` thực hiện các kiểm tra không tạo traffic và in
ra lệnh cần chạy cho từng scenario. Các request/flow phải mang một ID riêng
để đối chiếu conntrack, engine event, API JSON và access log upstream.

## Scenarios

| Case | Thực hiện | Điều kiện PASS |
|---|---|---|
| A | LAN mở một TCP flow tới WAN, gọi `/api/v1/sessions?page_size=20`. | Một session có original tuple đúng, không có record chiều ngược riêng. |
| B | Tạo connection mới qua MASQUERADE. | Cùng SessionID có original private tuple và translated public tuple/port. |
| C | WAN gọi public DNAT `8443` tới DMZ `443`. | Public và DMZ tuple nằm trong một session; reply map ngược đúng. |
| D | Gửi nhiều request/response hai chiều trên A/B/C. | Counters original/reply tăng đúng; không duplicate. |
| E | Quan sát NEW, reply, FIN/TIME_WAIT rồi DESTROY; thêm UDP nếu profile cho phép. | Event lifecycle và state chuyển đúng; index bị xoá sau cleanup. |
| F | Giữ long-lived ALLOW, commit policy DROP, gửi packet mới. | Generation tăng, cached ALLOW bị invalidate, packet mới không qua old allow; rollback có generation cao hơn. |
| G | Block source của session đang established. | Guard kernel chặn packet tiếp theo dù flow mang mark ALLOW; TTL vẫn hoạt động khi API dừng. |
| H | Giữ conntrack, restart riêng engine. | Resync không duplicate; NAT binding còn; epoch mới hoặc safe no-cache; không tin mark stale. |
| I | Tạo flows đồng thời tới giới hạn cấu hình. | Count/index nhất quán, capacity metric tăng nếu đầy, forwarding không crash. |
| J | Query page/filter/state/decision/tuple_view và tham số sai. | Page tối đa 500, kết quả ổn định/bounded, filter đúng, engine mất thì API trả 503. |

## Evidence

Mỗi run lưu `manifest.json`, config/version, command log đã xoá bí mật,
`conntrack` trước/sau, `nft list ruleset`, raw API responses, engine/API journal
và pcap khi cần. Kết quả phải ghi `PASS`, `FAIL`, `SKIP` hoặc `NOT_RUN`; chỉ
`PASS` trên Ubuntu VM mới được dùng để claim M2 completed. Unit PASS chỉ chứng
minh code complete/ready for acceptance.

IPv6 chỉ ghi `SKIP` khi profile dual-stack chưa được bật và kiểm thử; không tự
bật IPv6 forwarding để làm cho scenario PASS.
