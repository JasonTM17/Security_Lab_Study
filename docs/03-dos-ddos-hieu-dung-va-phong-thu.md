# 03 · Hiểu đúng DoS/DDoS — và phòng thủ

## 1. Định nghĩa ngắn

- **DoS (Denial of Service):** làm một dịch vụ không phục vụ được người dùng hợp
  lệ, từ **một** nguồn.
- **DDoS (Distributed DoS):** cùng mục đích nhưng từ **hàng nghìn** nguồn
  (botnet) — vượt quá khả năng phòng thủ của một server đơn lẻ.

## 2. Ba lớp tấn công (phân loại chuẩn)

| Lớp | Tấn công tiêu biểu | Ngăn chặn ở đâu |
|---|---|---|
| **Volumetric** (điển đĩa/băng thông) | UDP flood, DNS amplification, NTP amplification | Không thể vá ở server — phải có ISP/CDN scrubbing (Cloudflare, AWS Shield) |
| **Protocol** (lớp 3/4) | SYN flood, **Slowloris**, connection exhaustion | Kernel + web server: SYN cookies, timeout, `limit_conn` |
| **Application** (lớp 7) | HTTP flood vào endpoint đắt tiền, cache-busting | Ứng dụng: rate limit, WAF, cache, queue |

SecLab mô phỏng **lớp protocol (slowloris)** và **lớp application (HTTP flood
có pacing)** — đúng hai lớp mà một developer/backend có thể tự phòng thủ được.

## 3. Vì sao một server "chết" — bài học từ chính lab này

Chạy `node src/cli.js loadtest http://127.0.0.1:3000 --path=slow --rps 40 --duration 8`
bạn sẽ thấy:

- Mỗi request vào `/slow` giữ một worker **3 giây**.
- `p95 latency ≈ 3000ms`, thông lượng thực tế chỉ ≈ 13 req/s dù yêu cầu 40.
- Kết luận: **độ thông lượng = số worker × (1/thời gian xử lý)**. Endpoint chậm
  chính là điểm tự huỷ của server — kẻ tấn công chỉ cần nhắm vào nó.

Ba yếu tố bị khai thác trong DoS hiện đại:

1. **Tài nguyên hữu hạn** — worker pool, connection pool, RAM, băng thông.
2. **Độ bất đối xứng** — 1 byte của attacker buộc server xử lý 1 giây
  (ReDoS, hash-collision, regex, query nặng).
3. **Thiếu giới hạn** — không rate limit, không timeout, không cap connection.

## 4. Phòng thủ từng lớp — và SecLab đã cài sẵn ở đâu

| Hàng rào | Kỹ thuật | Trong SecLab (bản hardened) |
|---|---|---|
| Ngắt kết nối treo | `headersTimeout`, `requestTimeout`, socket idle timeout | `server.headersTimeout = 4000`… trong `lab/app.js` |
| Giới hạn kết nối nửa-request | per-IP half-open cap (kiểu nginx `limit_conn`) | `HALF_OPEN_LIMIT = 10` + grace 2s |
| Chặn request flood | token bucket rate limit theo IP | `defense/ratelimiter.js` → 429 + `Retry-After` |
| Hạn chế payload | body size limit | `readBody(req, 8KB)` ở bản hardened |
| Giảm độ đắt của endpoint | cache, async, rẻ hoá query | (bài tập suy luận — thử tự vá `/slow`) |
| Hạ tầng | CDN/Anycast, autoscaling, scrubbing center | ngoài phạm vi lab — đọc thêm ở §6 |

## 5. Điều TRÁI NGƯỢC với trực giác người mới

- Rate limit **không** làm server "chịu tải tốt hơn" — nó làm server **từ chối
  có kiểm soát** để phần còn lại sống. Chạy `loadtest` lên bản hardened: sẽ thấy
  rừng `429`, nhưng `p50 ≈ vài ms` và endpoint vẫn trả lời client hợp lệ.
- Chống DDoS volumetric **không phải** việc của developer — là việc của mạng
  (ISP, CDN). Server đơn lẻ không thắng nổi 10 Gbps, dù code đẹp đến đâu.
- "Timeout ngắn" là hàng rào số 1 và rẻ nhất — nhiều hệ thống lộ vì để timeout
  mặc định 60s cho kết nối chưa hoàn tất.

## 6. Đọc thêm (nguồn chuẩn)

- OWASP: *Denial of Service Cheat Sheet* — owasp.org
- Cloudflare Learning: *What is a DDoS attack?* — öğren phân loại volumetric/protocol/app
- nginx docs: `limit_req`, `limit_conn` — chính là 2 kỹ thuật SecLab đã cài
- Node.js docs: `server.headersTimeout`, `server.requestTimeout`

> Nhắc lại: mô phỏng trong SecLab CHỈ chạy trên `127.0.0.1`. Chuyển kỹ thuật
> này ra Internet với hệ thống người khác là phạm tội (xem `docs/01`).
