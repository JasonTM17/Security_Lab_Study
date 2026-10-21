# 02 · Kiến trúc của SecLab

```
┌────────────────────────────── seclab (D:Ddos_Tool) ───────────────────────────────┐
│                                                                                   │
│  src/cli.js ◄── điểm vào duy nhất (serve · recon · scan · loadtest · flowtest ·   │
│      │              slowloris · crawl · hub · doctor · labs)                      │
│      │                                                                            │
│      ├──► src/guard.js          ⛔ "Cửa ủy quyền": chặn mục tiêu public,          │
│      │                          yêu cầu --i-own-this-target cho dải riêng         │
│      │                                                                            │
│      ├──► src/modules/          CÁC MODULE CHỦ ĐỘNG (đều có lớp kiểm duyệt        │
│      │     │                     mục tiêu riêng — xem ⛔ và 🕷)                   │
│      │     ├── recon.js          thu thập: headers, fingerprint, port, robots.txt │
│      │     ├── vulnscan.js      7 nhóm check: headers, cookie, SQLi, XSS,         │
│      │     │                     IDOR, đường nhạy cảm, rate limit                 │
│      │     ├── loadtest.js       tạo tải có pacing (rps), đo p50…p99              │
│      │     ├── flowload.js       flowtest: chuỗi bước như người dùng thật         │
│      │     │                     (think-time + ramp-up), đo p95 từng bước         │
│      │     ├── slowloris.js      mở kết nối "nửa request", đo server có cắt không │
│      │     ├── scraper.js       🕷 CRAWL — module DUY NHẤT cho phép web PUBLIC,   │
│      │     │                     guard NGƯỢC chiều: chặn loopback/dải riêng,      │
│      │     │                     tôn trọng robots.txt + rate-limit lịch sự        │
│      │     ├── http.js           helper dùng chung: fetch có timeout, percentile  │
│      │     └── report.js         xuất báo cáo .md + .html vào reports/            │
│      │                                                                            │
│      ├──► src/lab/              MỤC TIÊU THỰC HÀNH (bind cứng 127.0.0.1)          │
│      │     ├── app.js           2 chế độ: vuln (8 lỗ hổng) / hardened (đã vá)     │
│      │     └── serve.js          chạy server, in thông tin                        │
│      │                                                                            │
│      ├──► src/hub/               server tĩnh Hub học SecHub — chỉ 127.0.0.1       │
│      │                                                                            │
│      ├──► src/defense/          MODULE PHÒNG THỦ (bản hardened dùng)              │
│      │     ├── ratelimiter.js    token bucket theo IP → 429                       │
│      │     └── headers.js        CSP, nosniff, X-Frame-Options, HSTS…             │
│      │                                                                            │
│      └──► src/db.js             SQLite thật (node:sqlite) — SQLi minh hoạ chuẩn   │
│                                 + fallback bộ nhớ nếu sqlite không có             │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## Vòng lặp học tập

```
   npm run serve (vuln) ──► recon ──► scan ──► khai thác thủ công ──► loadtest/slowloris
          ▲                                                        │
          │                                                        ▼
   npm run serve:hardened ◄──────────── Tìm cách vá trong docs/ và code hardened
          │                                                        │
          └────────────── scan lại ──► SO SÁNH báo cáo trước/sau ──┘
```

## Ba tầng an toàn của công cụ

1. **Guard ở entry** (`guard.js`) — mọi module tấn công/recon gọi
   `assertAuthorizedTarget()` trước khi gửi byte đầu tiên. Địa chỉ public bị từ
   chối bằng văn bản (kèm điều luật), dải riêng cần cờ `--i-own-this-target`.
   Ngoại lệ **ngược chiều**: `scraper.js` (crawl) cho phép web **public** vì cào
   lịch sự là hợp pháp — nhưng đổi lại mặc định chặn loopback/dải riêng (cùng
   cờ `--i-own-this-target` khi muốn tập trên lab), tôn trọng robots.txt.
2. **Bind cứng 127.0.0.1** (`lab/serve.js`) — lab server không bao giờ lắng nghe
   trên `0.0.0.0`, nên không ai trong mạng LAN truy cập được lab của bạn.
3. **Dữ liệu ảo** (`db.js`, `VFS` trong `app.js`) — CSDL là SQLite in-memory,
   "file system" của bài path traversal là object trong RAM. Không có thao tác
   đọc/ghi nào chạm vào đĩa thật.

## Vì sao code lab cố tình "xấu" và code hardened cố tình "đẹp"

Đây là kỹ thuật giảng dạy **vuln/hardened pair**: cùng một ứng dụng, hai bản.
Bạn đọc cặp hàm `db.searchUsers()` (nối chuỗi — lỗi) và `db.searchUsersSafe()`
(parameterized — đúng) cạnh nhau; chạy scanner lên cả hai bản và thấy số
finding giảm về 0. Kiểu học này bám sát thực tế pentest: kết quả quét chỉ có
giá trị khi bạn chỉ ra được **cách vá** và **chứng minh đã vá**.
