# Answer key · Bài 07–12 — trung cấp

---

## Bài 07 · Crawl & Flow

| Checklist | Đáp án |
|---|---|
| Vì sao scraper dùng guard NGƯỢC chiều | `crawl` chỉ ĐỌC trang công khai bằng GET chậm rãi (≥300ms/request, robots.txt, cùng-origin, không auth/cookie) → tự nhiên vô hại → được phép trên web public; ngược lại nó CHẶN loopback/dải riêng vì không có lý do gì cào mạng nội bộ mà không phải dò mạng. Các lệnh tấn công chủ động (scan/loadtest) thì ngược lại: chặn public, cho phép lab + target sở hữu. Một guard — hai chiều — đúng ngữ nghĩa từng tool. |
| Bảng so sánh vuln/hardened flowtest | vuln: tất cả step ~200 nhưng p95 `/slow` ~3s; hardened: nhiều 429 (rate limiter) nhưng p50 vài ms, không timeout — bài học: "bị chặn nhanh" ≠ "sập". |

---

## Bài 08 · E2E & kiểm thử tự động

| Checklist | Đáp án |
|---|---|
| Cả hai lệnh xanh | `npm test` → `fail 0` (140 test); `npm run e2e` → `61/61 PASS`. |
| Vì sao nhóm C "lỗ hổng phải tồn tại" cũng PASS | e2e khẳng định lab vuln *còn* lỗ hổng — nếu ai "vá nhầm" bản vuln, C1-C10 FAIL. Test bảo vệ giá trị giảng dạy, không chỉ bảo vệ code. |
| 140 test vs 61 e2e khác nhau thế nào | Unit: hàm thuần + route, in-process, ~7s, cô lập; e2e: HTTP thật qua socket, tự khởi động 3 server port tạm, đo hành vi end-to-end — bắt lỗi wiring/middleware mà unit không thấy. |

---

## Bài 09 · CTF

| Checklist | Đáp án |
|---|---|
| 265/265 | Xem `solutions/ctf/ctf-01-05.md` + `ctf-06-10.md` + solver 4 ngôn ngữ. |
| Vì sao cờ sinh theo phiên | Chống chép đáp án — `FLAG{}` không hardcode trong repo, mỗi `createLabApp()` random 12 hex. Buộc khai thác thật. |
| `timingSafeEqual` chống gì | Timing attack: `===` thoát sớm ở ký tự sai đầu tiên → đo thời gian response suy ra bao nhiêu ký tự đúng → brute-force từng ký tự. So sánh thời gian hằng chạy hết chuỗi → không rò kênh thời gian. |
| 404 vs 403 cho /admin | 404 giấu tồn tại (tốt: attacker không biết có trang admin; xấu: blue-team cũng không phân biệt probe vs lỗi). 403 rõ ràng hơn cho defender — lab chọn 403 chủ đích cho bài học logging. |

---

## Bài 10 · Command Injection

| Checklist | Đáp án |
|---|---|
| Chêm `whoami`/`id` | `127.0.0.1 & whoami` (Win) / `127.0.0.1; id` (Linux) — `%26`/`%3B` encoded. |
| Cờ CTF #5 | `& set SECLAB` / `; env` → `SECLAB_CTF_CMD=FLAG{cmd-...}` |
| detect thấy "Command injection probe" | Log ghi path chứa `&`/`;` → pattern cmdinj bắt. |
| `execFile` chắc hơn escape | Escape là blacklist — luôn sót metachar (`\n`, `$(...)`, backtick, `&&`). `execFile` không qua shell → `&` chỉ là ký tự argument, không còn ngữ nghĩa shell. Đây là khác biệt "vá kiến trúc" vs "vá bề mặt". |

---

## Bài 11 · JWT

| Checklist | Đáp án |
|---|---|
| Decode + đọc payload | `jwt decode <tok>` → header `{alg:HS256}`, payload `{sub:alice,role:user,iat,exp}` |
| Forge alg=none → cờ | `jwt forge --payload='{"sub":"ctfsvc","role":"svc"}' --alg=none` → `/api/profile?token=` → `FLAG{jwt-...}` |
| Crack + forge HS256 | `jwt crack <tok>` → `secret123` (từ điển ~40 entries, <1s); `jwt forge --secret=secret123` → token hợp lệ. |
| Vì sao crack HS256 nhanh | HMAC-SHA256 là hàm NHANH (vài triệu lần/giây) → brute-force rẻ. Khoá mạnh 256-bit thì nhanh cũng vô ích — nhưng `secret123` trong từ điển → gãy ngay. Bài học đối lập: mật khẩu user phải băm CHẬM (bcrypt/argon2) — khác với khoá HMAC vốn cần entropy, không cần chậm. |

---

## Bài 12 · CSRF & Open Redirect

| Checklist | Đáp án |
|---|---|
| Đổi email cross-origin không token | Login → POST `/settings/email` từ Origin khác → 200, email đổi. |
| Hardened: 403, token đúng → 200 | Thiếu `_csrf` → 403; GET `/settings` lấy token rồi POST kèm → 200. |
| SameSite vs CSRF token khác nhau | SameSite=Lax/Strict: browser KHÔNG gửi cookie cross-site POST → CSRF chết ở tầng trình duyệt (phòng thủ sâu, không cần app code). CSRF token: server kiểm token bí mật chỉ form thật có — hoạt động cả khi cookie được gửi. Khác ở chỗ: SameSite cần browser hiện đại + không bảo vệ GET/subdomain quirk; token bảo vệ mọi client nhưng cần implement đúng. Best practice: cả hai (defense in depth). |
| Open redirect | `/redirect?to=https://evil.example` → 302. Nguy hiểm: phishing (link tin cậy → domain độc), OAuth token leak qua `redirect_uri`. Vá: whitelist path nội bộ `/...` hoặc bảng domain cho phép. |
