# Changelog

Mọi thay đổi đáng chú ý của SecLab được ghi lại tại đây.
Format theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/), phiên bản
theo [Semantic Versioning](https://semver.org/lang/vi/).

## [1.1.0] — 2025-10

### Thêm

- **LAB-09 Command Injection** — `/tools/ping?host=` nối chuỗi vào `exec()` (vuln)
  ↔ `execFile` + whitelist ký tự (hardened); cờ CTF trong biến môi trường.
- **LAB-10 CSRF** — `POST /settings/email` không token (vuln) ↔ synchronizer
  token `src/defense/csrf.js` + kiểm Origin (hardened).
- **LAB-11 JWT yếu** — `POST /api/token` + `GET /api/profile`: secret
  `secret123` + chấp nhận `alg=none` (vuln) ↔ verify chặt, secret ngẫu nhiên
  theo phiên (hardened). Helper ký/verify: `src/lab/jwtx.js`.
- **LAB-12 Open Redirect** — `/redirect?to=` tin Location thô ↔ chỉ path nội bộ.
- **LAB-13 Unrestricted Upload** — `POST /upload` + `GET /uploads/:name` serve
  mọi đuôi ↔ whitelist đuôi + Content-Type an toàn.
- **LAB-14 XXE (mô phỏng)** — `POST /api/import` xử lý `<!ENTITY SYSTEM>` trên
  filesystem ảo ↔ từ chối DOCTYPE.
- **LAB-15 Stored XSS** — `/guestbook` lưu và render không escape ↔ `esc()`.
- **Lệnh `jwt`** — `src/modules/jwttool.js`: decode / forge (alg=none, HS256) /
  verify / crack secret bằng từ điển — chạy hoàn toàn cục bộ.
- **CTF mở rộng 4 → 7 thử thách (170 điểm)**: cờ command-injection qua env var,
  cờ JWT phải forge `sub=ctfsvc`, cờ XXE qua entity `file:///flag-xxe.txt`.
- **Scanner 7 → 14 probe**: thêm SXSS, CMDI, CSRF, JWT, OREDIR, UPLOAD, XXE.
- **Detect mở rộng**: pattern cmdinj/open-redirect/xxe/upload/jwt-probe +
  phát hiện brute-force theo IP (`/_lab/log` giờ ghi địa chỉ IP).
- **Giáo trình**: `docs/08-owasp-top10-mapping.md` (LAB→OWASP Top 10:2021→CWE),
  `exercises/10`–`13`, SecHub chuyên mục 04/05 cập nhật 15 lab.
- **Hồ sơ repo**: LICENSE (MIT), CONTRIBUTING, SECURITY, CODE_OF_CONDUCT,
  issue/PR templates, CI chạy cả e2e trên Ubuntu+Windows × Node 22/24.

### Sửa

- Số liệu docs đồng bộ thực tế: 15 lab, 7 CTF/170đ, 14 probe, 115 test,
  54 e2e check, scan vuln thật báo 10 High + 4 Medium.

## [1.0.0] — bản đầu

- Lab web 8 lỗ hổng cố ý (SQLi, reflected XSS, IDOR, path traversal trên VFS,
  thiếu headers/cookie flags, thiếu rate limit, thiếu authorization, verbose
  error) với bản đối chứng `--hardened`.
- Guard ủy quyền `src/guard.js`: loopback tự do, RFC1918 cần
  `--i-own-this-target`, public chặn cứng — kiểm tra trước mọi traffic.
- Module: recon, vulnscan (7 probe), loadtest (pacing rps, p50–p99), flowtest
  (virtual user + think-time), slowloris, polite scraper (robots.txt,
  same-origin), codec, detect, report md+html.
- CTF 4 thử thách/100 điểm, cờ `FLAG{...}` ngẫu nhiên theo phiên, verify
  timing-safe.
- SecHub 9 chuyên mục (tổng quan, DoS/DDoS, malware, OWASP, xác thực & mã hoá,
  mạng, pháp lý VN, lộ trình 12 tháng, cheat sheet).
- 71 unit test + 38 e2e check; docs 01–07; exercises 01–09.
