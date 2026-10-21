# 08 · Bản đồ OWASP Top 10 (2021) ↔ SecLab

Mỗi lỗ hổng trong lab được map với **OWASP Top 10 2021** và **CWE** — dùng khi
trình bày báo cáo hoặc giảng dạy: một finding không chỉ là "lỗi" mà là một hạng
mục nguy cơ đã được cả ngành chuẩn hoá.

| Lab | Lỗ hổng | Endpoint | OWASP 2021 | CWE |
|---|---|---|---|---|
| LAB-01 | SQL Injection | `/search`, `/login` | **A03** Injection | CWE-89 |
| LAB-02 | Reflected XSS | `/search`, 404 | **A03** Injection | CWE-79 |
| LAB-03 | IDOR | `/api/users/:id` | **A01** Broken Access Control | CWE-639 |
| LAB-04 | Path Traversal | `/download` | **A01** Broken Access Control | CWE-22 |
| LAB-05 | Thiếu security headers / cookie flags | toàn bộ | **A05** Security Misconfiguration | CWE-16/693 |
| LAB-06 | Thiếu rate limiting | toàn bộ | **A05** + A04 Insecure Design | CWE-770 |
| LAB-07 | Missing authorization | `/admin` | **A01** Broken Access Control | CWE-862 |
| LAB-08 | Verbose error page | 500/404 | **A05** Security Misconfiguration | CWE-209 |
| LAB-09 | OS Command Injection | `/tools/ping` | **A03** Injection | CWE-78 |
| LAB-10 | CSRF | `POST /settings/email` | **A01** Broken Access Control | CWE-352 |
| LAB-11 | JWT yếu (alg=none, secret trong từ điển) | `/api/token`, `/api/profile` | **A02** Cryptographic Failures + A07 Auth | CWE-327/345 |
| LAB-12 | Open Redirect | `/redirect` | **A01** (unvalidated redirect) | CWE-601 |
| LAB-13 | Unrestricted Upload | `/upload`, `/uploads/` | **A05** Misconfiguration / A04 | CWE-434 |
| LAB-14 | XXE (mô phỏng trên VFS) | `/api/import` | **A05** Security Misconfiguration | CWE-611 |
| LAB-15 | Stored XSS | `/guestbook` | **A03** Injection | CWE-79 |

## 10 hạng mục OWASP 2021 — lab phủ được bao nhiêu?

| Mã | Hạng mục | Trong SecLab? |
|---|---|---|
| A01 | Broken Access Control | ✅ LAB-03, 04, 07, 10, 12 |
| A02 | Cryptographic Failures | ✅ LAB-11 (JWT), cookie không Secure/HttpOnly (LAB-05) |
| A03 | Injection | ✅ LAB-01, 02, 09, 15 — đủ cả SQL/OS/DSL (XXE)/script |
| A04 | Insecure Design | 🟡 gián tiếp: thiếu rate limit (LAB-06) là lỗi thiết kế |
| A05 | Security Misconfiguration | ✅ LAB-05, 06, 08, 13, 14 |
| A06 | Vulnerable & Outdated Components | ➖ lab không có dependency (chủ đích — để bạn đọc code gốc) |
| A07 | Identification & Auth Failures | ✅ LAB-11 (JWT), brute-force login (detect), session không cờ |
| A08 | Software & Data Integrity Failures | 🟡 XXE/DTD là biến thể; không có supply-chain demo |
| A09 | Security Logging & Monitoring | ✅ module `detect` + `/_lab/log` — bài blue-team xoay quanh đây |
| A10 | SSRF | 🟡 scraper có guard ngược chiều; thảo luận trong `docs/02` |

**Cách dùng khi dạy:** cho học viên quét lab (`scan`), rồi tự map từng finding
vào bảng trên — bài tập "đặt tên đúng hạng mục" giúp ghi nhớ taxonomy lâu hơn
đọc lý thuyết.

## Đọc thêm

- OWASP Top 10 2021: https://owasp.org/Top10/
- CWE Top 25: https://cwe.mitre.org/top25/
- Juiceshop/DVWA (lý tưởng thiết kế của lab này)
