# Changelog

Mọi thay đổi đáng chú ý của SecLab được ghi lại tại đây.
Format theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/), phiên bản
theo [Semantic Versioning](https://semver.org/lang/vi/).

## [1.5.0] — 2026-10

### Thêm

- **🔵 Blue Team SOC console** — `GET /blue`: dashboard phòng thủ tách biệt với
  Red Team. Live request feed tự làm mới 2.5s (tô đỏ hàng khớp pattern nghi
  ngờ, flag pill theo loại tấn công), thẻ alert từ engine `detect.js` chạy
  trên request log thật, bảng 16 detection rule kèm giới hạn (access log không
  thấy request body → proto pollution cần telemetry tầng app), và 20 thẻ phòng
  thủ theo từng bài LAB — khép kín luồng học **tấn công → quan sát → so sánh
  hardened**. Có nút tạm dừng feed.
- **`GET /_lab/alerts`** — endpoint JSON chạy `analyzeLog(reqLog)` trên log
  sống, trả `{ mode, findings, rules }` cho SOC console và công cụ ngoài.
- **Request log ghi `status`** — mỗi entry trong `/_lab/log` cập nhật HTTP
  status qua `res.on('finish')` (0 = đang xử lý), để Blue Team nhìn được oracle
  200/404 của blind SQLi và tỉ lệ lỗi.
- **Nav bar chung** cho `/`, `/lab`, `/blue` với badge mode VULN/HARDENED.

### Sửa

- **CSP hardened chặn dashboard** — `script-src/style-src 'self'` cấm inline
  `<script>`/`<style>`/`style=` → dashboard hardened mất hết style và JS.
  Tách CSS/JS thành route `/_lab/dash.css` + `/_lab/dash-{red,blue}.js`
  (same-origin, CSP cho phép) và chuyển mọi màu nhóm sang class `c-<nhóm>`
  + biến `--cat`. Dashboard giờ hoạt động đầy đủ trên CẢ hardened — đúng
  bài học CSP: trang tuân thủ CSP dùng asset ngoài.
- `flagsOf` (blue feed) không bắt payload URL-encoded (`%27%20UNION%20`,
  `%3Cscript%3E`, `%26`) vì regex `\s` không khớp `%20` — giờ decode path
  trước khi match; xoá `SUS` dead code.
- Blue feed: timestamp `Date.now()` (numeric epoch) làm client crash vì gọi
  `.slice` trên số — formatter mới xử lý cả epoch số lẫn chuỗi ISO.
- Nút copy payload: thêm fallback `execCommand` khi Clipboard API bị chặn.
- Favicon inline cho `/lab` + `/blue` (diệt 404 console).
- `/lab` redesign sang theme Red Team (đỏ/cam, nhóm theo màu kỹ năng) tách
  biệt với Blue Team (cyan); giữ nguyên lọc, tiến độ, CTF panel.

### Test

- `tests/dashboard.test.js` +7: route `/blue`, `/_lab/alerts` bắt SQLi +
  admin-probe từ traffic thật, status recording, timestamp helper,
  `flagsOf` encoded-payload (extract+exec thật), MIME asset `/_lab/dash.*`,
  coverage `LAB_DETECT` → **147 test** (trước 140).
- `tests/e2e.mjs` +3 check nhóm I: `/blue` render + asset JS, `/_lab/alerts`
  phát hiện từ traffic e2e, status trong log → **64 check** (trước 61).

## [1.4.0] — 2026-10

### Thêm

- **Dashboard chọn bài LAB** — `GET /lab` trong lab app: catalog tương tác
  đủ 20 lỗ hổng lấy từ một nguồn dữ liệu `LABS` (`src/lab/dashboard.js`):
  lọc theo 6 nhóm kỹ năng (Injection/XSS/Truy cập & File/Xác thực & Phiên/
  Cấu hình/Logic nâng cao), 3 mức độ khó, chỉ-CTF, tìm kiếm full-text;
  mỗi thẻ gồm mục tiêu, endpoint GET click-mở được, payload gợi ý nút copy,
  cách kiểm chứng bản hardened, file bài tập liên quan; checkbox "Đã xong"
  lưu localStorage + thanh tiến độ; panel **nộp cờ CTF trực tiếp** gọi
  `/_lab/challenges` + `/_lab/verify` — điểm cập nhật live. Bản hardened
  hiện banner đối chứng (payload phải bị chặn).
- **Chuyên mục hub mới "10 · Chọn bài LAB"** — `scripts/assemble-hub.js`
  sinh catalog bảng từ cùng dữ liệu `LABS` → hub/GitHub Pages luôn đồng bộ
  với lab, không duplícate tay.
- `src/lab/html.js` — tách `esc()` dùng chung app.js ↔ dashboard.js.
- `tests/dashboard.test.js` — 6 test (route, data integrity, CTF mapping,
  exercise tồn tại, catalog) → **140/140**; e2e thêm nhóm I (2 check) →
  **61/61**. Ảnh `docs/images/lab-dashboard.png` chụp thật bằng Playwright.

### Sửa

- Trang chủ lab + footer mọi trang thêm link 🧪 Dashboard; số liệu docs
  đồng bộ 140 test/61 e2e/10 chuyên mục.

## [1.3.0] — 2026-10

### Thêm

- **`solutions/` — bộ lời giải hoàn chỉnh** (cho người dạy / tự đối chiếu):
  - Writeup 10 CTF (`ctf-01-05.md`, `ctf-06-10.md`): mỗi bài gồm mục tiêu,
    root cause kèm ref code, exploit copy-chạy, cách lấy cờ, hành vi bản
    hardened, và bài học phòng thủ.
  - **Solver thực thi bằng 4 ngôn ngữ** — `solve-all.mjs` (Node fetch),
    `solve_all.py` (stdlib urllib), `solve-all.sh` (bash+curl),
    `Solve-All.ps1` (PowerShell ≥5.1). Cùng giải 10/10 · 265/265 trên lab
    vuln sống; exit code 0 dùng được làm smoke-test CI.
  - **Answer key 17 bài tập** (`exercises/answers-*.md`): đáp án từng
    tiêu chí hoàn thành + lỗi học viên hay mắc + câu trả lời câu hỏi mở.
  - Solver tuân thủ cùng mô hình an toàn `guard.js`: từ chối mục tiêu
    không-loopback trừ khi `--i-own-this-target`.
- **GitHub Pages cho SecHub** — `.github/workflows/pages.yml` deploy `hub/`
  tự động khi push đụng `hub/**`; README hướng dẫn bật Pages.

## [1.2.0] — 2026-10

### Thêm

- **LAB-16 Prototype Pollution** — `POST/GET /api/config` merge đệ quy không
  lọc `__proto__` (vuln, `unsafeMerge`) ↔ `safeMerge` lọc
  `__proto__/constructor/prototype` (hardened). Cờ CTF #8 lộ ra khi
  `Object.prototype` bị nhiễm (`protoPolluted` liệt kê key enumerable).
- **LAB-17 Mass Assignment** — `POST /api/register` copy mọi field kể cả
  query `?role=admin` (vuln) ↔ whitelist `username`/`password`, role gán
  cứng `user` (hardened). Cờ CTF #9 ở `GET /api/me` khi user tự đăng ký
  có `role=admin`.
- **LAB-18 Blind SQL Injection** — `GET /track?code=` là oracle boolean
  (200 "TỒN TẠI" vs 404), rút cờ từng ký tự từ bảng ẩn `ctf_blind` bằng
  `substr()` (CTF #10 — 40 điểm, khó nhất). `trackShipmentSafe()`
  parameterized làm oracle biến mất. Hai bảng mới `shipments`/`ctf_blind`
  trong `src/db.js` (SQLite + fallback memory mô phỏng injection).
- **LAB-19 Reset token yếu** — `/api/reset/request` + `/api/reset/confirm`:
  token `md5(username)[0:12]` dự đoán được và trả trong response (vuln) ↔
  `crypto.randomBytes(16)` + TTL 10 phút + dùng một lần + không lộ token
  (hardened).
- **LAB-20 DOM-based XSS** — `/dom` render `location.hash` bằng `innerHTML`
  (vuln) ↔ `textContent` (hardened). Payload trong `#fragment` không lên
  server — bài học về telemetry mù.
- **CTF mở rộng 7 → 10 thử thách (265 điểm)**: proto pollution, mass
  assignment, blind SQLi.
- **Scanner 14 → 19 probe**: PROTO, MASS, BLIND, RESET, DOMXSS.
- **Detect mở rộng**: 4 pattern mới — proto-pollution, mass-assign,
  blind-sqli (behavioral, đếm theo IP), reset-abuse.
- **`docs/10-detection-engineering.md`** — từ access log tới alert: bảng 16
  rule hiện có, signature vs behavioral detection, vòng đời rule,
  giới hạn telemetry.
- **`docs/11-case-study-thuc-chien.md`** — 3 case study (blind SQLi, mass
  assignment, proto pollution) theo chu trình tấn công → phát hiện → vá →
  chứng minh.
- **Exercises 13 → 17 bài**: 14 proto+mass, 15 blind SQLi, 16 reset+DOM,
  17 detection engineering.
- **`tests/lab16-20.test.js`** — 14 test đối chứng mới; e2e thêm nhóm H
  (5 check) → **59/59**; unit **134/134**.
- Response `/_lab/verify` trả thêm `count` — CLI in `x/10` động thay vì
  hardcode.

### Sửa

- Đồng bộ toàn bộ số liệu tài liệu: 15→20 lỗ hổng, 7→10 CTF/170→265đ,
  14→19 probe, 13→17 bài tập, 115→134 test, 54→59 e2e, scan vuln
  10H/4M → 14H/5M — README, cheat-sheet, OWASP map (5 dòng LAB mới),
  e2e checklist, instructor guide (thêm buổi 4b), 9 chuyên mục hub.

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
