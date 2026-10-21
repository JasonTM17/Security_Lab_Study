# 04 · Cheat sheet — tất cả lệnh và payload của lab

> LƯU Ý Git Bash trên Windows: dùng cú pháp `--path=slow` (dấu `=`) để Git Bash
> không biến `/slow` thành `C:/Program Files/Git/slow`.

## Lệnh

```bash
npm run doctor                              # kiểm tra môi trường
npm run serve                               # lab VULN    → http://127.0.0.1:3000
npm run serve -- --port 3001                # lab VULN    ở port khác
npm run serve:hardened                      # lab HARDENED → http://127.0.0.1:3000
npm test                                    # 71 test (guard, ratelimiter, app, scraper, flowload, unit-gaps)
npm run e2e                                 # 38 check E2E HTTP — tự khởi động 3 server, đối chứng vuln/hardened

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
| `GET /slow?ms=` | endpoint chậm 3s (mồi cho DoS demo) | vẫn chậm, nhưng rate limit bảo vệ |
| `GET /_lab/metrics` | bộ đếm request (dụng cụ học tập) | có |
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
