# Bài 09 — Chế độ CTF: giải trọn 10 thử thách của lab

> Cờ sinh ngẫu nhiên **mỗi lần khởi động lab vuln**. Nhiệm vụ: khai thác 7 lớp lỗ hổng
> bằng tay (trình duyệt hoặc curl), thu đủ 7 cờ `FLAG{...}` và nộp về server xác minh.
> Bản hardened từ chối nhận cờ — đã vá thì không còn đường lấy: đó là phần bài học.

## Chuẩn bị

```bash
node src/cli.js serve              # lab vuln + CTF ở 127.0.0.1:3000
node src/cli.js challenge http://127.0.0.1:3000    # xem 10 thử thách + gợi ý
```

## 10 thử thách (265 điểm)

| # | Thử thách | Điểm | Kỹ năng |
|---|---|---|---|
| 1 | SQL Injection — dump toàn bộ người dùng | 30 | boolean-based SQLi; tìm người dùng ẩn mang cờ trong email |
| 2 | Path Traversal — đọc flag-ctf.txt ở GỐC | 25 | leo thư mục bằng `../`; file KHÔNG có trong /files listing |
| 3 | IDOR — đánh cắp apiKey của dave | 25 | đọc dữ liệu người khác khi chưa có phiên |
| 4 | Broken Access Control — vào /admin | 20 | route nhạy cảm không kiểm tra quyền |
| 5 | Command Injection — đọc biến môi trường server | 25 | nối lệnh bằng `&`/`;` trong /tools/ping; cờ ở `SECLAB_CTF_CMD` |
| 6 | JWT yếu — giả mạo token ctfsvc | 25 | alg=none hoặc crack secret `secret123` bằng `jwt crack`/`jwt forge` |
| 7 | XXE — đọc flag-xxe.txt qua entity | 20 | `<!ENTITY x SYSTEM "file:///flag-xxe.txt">` trong POST /api/import |
| 8 | Prototype Pollution — nhiễm Object.prototype | 30 | POST `{"__proto__":{"isAdmin":true}}` vào /api/config → GET lại |
| 9 | Mass Assignment — tự cấp role admin | 25 | `POST /api/register?role=admin` → login → /api/me |
| 10 | Blind SQLi — rút cờ từng ký tự | 40 | oracle boolean ở /track?code=; substr(flag,N,1) từ ctf_blind |

## Gợi ý theo lớp (đọc dần, đừng nhảy cóc)

1. **SQLi:** `/search?q=` — bản vuln nối chuỗi. Payload kinh điển `' OR 1=1 --`.
   Người dùng ẩn `zz_ctf_hidden` không bao giờ hiện khi tìm "alice".
2. **Traversal:** `/download?name=...` — file cờ nằm ở GỐC (ngoài `files/`).
   `/files` liệt kê KHÔNG cho thấy nó — vì sao? (xem `src/lab/app.js` — listing chỉ lọc `files/`).
3. **IDOR:** so sánh `/api/users/4` trên vuln (200, trả cả apiKey) và hardened (401).
4. **Admin:** mở thẳng `/admin` trên vuln. Trên hardened: 403.
5. **CmdInj:** `/tools/ping?host=127.0.0.1 & set SECLAB` (Windows) hoặc
   `; env | grep SECLAB` (Linux). Chi tiết: `exercises/10-command-injection.md`.
6. **JWT:** `jwt decode` → `jwt crack` (secret123) hoặc `jwt forge --alg none`,
   payload `{"sub":"ctfsvc"}` → `/api/profile`. Chi tiết: `exercises/11-jwt.md`.
7. **XXE:** entity `file:///flag-xxe.txt` trong POST /api/import.
   Chi tiết: `exercises/13-upload-xxe-stored-xss.md`.
8. **Proto pollution:** JSON body `{"__proto__":{"isAdmin":true}}` — key nhiễm
   enumerable lộ ra ở GET /api/config. Chi tiết: `exercises/14`.
9. **Mass assign:** register kèm `?role=admin` — field query string bị gộp vào
   user object. Cờ chỉ hiện ở `/api/me` khi user TỰ ĐĂNG KÝ có role admin.
   Chi tiết: `exercises/14`.
10. **Blind SQLi:** khó nhất — không có dữ liệu trong response, chỉ có
    200 vs 404. Xác nhận oracle `AND 1=1`/`AND 1=2` rồi rút từng ký tự bằng
    `substr`. Viết script tự động. Chi tiết: `exercises/15-blind-sqli.md`.

## Nộp cờ

```bash
node src/cli.js challenge http://127.0.0.1:3000 --submit=1 --flag='FLAG{sqli-xxxxxxxx}'
# hoặc nộp bằng curl:
curl "http://127.0.0.1:3000/_lab/verify?id=1&flag=FLAG%7Bsqli-xxxx%7D"
```

Server xác minh bằng **so sánh thời gian hằng** (`crypto.timingSafeEqual`) — thử hiểu
vì sao chi tiết đó quan trọng (gợi ý: timing attack đo độ dài so sánh).

## Lần 2 — nhìn bằng mắt blue-team

Sau khi khai thác xong, NGAY TRÊN PHIÊN LAB ĐÓ:

```bash
node src/cli.js detect http://127.0.0.1:3000
```

Bạn sẽ thấy CHÍNH các request vừa làm xuất hiện trong log như dấu hiệu tấn công
(SQLi probe, traversal, dò admin). Đó là vòng lặp nghề: **tấn công → phát hiện → phòng thủ**.
Chạy lại trên bản hardened (`npm run serve:hardened -- --port 3001`) và dùng `detect`
sau khi thử cùng payload — hardened chặn hết nhưng LOG vẫn ghi nhận đủ để phân tích.

✅ **Hoàn thành khi:** score 265/265 (server xác nhận) + một bản chụp màn hình
`detect` hiện đúng các nhóm dấu hiệu từ session của bạn + 3 câu trả lời:

1. Vì sao cờ phải sinh theo phiên (không hardcode)?
2. `timingSafeEqual` chống lại kiểu tấn công nào?
3. Nếu hardened trả 404 thay vì 403 cho /admin thì điều gì tốt/dở cho người phòng thủ?
