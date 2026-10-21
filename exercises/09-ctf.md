# Bài 09 — Chế độ CTF: giải trọn 4 thử thách của lab

> Cờ sinh ngẫu nhiên **mỗi lần khởi động lab vuln**. Nhiệm vụ: khai thác 4 lớp lỗ hổng
> bằng tay (trình duyệt hoặc curl), thu đủ 4 cờ `FLAG{...}` và nộp về server xác minh.
> Bản hardened từ chối nhận cờ — đã vá thì không còn đường lấy: đó là phần bài học.

## Chuẩn bị

```bash
node src/cli.js serve              # lab vuln + CTF ở 127.0.0.1:3000
node src/cli.js challenge http://127.0.0.1:3000    # xem 4 thử thách + gợi ý
```

## 4 thử thách (100 điểm)

| # | Thử thách | Điểm | Kỹ năng |
|---|---|---|---|
| 1 | SQL Injection — dump toàn bộ người dùng | 30 | boolean-based SQLi; tìm người dùng ẩn mang cờ trong email |
| 2 | Path Traversal — đọc flag-ctf.txt ở GỐC | 25 | leo thư mục bằng `../`; file KHÔNG có trong /files listing |
| 3 | IDOR — đánh cắp apiKey của dave | 25 | đọc dữ liệu người khác khi chưa có phiên |
| 4 | Broken Access Control — vào /admin | 20 | route nhạy cảm không kiểm tra quyền |

## Gợi ý theo lớp (đọc dần, đừng nhảy cóc)

1. **SQLi:** `/search?q=` — bản vuln nối chuỗi. Payload kinh điển `' OR 1=1 --`.
   Người dùng ẩn `zz_ctf_hidden` không bao giờ hiện khi tìm "alice".
2. **Traversal:** `/download?name=...` — file cờ nằm ở GỐC (ngoài `files/`).
   `/files` liệt kê KHÔNG cho thấy nó — vì sao? (xem `src/lab/app.js` — listing chỉ lọc `files/`).
3. **IDOR:** so sánh `/api/users/4` trên vuln (200, trả cả apiKey) và hardened (401).
4. **Admin:** mở thẳng `/admin` trên vuln. Trên hardened: 403.

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

✅ **Hoàn thành khi:** score 100/100 (server xác nhận) + một bản chụp màn hình
`detect` hiện đúng 4 nhóm dấu hiệu từ session của bạn + 3 câu trả lời:

1. Vì sao cờ phải sinh theo phiên (không hardcode)?
2. `timingSafeEqual` chống lại kiểu tấn công nào?
3. Nếu hardened trả 404 thay vì 403 cho /admin thì điều gì tốt/dở cho người phòng thủ?
