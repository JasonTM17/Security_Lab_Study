# Bài 03 · Quét lỗ hổng tự động

**Mục tiêu:** chạy scanner, ĐỌC báo cáo, hiểu từng finding — không chỉ nhìn "đỏ là xong".

```bash
node src/cli.js scan http://127.0.0.1:3000
```

Kỳ vọng bản vuln: **🔴 High 4 · 🟠 Medium 3**. Báo cáo được ghi vào `reports/scan-*.md` và `.html`.

## Giải mã từng finding

| ID | Lỗi là gì | Mức độ | Vá ở đâu (đọc code!) |
|---|---|---|---|
| SQLI-001/002 | Nối chuỗi input vào SQL | High | `src/db.js` → so sánh `searchUsers` vs `searchUsersSafe` |
| XSS-001 | In input ra HTML không encode | High | `src/lab/app.js` → hàm `esc()` |
| IDOR-001 | API không kiểm tra ownership | High | route `/api/users/:id` — bản hardened có session check |
| PATH-001 | `/admin` + `/files/` mở tự do | High | route `/admin`, `/files` |
| HDR-001 | Thiếu 5 security headers | Medium | `src/defense/headers.js` |
| CKI-001 | Cookie không HttpOnly/SameSite | Medium | `Set-Cookie` ở route `/login` |
| RPS-001 | 60 request dồn dập, 0 lần bị chặn | Medium | `src/defense/ratelimiter.js` |

**Bài tập bắt buộc:** mở 2 file code ở cột "Vá ở đâu", đọc cặp hàm lỗi/đã-vá
cạnh nhau. Đây là phần học nhiều nhất của toàn bài.

## So sánh với bản hardened

```bash
node src/cli.js scan http://127.0.0.1:3001
```

Kỳ vọng: **High 0 · Medium 0 · ✅ Đạt 3** (headers, cookie, rate limit).

## Câu hỏi kiểm tra hiểu biết

1. Vì sao SQLI là High còn HDR là Medium? (gợi ý: tác hại trực tiếp vs hàng rào hỗ trợ)
2. Scanner báo "không có rate limit" bằng cách nào? Nó gửi bao nhiêu request?
3. Nếu bạn phải vá thêm 1 thứ ngoài danh sách trên, bạn chọn gì?

## ✅ Hoàn thành khi

- [ ] Có 2 báo cáo trong `reports/` (vuln + hardened) và giải thích được sự khác biệt từng dòng
- [ ] Đọc xong cặp hàm `searchUsers` / `searchUsersSafe` và tự viết lại theo cách mình
