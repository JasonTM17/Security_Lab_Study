# Bài 12 · CSRF + Open Redirect — lợi dụng niềm tin (LAB-10, LAB-12)

**Mục tiêu:** hai lỗ hổng "không chạy code trên server" nhưng đánh vào niềm tin:
CSRF lợi dụng **cookie tự gửi của trình duyệt**, Open Redirect lợi dụng
**tên miền hợp pháp của bạn** để dẫn tới trang độc.

## 1. CSRF — đổi email mà không cần biết mật khẩu

Lab vuln `http://127.0.0.1:3000`. Đăng nhập `alice/alice123` rồi mở `/settings`
— form đổi email **không có trường ẩn nào**.

Kịch bản thật: trang `evil.example` chứa form auto-submit

```html
<form action="http://127.0.0.1:3000/settings/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form><script>document.forms[0].submit()</script>
```

→ trình duyệt nạn nhân TỰ gửi kèm cookie phiên → server vuln đổi email.

Mô phỏng bằng curl (Origin lạ + không token vẫn được chấp nhận):

```bash
# đăng nhập lấy cookie
curl -si -X POST http://127.0.0.1:3000/login -d "username=alice&password=alice123" | grep -i set-cookie
# giả lập request CSRF từ trang độc
curl -s -X POST http://127.0.0.1:3000/settings/email \
  -H "Cookie: session=<sid>" -H "Origin: https://evil.example" \
  -d "email=attacker@evil.example"        # → 200, email bị đổi!
```

## 2. Đối chứng hardened

Bản hardened (`:3001`) phòng thủ 3 lớp:

- **Synchronizer token**: form có `<input name="csrf" value="...">` — token =
  HMAC(secret, sessionId); trang độc không đọc được (same-origin policy) →
  không forge được. POST thiếu token → `403 csrf_failed`.
- **Kiểm Origin**: `Origin` lạ → `403 bad_origin`.
- **Cookie SameSite=Strict**: trình duyệt không gửi cookie trong request
  cross-site — đã có sẵn ở hardened.

## 3. Open Redirect — "cầu" tới phishing

```
http://127.0.0.1:3000/redirect?to=https://example.com/phish   → 302 tới domain ngoài
http://127.0.0.1:3001/redirect?to=https://example.com/phish   → 400 (hardened)
http://127.0.0.1:3001/redirect?to=/slow                        → 302 path nội bộ vẫn OK
```

Nguy hiểm vì: link `http://ten-mien-uy-tin/redirect?to=...` **vượt qua** cảm
giác an toàn của nạn nhân và cả bộ lọc URL thô sơ. Kiểm `startsWith('/')` +
chặn `//` (protocol-relative) + chặn `\` là cách vá đúng ở hardened.

## ✅ Hoàn thành khi

- [ ] Đổi email bằng POST cross-origin (không token) trên vuln
- [ ] Cùng request đó bị 403 trên hardened; request kèm token đúng → 200
- [ ] Giải thích: SameSite cookie và CSRF token khác nhau thế nào? Vì sao
      SameSite=Lax chưa đủ cho mọi endpoint?
