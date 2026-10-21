# 11 · Case Study Thực Chiến — tấn công → phát hiện → vá → chứng minh

> Ba tình huống dựng lại chu trình đầy đủ của một incident nhỏ — tất cả đều
> chạy được trên lab, tất cả output dưới đây là output THẬT đã chạy kiểm
> chứng. Mục tiêu: học viên nhìn thấy *cùng một lỗ hổng* qua 4 con mắt:
> attacker, scanner, blue-team, và người vá.

---

## Case 1 — Blind SQLi: "ứng dụng không lộ gì cả" nhưng vẫn mất CSDL

**Bối cảnh:** trang tra cứu vận đơn `/track?code=` của lab chỉ trả "TỒN TẠI"
hoặc "không tìm thấy". Nhìn bề ngoài không có gì để đánh cắp — không bảng
dữ liệu, không thông báo lỗi.

**Tấn công (red):**

```
GET /track?code=AB-100' AND 1=1 --   → 200
GET /track?code=AB-100' AND 1=2 --   → 404
```

Response khác nhau theo điều kiện → oracle boolean. Kẻ tấn công không cần
thấy dữ liệu — chỉ cần hỏi DB từng câu đúng/sai:

```
AB-100' AND (SELECT substr(flag,1,1) FROM ctf_blind)='F' --   → 200
AB-100' AND (SELECT substr(flag,1,1) FROM ctf_blind)='Z' --   → 404
```

Lặp đủ vị trí × ký tự → rút trọn `FLAG{blind-...}` từ bảng ẩn `ctf_blind`.
Trên hệ thống thật: đây là cách sqlmap rút DB qua một form tìm kiếm tưởng
"vô hại" — chỉ mất thời gian, không mất kỹ thuật.

**Phát hiện (blue):** một request `substr(...)` có thể trượt, nhưng rút 30 ký
tự cần ≥30 request cùng IP mang pattern SQL. Rule `blind-sqli` đếm theo IP —
behavioral detection, bắt *hành vi lặp* chứ không bắt payload.

**Vá (builder):** `trackShipmentSafe()` — parameterized query. Payload
`AND 1=1` trở thành chuỗi literal không khớp mã nào → 404, oracle chết.
Không phải "lọc input" mà là *không cho input tham gia vào cú pháp SQL*.

**Chứng minh:** e2e `H3` — cùng payload, vuln `200`, hardened `404`. Scanner
probe `BLIND-001` tái hiện toàn bộ chuỗi trên bản vuln, im lặng trên hardened.

**Bài học:** "không lộ dữ liệu trong response" KHÔNG đồng nghĩa an toàn —
side channel ở mã trạng thái/nội dung đã là oracle. Defense đúng: khử
oracle ở tầng query.

---

## Case 2 — Mass Assignment: đăng ký 5 giây, thành admin

**Bối cảnh:** `POST /api/register` nhận form `username&password`. Người dùng
bình thường không thấy gì khác.

**Tấn công (red):** endpoint còn gộp query string vào field và copy tất cả
vào object user:

```
POST /api/register?role=admin      (body: username=x&password=y)
→ 201 {"user":{"role":"admin"}}
POST /login → session cookie
GET  /api/me → {"role":"admin", "flag":"FLAG{mass-...}"}
```

Không cần SQLi, không cần XSS — chỉ cần server "lịch sự" nhận thêm field
client gửi. Đây là lỗi của GitHub năm 2012 (Rails mass assignment): user
push key vào repo của người khác vì form nhận trội `user_id`.

**Phát hiện (blue):** request `/api/register` kèm `role=`/`isadmin` trong
query — `mass-assign` rule. Lưu ý: nếu field độc nằm trong *body* thì access
log không thấy (lab không log body — bài học telemetry).

**Vá:** whitelist cứng `{username, password}` khi build object; `role` gán
server-side `'user'`; field lạ bị *bỏ qua* chứ không báo lỗi (tránh lộ
schema). Đối chứng: register `?role=admin` trên `:3001` → vẫn 201 nhưng
`role:"user"`, `/api/me` sạch cờ.

**Chứng minh:** e2e `H2`, unit test `LAB-17 hardened`.

**Bài học:** trust-boundary nằm ở *danh sách field được phép ghi* — không
phải ở client gửi gì. "Nhận được" ≠ "được phép".

---

## Case 3 — Prototype Pollution: một JSON object nhiễm cả process

**Bối cảnh:** `POST /api/config` merge JSON vào object config — tính năng
"cập nhật cấu hình" nghe vô hại.

**Tấn công (red):**

```
POST /api/config  {"__proto__":{"isAdmin":true}}
GET  /api/config  → {"protoPolluted":["isAdmin"], "flag":"FLAG{proto-...}"}
```

`unsafeMerge()` đi xuyên `dst.__proto__` → ghi vào `Object.prototype` toàn
cục. Từ đây **mọi** object trong process kế thừa `isAdmin`. Trên app thật:
một check `if (user.isAdmin)` ở file khác hoàn toàn bị bypass dù code check
đó không hề lỗi — prototype pollution là lỗ hổng *toàn cục*, không phải
lỗi của chỗ bị kiểm soát.

Key nhiễm còn trở thành enumerable → chính `GET /api/config` liệt kê được
bằng `Object.keys(Object.prototype)` — lab biến side-effect vô hình thành
điều nhìn thấy được.

**Phát hiện (blue):** rule `proto-pollution` bắt `__proto__`/`constructor[`
/`prototype[` trong request — signature-based, dễ evade (`__pro%74o__`,
nested `{"a":{"__proto__"...}}` trong body). Telemetry cần inspect JSON
sau parse, không chỉ path.

**Vá:** `safeMerge()` — bỏ qua `__proto__`, `constructor`, `prototype` khi
đệ quy. Hardened: `protoPolluted` luôn `[]`. Nâng cao hơn nữa: `Object.create
(null)` cho object nhận merge, hoặc `Object.freeze(Object.prototype)`.

**Chứng minh:** e2e `H1`, unit test `LAB-16` — vuln nhiễm `{}`.isAdmin=true,
hardened sạch.

**Bài học:** lỗ hổng của ngôn ngữ runtime (prototype chain) nằm trong một
hàm merge 10 dòng viết tay — "chỉ là merge object" không hề đơn giản khi
input là dữ liệu độc.

---

## Mẫu chung rút ra từ 3 case

| Bước | Câu hỏi đặt ra |
|---|---|
| Tấn công | Input nào của tôi chạm tới trạng thái/quyền? |
| Phát hiện | Payload né được thì *hành vi lặp* có né được không? |
| Vá | Sửa ở tầng nào — filter (yếu) hay kiến trúc (mạnh)? |
| Chứng minh | Test đối chứng nào chứng tỏ vá *đúng lỗ hổng* chứ không phải vá bề mặt? |

Cùng một quy trình áp dụng cho cả 20 lỗ hổng của lab — đây là bản chất của
"secure development lifecycle", chỉ gói trong 2 server loopback.
