# Bài 05 · Mô phỏng tải & slowloris — vì sao server sập, và nhắm chừng thế nào

**Mục tiêu:** tái hiện hai kỹ thuật DoS lớp 7 trong phạm vi lab, ĐO bằng số,
rút ra nguyên lý phòng thủ. (Chỉ 127.0.0.1 — xem `docs/01` vì sao.)

## 1. HTTP flood vào endpoint chậm (bản vuln)

```bash
node src/cli.js loadtest http://127.0.0.1:3000 --path=slow --rps 40 --duration 8
```

Đọc kết quả:

- `thông lượng thực tế ≈ 13 req/s` dù yêu cầu 40 — vì mỗi request chiếm worker 3 giây.
- `p95 ≈ 3000ms` — khách hàng "bình thường" cũng chịu trọn độ trễ này.
- Server xác nhận đã nhận đủ request — nghẽn do **xử lý**, không do mạng.

**Công thức mấu chốt:** `thông lượng ≤ số worker × (1000 / thời gian xử lý ms)`.
Endpoint chậm = giảm 30 lần thông lượng. Attacker hiểu điều này nên luôn nhắm
endpoint đắt tiền (search, upload, báo cáo).

## 2. So sánh với bản hardened (rate limit hoạt động)

```bash
node src/cli.js loadtest http://127.0.0.1:3001 --path=slow --rps 40 --duration 8
```

Kỳ vọng: rừng `429` (151/186 chẳng hạn) nhưng `p50 ≈ vài ms` — server **từ chối
có kiểm soát** thay vì ngộp thở. Đó là toàn bộ tinh thần của anti-DoS: không
"chịu được tải", mà "không chết vì tải".

## 3. Slowloris — cực ít băng thông, cực nhiều phiền

```bash
node src/cli.js slowloris http://127.0.0.1:3000 --sockets 100 --duration 20
```

Bản vuln: **giữ 100/100 kết nối "nửa request"** — server cứ chờ phần header còn
lại. Làm điều này với vài nghìn socket là tê liệt, băng thông gần bằng 0.

```bash
node src/cli.js slowloris http://127.0.0.1:3001 --sockets 100 --duration 20
```

Bản hardened: **cắt sớm ~90 kết nối** (giới hạn half-open connection per-IP +
`headersTimeout`), request bình thường vẫn `200`.

## 4. Thí nghiệm tự thiết kế

- Đo dần dần: `--rps 5, 10, 20, 40` lên `/slow` — tìm "điểm gãy" của server vuln.
- So sánh `--path=/` (endpoint rẻ) vs `--path=slow` — cùng rps, khác hệ quả.
- Giảm `--sockets` xuống 5 trên slowloris — vì sao bản hardened không cắt nữa?
  (gợi ý: ngưỡng `HALF_OPEN_LIMIT = 10` trong `src/lab/app.js`).

## ✅ Hoàn thành khi

- [ ] Nêu được 3 con số: thông lượng vuln, % 429 hardened, số kết nối bị cắt slowloris
- [ ] Giải thích được 4 hàng rào trong `docs/03` §4 và chỉ ra code của từng hàng rào
- [ ] Hiểu vì sao bài học này KHÔNG cho phép tấn công ngoài lab (Điều 287 BLHS)
