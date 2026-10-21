# Bài 06 · Phòng thủ, viết báo cáo, và lộ trình tiếp theo

**Mục tiêu:** đóng vòng lặp pentest: phát hiện → vá → **chứng minh đã vá** → báo cáo.

## 1. Đọc code phòng thủ (phần "đắt" nhất của bài học)

| File | Hàng rào | Đọc kỹ cái gì |
|---|---|---|
| `src/defense/ratelimiter.js` | Token bucket | `capacity`, `refillPerSec`, vì sao trả 429 kèm `Retry-After` |
| `src/defense/headers.js` | Security headers | `HEADERS_DOC` — từng header chống loại tấn công nào |
| `src/lab/app.js` | Giới hạn half-open conn | `HALF_OPEN_LIMIT`, `HALF_OPEN_GRACE_MS` — vì sao cần grace 2s |
| `src/db.js` | Parameterized query | `searchUsersSafe` — placeholder `?` + `ESCAPE '\\'` |

## 2. Chứng minh bằng số (so sánh 2 báo cáo)

```bash
# đã có từ bài 03:
#   reports/scan-...-vuln.md  (High 4, Medium 3)
#   reports/scan-...-hard.md  (High 0, Medium 0)
```

Bảng so sánh bắt buộc trong báo cáo của bạn:

| Chỉ số | Vuln | Hardened |
|---|---|---|
| High findings | 4 | 0 |
| Medium findings | 3 | 0 |
| p95 latency khi flood 40 rps vào /slow | ~3000 ms | ~7 ms (p50) |
| Kết nối slowloris còn giữ | 100 | ~10 |
| Request bị 429 khi flood | 0 | ~80% |

## 3. Viết báo cáo pentest mini (1 trang)

Cấu trúc chuẩn ngành:

1. **Phạm vi** — mục tiêu nào, thời gian nào, kỹ thuật nào được phép.
2. **Tóm tắt cho quản lý** — 3 câu: rủi ro lớn nhất, trạng thái, khuyến nghị.
3. **Chi tiết từng finding** — ID, mức độ, bằng chứng (payload + response),
   tác hại, cách vá, trạng thái (mở/đã vá).
4. **Phụ lục** — output recon/loadtest, file báo cáo đính kèm.

Mở `reports/scan-*.md` — đó chính là phần 3 có sẵn; nhiệm vụ của bạn là viết
phần 1, 2 và phần "đã vá/chưa vá".

## 4. Lộ trình sau SecLab

1. **Cài bản vá của riêng bạn:** tự vá `/slow` bằng cache/queue, scan lại, cập nhật báo cáo.
2. **Thêm check mới vào scanner:** ví dụ phát hiện CSRF token, clickjacking test, HTTP methods (OPTIONS/TRACE).
3. **Đổi công cụ thật trên lab của bạn:** chạy [OWASP ZAP](https://www.zaproxy.org/)
   hoặc [Nikto](https://cirt.net/Nikto2) nhắm `127.0.0.1:3000` — so kết quả với SecLab.
4. **Học có chứng chỉ:** nền tảng lab hợp pháp — PortSwigger Web Security
   Academy (miễn phí), TryHackMe, HackTheBox, picoCTF.
5. **Đọc chuẩn:** OWASP Top 10 → OWASP ASVS → OWASP WSTG (kiểm thử web).

## ✅ Hoàn thành khi

- [ ] Có bảng so sánh số liệu vuln/hardened
- [ ] Có báo cáo 1 trang theo cấu trúc trên
- [ ] Trả lời được: "3 hàng rào nào nên bật NGAY trên 1 website thật?" (gợi ý: headers, rate limit, timeout)
