# Answer key · Bài 01–06 — nền tảng

> Đáp án "tiêu chí hoàn thành" của từng bài + lỗi học viên hay mắc + output
> mẫu để chấm. Đối chiếu với checklist cuối mỗi file `exercises/`.

---

## Bài 01 · Khởi động lab

| Checklist | Đáp án / cách chấm |
|---|---|
| `npm test` xanh 140/140 | Output có `ℹ tests 140 · ℹ pass 140 · ℹ fail 0` |
| Hai lab song song 3000/3001 | `curl -sI :3000` 200 badge VULN; `:3001` badge HARDENED |
| Vì sao `recon http://8.8.8.8` bị từ chối | `guard.js` assertAuthorizedTarget: chỉ loopback tự do; dải riêng cần `--i-own-this-target`; public chặn tuyệt đối — Điều 287 BLHS. |

**Lỗi hay gặp:** `EADDRINUSE` khi mở 2 lab cùng port — phải `--port 3001` cho bản hardened (exercise 01 §4). `node:sqlite experimental` warning là bình thường, không phải lỗi.

---

## Bài 02 · Recon

| Checklist | Đáp án gợi ý |
|---|---|
| ≥2 thông tin "có giá trị cho kẻ tấn công" | (1) `X-Powered-By`/Server lộ stack Node → dò CVE theo version; (2) thiếu security headers → biết trước không có CSP; (3) robots.txt lộ path admin/backup; (4) port scan thấy dịch vụ lạ. |
| Vì sao prod nên tắt `X-Powered-By` | Security-by-obscurity không phải vá, nhưng fingerprinting làm rẻ cuộc tấn công: bot quét tự động lọc mục tiêu theo stack. Ẩn ≠ vá — nhưng không nên quảng cáo. |

**Đáp án câu hỏi mở:** recon thụ động = đọc tín hiệu có sẵn (headers, robots, port mở) không gửi payload — ranh giới pháp lý vẫn mỏng: port scan trên hệ thống người khác có thể vi phạm dù "chỉ đọc".

---

## Bài 03 · Quét lỗ hổng

| Checklist | Đáp án |
|---|---|
| 2 báo cáo trong `reports/` | `scan-*.md/html` — vuln: **14 High + 5 Medium**; hardened: 0 finding + 3 Đạt (headers/cookie/rate-limit OK). |
| Giải thích từng dòng khác biệt | HDR/CKI chuyển Đạt vì `securityHeaders()`+cookie cờ; SQLi/XSS/IDOR/PATH/CMDI/CSRF/JWT/OREDIR/UPLOAD/XXE biến mất vì vá server-side; PROTO/MASS/BLIND/RESET/DOMXSS biến mất vì hardened lọc merge/whitelist/parameterize/random token/textContent. |
| Viết lại `searchUsers`/`searchUsersSafe` | Vuln: `` `WHERE name LIKE '%${q}%'` ``. Safe: `WHERE name LIKE ?` truyền `'%'+q+'%'` — input luôn là data. |

**Câu hỏi hay bị hỏi:** "scanner có thay thế pentester không?" — không: scanner chỉ bắt signature đã biết (19 probe), blind-logic/business-logic/SSRF chuỗi phức tạp cần người. Chứng minh: DOM-XSS probe chỉ phân tích source/sink tĩnh, không chứng minh exploit được.

---

## Bài 04 · Tấn công lab (4 nhóm cơ bản)

| Checklist | Đáp án chuẩn |
|---|---|
| 4 nhóm lỗi trên vuln | SQLi `' OR 1=1 --`; XSS `<svg/onload=alert(1)>`; IDOR `/api/users/4` không phiên; traversal `../secrets.txt` |
| Payload tự viết bị chặn hardened | SQLi→0 dòng; XSS→`&lt;svg`; IDOR→401; traversal→400 |
| Dòng code gốc | SQLi: `db.js` nối chuỗi LIKE; XSS: `app.js` render `q` không `esc()`; IDOR: thiếu check `session.id===params.id`; traversal: thiếu filter `..`. |

**Câu hỏi phỏng vấn hay gặp:** "vì sao escape output không vá SQLi?" — hai tầng khác nhau: SQLi là data→SQL (vá bằng parameterize), XSS là data→HTML (vá bằng escape). Trộn hai khái niệm = vá sai chỗ.

---

## Bài 05 · Mô phỏng tải & slowloris

| Checklist | Đáp án (số thật đo trên máy dev) |
|---|---|
| 3 con số | vuln `/slow` 40rps: ~13 req/s thực tế, p95 ~3000ms; hardened: ~80% request 429; slowloris 100 socket: vuln giữ gần hết, hardened cắt ~90 bằng per-IP half-open limit + header timeout. |
| 4 hàng rào trong `docs/03` §4 | (1) rate limit token-bucket (`src/defense/ratelimiter.js`); (2) request/header timeout (`server.timeout`/`headersTimeout` trong serve.js); (3) giới hạn kết nối half-open per-IP; (4) body size cap `readBody(maxBytes)`. |
| Không tấn công ngoài lab | Điều 287 BLHS 2015 — xâm nhập trái phép hệ thống mạng; DoS là tấn công tính sẵn sàng, không có "kích thước nhỏ thì không tính". |

---

## Bài 06 · Phòng thủ & báo cáo

| Checklist | Đáp án |
|---|---|
| Bảng so sánh vuln/hardened | Tối thiểu: scan findings (14H5M vs 0), loadtest p95 (3000ms vs vài ms), %429 (0% vs ~80%), slowloris sockets giữ (100 vs ~10). |
| Báo cáo 1 trang | Cấu trúc: mục tiêu → phạm vi → findings theo severity → evidence → remediation → retest. Mẫu: `reports/scan-*.md` đã gần đúng format — chỉ cần thêm executive summary + phạm vi. |
| 3 hàng rào bật NGAY trên website thật | (1) security headers (miễn phí, chặn clickjacking/sniffing); (2) rate limit per-IP (chặn brute force + DoS nhỏ); (3) request/header timeout (slowloris). Sau đó: parameterize mọi query, CSRF token, cookie cờ. |

**Điểm hay để hỏi sâu:** "rate limit chặn được DDoS thật không?" — chỉ chặn per-IP tầng 7 nhỏ; DDoS phân tán hàng triệu IP cần CDN/Anycast/upstream scrubbing — rate limit là *hàng rào đầu* không phải toàn bộ.
