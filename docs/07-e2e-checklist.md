# 07 · Ma trận E2E tự kiểm thử — kết quả đã chạy thật

> Hai tầng kiểm thử bổ trợ nhau:
> **(1) `npm run e2e`** — 64 check HTTP tự động, tự khởi động 3 server trên port tạm, chạy được trong CI.
> **(2) Browser E2E qua browser-use** — chính trình duyệt thật (webview Chromium) thao tác như người dùng: click, điền form, cookie jar thật, chụp màn hình.

Kết quả lần chạy gần nhất (2026-10-21): **E2E 64/64 PASS · Browser E2E 30/30 PASS**.

## Tầng 1 — `npm run e2e` (64 check, tự chứa)

| Nhóm | Số check | Phủ những gì |
|---|---|---|
| A. Hub | 8 | 200 + tiêu đề; đủ 10 chuyên mục (9 file + catalog LAB tự sinh); mục lục KHÔNG nhân đôi; đủ "Điểm cần nhớ"; cảnh báo Điều 287; số liệu pháp lý đã kiểm chứng (không "12–15 năm", có "7–12 năm"); path traversal raw path → 403; 404 |
| B. Hardened — luồng hợp lệ | 17 | trang chủ; search 1 dòng; SQLi → 0 dòng; XSS escape; login đúng + cookie HttpOnly/SameSite; SQLi bypass → 401 không lộ CSDL; IDOR 401; /admin 403; user đọc của mình 200; bob đọc người khác 403; download hợp lệ 200; traversal 400; /files 403; /slow chờ thật; metrics; security headers; logout |
| C. Vuln — lỗ hổng phải TỒN TẠI (đối chứng) | 10 | SQLi boolean lộ ≥4 email; error-based lộ CSDL; XSS phản chiếu nguyên văn; bypass login thành công; cookie thiếu HttpOnly/SameSite; IDOR 200; /admin 200; traversal lộ LAB_SECRET; /files listing; phiên hoạt động |
| D. Rate limit (instance riêng) | 2 | burst 28 → có 429; 429 kèm Retry-After |
| F. CTF + log blue-team | 8 | 10 thử thách/265 điểm; cờ sqli trong dump; flag-ctf.txt; admin flag; idor apiKey; verify đúng/sai; /_lab/log entry; hardened tắt CTF |
| G. Lỗ hổng mở rộng LAB-09..15 (đối chứng) | 8 | CMDI echo marker; JWT alg=none + weak secret; open redirect 302 vs 400; upload .html text/html vs 415; XXE resolve vs 400; stored XSS raw vs escaped; CSRF không token 200 vs 403 |
| H. Lỗ hổng nâng cao LAB-16..20 (đối chứng) | 5 | proto pollution nhiễm prototype vs lọc sạch; mass assign role=admin vs user; blind SQLi oracle 200/404 vs 404; reset md5 đoán được vs random+one-time; DOM XSS innerHTML vs textContent |
| I. Dashboard Red/Blue Team | 5 | /lab Red Team đủ 20 thẻ + CTF panel; /lab hardened banner đối chứng; /blue SOC console + feed + rules; /_lab/alerts phát hiện tấn công từ traffic thật; /_lab/log ghi status sau response |
| E. Dọn dẹp | 1 | hub server đóng sạch |

Ghi chú kỹ thuật: check A7 phải dùng **raw HTTP request** (`node:http`, không chuẩn hoá
đường dẫn) vì `fetch()` của Node tự gộp `/../` trước khi gửi — lỗi test, không phải lỗi server.

## Tầng 2 — Browser E2E qua browser-use (30 kịch bản, webview Chromium thật)

| # | Kịch bản | Bằng chứng |
|---|---|---|
| H1 | Hub hiển thị: hero gradient, badge 8 chương, mục lục | screenshot |
| H2 | Điều hướng anchor tới chuyên mục 02 | hash `#chuong-02` + screenshot thẻ 3 cột |
| H3 | Mục lục duy nhất (sau sửa lỗi nhân đôi) | snapshot: 8 link, không trùng |
| L1 | Lab hardened: trang chủ render (dark-native sau sửa lỗi viewer ép dark) | screenshot |
| L2 | Click link /search → bảng kết quả alice | domSnapshot |
| L3 | Điền payload SQLi vào ô tìm kiếm → 0 dòng | evaluate rows=0 |
| L4 | Login alice/alice123 → 200 "Xin chào" | evaluate |
| L5 | SQLi bypass login → 401 thông báo chung, không lộ CSDL | evaluate |
| L6 | Phiên thật: /api/me trả alice qua **cookie jar trình duyệt** | evaluate |
| L7 | HttpOnly kiểm chứng ngược: `document.cookie` KHÔNG thấy session | evaluate |
| L8 | IDOR: alice (admin) đọc user 2 → 200 | evaluate |
| L9 | IDOR: bob đọc user 1 → 403; user 2 (của mình) → 200 | evaluate |
| L10 | Logout → /api/me user:null; cookie bị thu hồi | evaluate |
| L11 | Download traversal → 400; /files 403; /admin 403 | evaluate |
| L12 | /slow?ms=150 → 200, chờ đúng ~163ms | evaluate |
| L13 | /_lab/metrics mode=hardened | evaluate |
| L14 | CORS: fetch chéo origin 3001→3000 bị trình duyệt chặn (lớp phòng thủ miễn phí) | evaluate |
| V1 | Vuln: SQLi `' OR 1=1 --` lộ đủ 4 người dùng | **screenshot** |
| V2 | Vuln: /admin mở tự do không đăng nhập | evaluate |
| V3 | Vuln: IDOR 200 không cần phiên | evaluate |
| V4 | Vuln: traversal lộ LAB_SECRET | evaluate |
| V5 | Vuln: /files liệt kê invoice-2026.pdf | evaluate |
| V6 | Vuln: error-based lộ lỗi SQLite | evaluate |
| S1 | Hub server: file hợp lệ 200; traversal 403 (curl + raw) | curl/netstat |
| S2 | Webview ép dark mode → phát hiện & sửa lab sang dark-native | screenshot trước/sau |
| S3 | POST top-level bị webview chặn → thay bằng in-page fetch (cùng endpoint + cookie jar) | ghi nhận hạn chế |

## Cách chạy lại

```bash
npm test        # 147 unit/integration
npm run e2e     # 64 E2E HTTP (tự khởi động server, port tạm)
node src/cli.js hub --port 4000   # rồi mở http://127.0.0.1:4000 xem hub
node src/cli.js serve --hardened --port 3001  # lab để test tay trên trình duyệt
```

Phần browser-use được điều khiển qua ZCode (skill control-browser); webview có hai
hạn chế đã ghi nhận: ép dark mode toàn cục, và chặn điều hướng POST top-level
(không ảnh hưởng trình duyệt thật của bạn — Chrome/Edge render và POST chuẩn).
