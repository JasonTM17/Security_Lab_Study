# Bài 07 — Cào dữ liệu lịch sự & mô phỏng luồng người dùng thật

> Mục tiêu: dùng 2 lệnh mới của SecLab — `crawl` (web công khai, hợp pháp) và
> `flowtest` (luồng người dùng thật, chỉ trên lab) — và đọc đúng số liệu.

## Phần A — Crawl trên lab (an toàn tuyệt đối)

### Chuẩn bị

```bash
npm run serve            # terminal 1: lab vuln ở 127.0.0.1:3000
```

### Thực hành

```bash
node src/cli.js crawl --url=http://127.0.0.1:3000 --max-pages=6 --depth=2 --i-own-this-target
```

### Việc cần làm

1. Chú ý dòng `robots.txt: có — đã tôn trọng` — đọc `http://127.0.0.1:3000/robots.txt`
   và khớp với danh sách URL trong báo cáo: có URL nào thuộc `Disallow` bị bỏ qua không?
2. Với mỗi trang, so cột **Tiêu đề** trích ra với nội dung thật của trang.
3. Mở `reports/crawl-127.0.0.1-*.json` — đây là dữ liệu có cấu trúc bạn có thể
   nạp tiếp vào Python/Excel. Cột `ms` là **latency từng request thật**.
4. Chạy lại **không có** `--i-own-this-target` → tool phải từ chối với thông báo
   "scraper mặc định chỉ chạy trên WEB CÔNG KHAI". Đây là guard ngược chiều:
   scraper cho public nhưng chặn nội bộ; các module tấn công thì ngược lại.
5. **ĐÚNG pháp lý:** chạy `crawl --url=https://example.com --max-pages=3` —
   site demo của IANA, robots.txt cho phép. Đọc báo cáo rồi xoá thư mục
   `reports/` nếu không cần giữ.

✅ **Hoàn thành khi:** giải thích được tại sao scraper dùng guard NGƯỢC chiều
(cho public, chặn nội bộ) so với loadtest, và chỉ ra ít nhất 1 URL bị robots chặn
hoặc lý do không có.

## Phần B — Flowtest: "người dùng thật" khác bắn 1 endpoint thế nào

### Chuẩn bị

```bash
npm run serve:hardened -- --port 3001    # terminal 2: bản đã vá
```

### Thực hành — so sánh vuln vs hardened với CÙNG luồng

```bash
# vuln (đang chạy ở 3000):
node src/cli.js flowtest http://127.0.0.1:3000 --users=8 --iterations=10 --think=100

# hardened (3001):
node src/cli.js flowtest http://127.0.0.1:3001 --users=8 --iterations=10 --think=100
```

### Việc cần làm

1. So sánh **statusCounts** từng bước: ở hardened, bước nào bắt 429 trước?
   (thường là mọi bước sau khi token bucket cạn — nhưng kiểm chứng bằng số).
2. Ở hardened có bước trả **401** không? Vì sao vuln không có? (gợi ý: hardened
   yêu cầu phiên đăng nhập cho dữ liệu user khác — IDOR đã được vá).
3. Tăng `--users=20 --iterations=20` trên hardened: p95 từng bước có tăng vọt
   không, hay vẫn thấp vì 429 trả gần như tức thời? Rút ra nhận xét: rate limiter
   bảo vệ **độ trễ** của người dùng hợp lệ như thế nào.
4. Tự định nghĩa luồng của riêng bạn bằng cách sửa `DEFAULT_FLOW` trong
   `src/modules/flowload.js` (ví dụ thêm bước `/download?name=readme.txt`),
   rồi chạy lại — quan sát bước mới thêm nặng nhất thế nào.

✅ **Hoàn thành khi:** có một bảng so sánh 2 lệnh chạy (vuln vs hardened) gồm
statusCounts từng bước + p95 chuỗi luồng, và 3 câu nhận xét của riêng bạn.

## Câu hỏi tự vấn (trả lời được là đã hiểu)

1. Vì sao `flowtest` chặn mục tiêu public còn `crawl` thì cho phép public?
2. `Crawl-delay: 5` trong robots.txt ảnh hưởng lệnh của bạn thế nào khi
   bạn truyền `--delay-ms=300`?
3. Nếu một site công khai muốn bạn đo tải giúp họ — quy trình đúng phải gồm
   giấy tờ gì trước khi bạn chạy bất cứ lệnh tạo tải nào?
