# 06 · Cào dữ liệu web công khai một cách HỢP PHÁP và LỊCH SỰ

> Module: `src/modules/scraper.js` · Lệnh: `node src/cli.js crawl --url=<https://site>`

## Ranh giới pháp lý — đọc trước khi cào

| Hành vi | Trạng thái |
|---|---|
| Fetch trang **công khai**, chậm rãi, tôn trọng robots.txt, phục vụ học tập cá nhân | ✅ Hợp pháp — như một trình duyệt đọc trang |
| Tạo **tải lớn** nhắm website công khai không thuộc sở hữu (load test / flood) | ❌ **Bất hợp pháp** — Điều 287 BLHS 2015. SecLab **chặn cứng** mọi lệnh tạo tải nhắm mục tiêu public |
| Cào vượt qua đăng nhập / paywall / vùng riêng tư | ❌ Xâm nhập bất hợp pháp (Điều 291, Luật An ninh mạng 2018) |
| Thu thập **dữ liệu cá nhân** quy mô lớn (email, SĐT, CMND…) | ❌ Vi phạm Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân |
| Cào nội dung rồi **đăng lại** như của mình | ❌ Vi phạm bản quyền (Luật Sở hữu trí tuệ) |

**Nguyên tắc một dòng:** cào = đọc như người dùng lịch sự; đo tải = chỉ làm với hệ thống của bạn.

## SecLab đã cài sẵn những "phanh" nào

| Phanh | Giá trị mặc định | Ghi trong code tại |
|---|---|---|
| Chỉ http/https, xác thực host bằng DNS | bắt buộc | `assertScrapeTarget()` |
| Chặn loopback/dải riêng khi không có cờ sở hữu | chặn | `assertScrapeTarget()` |
| robots.txt — Disallow/Allow longest-match | tôn trọng tuyệt đối | `robotsAllows()` |
| Crawl-delay của site (nếu robots khai báo) | tự nhân bản lớn hơn delay của bạn | `runCrawl()` |
| Sàn delay giữa 2 request | **300 ms** (không thể xuống thấp hơn) | `MIN_DELAY_MS` |
| Cap số trang / độ sâu | **200 trang / sâu 5** | `MAX_PAGES_CAP`, `MAX_DEPTH_CAP` |
| Phạm vi | **chỉ cùng-origin** — không leo sang domain khác | `runCrawl()` |
| Định danh | `User-Agent: SecLab-EduScraper/1.0 (educational polite scraper)` — không giả danh trình duyệt | `USER_AGENT` |
| Không state | không gửi cookie, không đăng nhập, không retry dồn dập | `fetchPage()` |

## Lệnh mẫu

```bash
# 1) Cào một site công khai, tối đa 20 trang, sâu 2, cách nhau 800ms
node src/cli.js crawl --url=https://example.com --max-pages=20 --depth=2

# 2) Thực hành trên chính lab cục bộ (cần cờ sở hữu — scraper mặc định chặn nội bộ)
node src/cli.js crawl --url=http://127.0.0.1:3000 --max-pages=6 --i-own-this-target
```

Kết quả: bảng trang + tiêu đề + số ký tự text + latency từng request in ra màn hình;
báo cáo đầy đủ ghi vào `reports/crawl-<host>-<thời-gian>.md` và `.json`.

## Trước khi cào một site thật — checklist 60 giây

1. **robots.txt** của site có chặn phần bạn cần không? (`https://site/robots.txt` — tool tự đọc, nhưng bạn nên biết trước)
2. **ToS / Điều khoản sử dụng** có điều khoản cấm thu thập tự động không? Có → đừng cào, hoặc chỉ cào phần được phép.
3. Dữ liệu cần có **dữ liệu cá nhân** không? Có → dừng lại hoặc ẩn danh hoá ngay khi lưu.
4. Mục đích là **học/nghiên cứu cá nhân** hay tái sử dụng thương mại? Thương mại → cần giấy phép.
5. Giữ `--delay-ms` cao (≥800). Site chậm là site đang sống — cứFetch như người đọc thật.

## Vì sao "test khả năng chống chịu" với site công khai KHÔNG có trong tool

Tạo tải lớn nhắm site bạn không sở hữu = tấn công từ chối dịch vụ, bất chấp mục đích.
Không chỉ Điều 287 BLHS 2015 (tù đến nhiều năm): hầu hết quốc gia đều hình sự hoá
(US: CFAA, EU: quy định quốc gia theo Directive 2013/40/EU). Nếu bạn muốn đo khả
năng chống chịu của một website thật, con đường đúng là:

1. **Bạn sở hữu nó** → chạy SecLab nhắm thẳng vào server của bạn (`--i-own-this-target`).
2. **Bạn được chủ sở hữu cho phép bằng văn bản** (pentest scope/sRules of Engagement) → giới hạn trong scope đã ký.
3. **Site của bên thứ ba có sẵn trang status/benchmark** → dùng số liệu công khai của họ, đừng tự tạo tải.

Muốn học đo đạc trên tải thật → `npm run serve:hardened` rồi `flowtest`/`loadtest`
nhắm vào 127.0.0.1 — mọi con số bạn thu được là thật, và pháp lý cũng thật sạch.
