# 05 · Security review — xác nhận 3 advisory findings của Mimosa (L3)

> Tài liệu này là **bản xác nhận của con người** cho 3 cảnh báo tĩnh mà Mimosa
> gắn cờ `advisory` khi commit. Bản thân findings.json của Mimosa ghi rõ:
> *"静态 advisory 需要人工确认真实数据流和可利用性"* (cảnh báo tĩnh cần người
> xác nhận dòng dữ liệu thật và khả năng khai thác). Đây chính là bản xác nhận đó.

- **Scan seal:** `sha256:1d7f389fbfd0e20a7cead19f62656fa7db93e4d110acf993137d38aeb3da8896`
- **Scan:** `scan-2026-10-04T16-02-57.445Z-bdf8573749f6` (depth: deep)
- **Ngày xác nhận:** 2026-10-04
- **Kết luận:** 3/3 finding là hành vi **thiết kế có chủ đích** của một công cụ
  kiểm thử bảo mật, đã có mitigation thật + test tự động. **Đã xem xét và chấp
  nhận** cho phạm vi sử dụng: lab cục bộ của người sở hữu máy.

---

## Finding 1 — "runRecon 经 1 跳到达 ssrf" (src/cli.js:182)

| | |
|---|---|
| Analyzer nói gì | CLI args → `runRecon()` → `fetchPage()` (sink: ssrf) |
| Thực tế dòng dữ liệu | Mục tiêu là **tham số đầu vào có chủ đích** của lệnh `recon` — công cụ pentest làm việc bằng cách gửi request tới mục tiêu. Không có "SSRF" nếu không có chức năng này |
| Mitigation | `assertAuthorizedTarget()` chạy **2 lớp** (tại entry trong cli.js + trong module) trước byte đầu tiên: mục tiêu public → từ chối kèm căn cứ pháp lý; dải riêng → bắt buộc `--i-own-this-target` |
| Bằng chứng tự động | `tests/guard.test.js`: *"TỪ CHỐI mục tiêu IP public — kể cả khi có --i-own-this-target"* — pass |
| Quyết định | ✅ Chấp nhận — đây là chức năng lõi, đã kiểm soát |

## Finding 2 — "writeReport 是 path-traversal 入口" (src/cli.js:203)

| | |
|---|---|
| Analyzer nói gì | CLI args → `writeReport()` → fs.write (sink: path-traversal) |
| Đã xử lý kỹ thuật | Sau cảnh báo, **đã loại bỏ hoàn toàn tham số đường dẫn**: `--out` bị xoá; thư mục ghi là **hằng số** `PROJECT_ROOT/reports` tính từ `import.meta.url` (xem `src/modules/report.js`). Không có input người dùng nào chạm vào fs.write |
| Taint còn lại | Analyzer truy vết "nội dung" báo cáo (chuỗi `target` nằm trong scan object) — đó là dữ liệu được **viết vào file**, không phải **đường dẫn** file |
| Bằng chứng tự động | `node --test` 22/22 pass sau thay đổi; scan chạy thật ghi đúng vào `reports/` |
| Quyết định | ✅ Chấp nhận — đã khắc phục; taint dư là artifact của phân tích xuyên-object |

## Finding 3 — "runLoadTest 是 ssrf 入口" (src/cli.js:212)

| | |
|---|---|
| Analyzer nói gì | CLI args → `runLoadTest()` → `fetch()` (sink: ssrf) |
| Thực tế | `loadtest` là bộ tạo tải cho lab — cùng bản chất Finding 1. Module còn đo đếm qua `/_lab/metrics` của lab |
| Mitigation | Giống Finding 1: guard 2 lớp trước khi tạo bất kỳ request nào |
| Bằng chứng tự động | `tests/guard.test.js` (chặn public) + `tests/app.test.js` (rate limiter của hardened trả 429 — hành vi phòng thủ hoạt động) |
| Quyết định | ✅ Chấp nhận — chức năng lõi, đã kiểm soát |

---

## Bối cảnh: vì sao 3 cảnh báo này là "bản chất ngành", không phải lỗi

Mọi công cụ kiểm thử bảo mật hợp lệ trên thế giới (OWASP ZAP, Nikto, Burp, nmap
NSE script…) đều có cấu trúc dữ liệu: *người dùng chỉ định mục tiêu → công cụ
gửi request đến mục tiêu*. Quét tĩnh generic sẽ đánh dấu cấu trúc này là SSRF
trong **mọi** công cụ dạng này. Điều phân biệt công cụ hợp pháp với vũ khí là
**lớp ủy quyền mục tiêu** — và SecLab có lớp đó cứng ở 2 tầng, có test, có tài
liệu pháp lý (`docs/01`).

## Điều kiện đi kèm việc chấp nhận (không rời điều kiện)

1. Chỉ dùng với hệ thống bạn sở hữu hoặc được phép bằng văn bản (docs/01 §3).
2. Không xoá/qua mặt `src/guard.js` trong bất kỳ fork/sửa đổi nào.
3. Không commit thay đổi nào làm yếu guard — nếu có nhu cầu, mở issue thảo luận trước.
