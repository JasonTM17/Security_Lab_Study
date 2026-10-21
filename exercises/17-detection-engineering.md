# Bài 17 · Detection Engineering — biến tấn công thành rule phát hiện

**Mục tiêu:** đổi vai sang phe xanh. Mọi request vào lab được ghi vào
`/_lab/log` (tối đa 500 entry, có IP + path + user-agent). Lệnh `detect`
đọc log đó và chạy bộ rule sẵn có. Bài này: bạn tạo "traffic tấn công",
quan sát `detect` bắt gì, rồi tự viết rule cho nhóm LAB-16..20.

Đọc song song: [docs/10-detection-engineering.md](../docs/10-detection-engineering.md).

## 1. Tạo dấu vết tấn công

```bash
npm run serve   # lab vuln :3000

# Giả lập một đợt khai thác đa dạng (mỗi cái vài phát):
curl -s "http://127.0.0.1:3000/search?q=' OR 1=1 --" > /dev/null
curl -s "http://127.0.0.1:3000/search?q=<script>alert(1)</script>" > /dev/null
for i in 1 2 3 4 5; do
  curl -s "http://127.0.0.1:3000/track?code=AB-100' AND substr(flag,$i,1)='x' --" > /dev/null
done
curl -s "http://127.0.0.1:3000/api/reset/request?user=alice" > /dev/null
curl -s "http://127.0.0.1:3000/api/reset/request?user=bob" > /dev/null
```

## 2. Xem blue-team nhìn thấy gì

```bash
node src/cli.js detect http://127.0.0.1:3000
```

Quan sát: SQLi và XSS bị bắt ngay; **5 request `/track` có `substr(...)`** bị
gộp thành finding `blind-sqli` (đếm theo IP — đây là "behavioral detection",
không phải match đơn lẻ); hai request reset cùng IP → `reset-abuse`.

## 3. Viết rule riêng

Mở `src/modules/detect.js` — mỗi rule là `{type, label, severity, match,
defense}`. Thử viết rule mới cho một pattern chưa có, ví dụ:

```js
{
  type: 'enumeration',
  label: 'Dò user hệ thống qua reset endpoint',
  severity: 'medium',
  match: (e) => e.path.startsWith('/api/reset/request'),
  defense: 'Rate limit + trả response giống nhau dù user tồn tại hay không.',
}
```

Quan trọng: `match` nhận **entry log** `{t, ip, method, path, ua}` — rule tốt
không chỉ regex path mà còn tổng hợp theo `ip` và tần suất.

## 4. Đánh giá chất lượng rule

- **False positive**: gõ `/track?code=AB-100` bình thường — rule có bắt
  nhầm không? (Không — phải có `'` hoặc `%27` + từ khoá SQL.)
- **False negative**: đổi payload `substr` → `substr ( dấu cách )` —
  regex của bạn còn bắt không? Evasion cơ bản: `AND` → `&&`-tương đương,
  comment `/**/`, case `AnD`.
- Đoạn này chính là vòng đời detection engineering thật: *giả định → rule →
  đo FPR/FNR → siết/nới → alert → runbook*.

## Tiêu chí hoàn thành

- [ ] `detect` bắt được đợt tấn công bạn tạo (ít nhất 3 type khác nhau).
- [ ] Tự viết được 1 rule mới chạy trong `analyzeLog()` (unit test mini).
- [ ] Nêu được 1 cách evade rule regex đơn giản và cách làm rule chặt hơn.
- [ ] Giải thích vì sao DOM XSS (LAB-20) *không thể* phát hiện qua access log
      — cần signal nào thay thế? (CSP report-uri, client-side telemetry).
