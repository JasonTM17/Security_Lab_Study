# 10 · Detection Engineering — từ access log tới alert có chất lượng

> Đối tượng: học viên đã qua các bài tấn công (exercises 01–16), giờ học phe
> phòng thủ — làm sao *nhìn thấy* kẻ tấn công qua dữ liệu mình có.

Detection engineering là nghề biến hành vi tấn công thành rule máy bắt được,
đồng thời giữ false-positive đủ thấp để alert có nghĩa. SecLab mô phỏng quy
trình này ở quy mô nhỏ nhưng đúng cấu trúc của SIEM thật.

## Pipeline phát hiện trong lab

```
HTTP request → middleware log (app.js) → reqLog[500]
                                     → GET /_lab/log (JSON)
                                     → detect module (analyzeLog)
                                     → findings {type, label, severity, count, samples, defense}
```

Mỗi entry log: `{t, ip, method, path, ua}` — tương đương một dòng access
log + user-agent. Đây là *telemetry tối thiểu* mà mọi web app nên có.

## Bộ rule hiện có (`src/modules/detect.js`)

| Type | Bắt gì | Cách match | Severity |
|---|---|---|---|
| `sqli` | SQL injection | `'`, `%27`, `union`, `select`, `or 1=1`, `sleep` trong path | high |
| `xss` | Reflected/stored XSS | `<script`, `onerror=`, `<svg`, `javascript:` | high |
| `traversal` | Path traversal | `../`, `..%2f`, `%2e%2e` | high |
| `cmdinj` | Command injection | `;`, `&`, `|`, `` ` ``, `$(` trong param host | critical |
| `xxe` | XML external entity | `ENTITY`, `SYSTEM`, `file://` | high |
| `open-redirect` | Redirect tới domain ngoài | `/redirect?to=http` | medium |
| `upload` | Upload file thực thi | `/upload` + `.html/.php/.jsp` | medium |
| `jwt-probe` | Dò JWT | `/api/profile?token=` nhiều lần / `alg":"none` | medium |
| `admin-probe` | Dò trang admin | `/admin` khi chưa đăng nhập | low |
| `sensitive` | Dò file nhạy cảm | `.env`, `.git`, `wp-config`, `backup` | medium |
| `scanner` | User-agent tool | `sqlmap`, `nikto`, `nmap`, `burp`, `acunetix` | info |
| `bruteforce` | Brute-force login | ≥10 request `/login` cùng IP | high |
| `proto-pollution` | Prototype pollution | `__proto__`, `constructor[`, `prototype[` trong path/body | high |
| `mass-assign` | Mass assignment | `/api/register` kèm `role=`/`isadmin` | medium |
| `blind-sqli` | Blind SQLi oracle | `/track` + (`'` hoặc `%27`) + `and/or/select/substr/glob` — **đếm theo IP** | high |
| `reset-abuse` | Lạm dụng reset password | ≥3 request `/api/reset/request` cùng IP | medium |

## Hai lớp detection

**1. Signature-based** (rule đơn lẻ): regex trên `path`/`ua`. Nhanh, dễ viết,
nhưng dễ evade — `OR 1=1` → `oR 1=1` → `OR/**/1=1` → `||1=1`. Bộ rule lab
có normalize cơ bản (lowercase, decode `%27`), nhưng người học nên tự evade
để hiểu giới hạn.

**2. Behavioral** (aggregate theo actor): `bruteforce`, `blind-sqli`,
`reset-abuse` không bắt *một* request mà đếm *N request cùng IP*. Đây là
tư duy của UEBA/rate-based detection — kẻ tấn công payload nào cũng né
được, nhưng *hành vi lặp* thì không: blind SQLi bắt buộc phải hỏi oracle
hàng trăm lần.

> Bài học lớn: **kẻ tấn công có thể thay đổi payload, không thể thay đổi
> mục tiêu** — muốn rút flag từng ký tự thì phải gửi nhiều request. Đếm,
> không đọc.

## Vòng đời một detection rule (làm trong lab)

1. **Giả định**: "kẻ tấn công sẽ brute-force reset token" → cần nhiều
   request `/api/reset/request`.
2. **Viết rule** → chạy `analyzeLog()` trên log có sẵn.
3. **Đo FPR**: traffic bình thường có bị gắn cờ không? (Người dùng quên
   pass thật cũng request vài lần → ngưỡng 3, không phải 1.)
4. **Đo FNR**: kẻ tấn công né bằng cách nào? (Nhiều IP → cần correlate
   theo session/thời gian; lab chỉ có 1 IP nên tập trung vào tần suất.)
5. **Siết/nới ngưỡng** → repeat.
6. **Alert → runbook**: finding của `detect` luôn kèm `defense` — đó là
   runbook tối thiểu: phát hiện X → làm Y.

## Giới hạn của telemetry lab

- DOM XSS (LAB-20) **không xuất hiện** trong log — payload trong fragment
  không lên server. Trên hệ thống thật cần CSP `report-uri` hoặc client-side
  beacon. Hãy dùng bài này để hiểu "không thấy log ≠ không có tấn công".
- Log chỉ có `path` — POST body không ghi (tránh lưu password!). Rule cho
  `__proto__` trong JSON body vì vậy match trên path của request tương ứng;
  hệ thống thật sẽ cần WAF inspect body có chọn lọc.

## Bài tập gợi ý

Làm [exercises/17-detection-engineering.md](../exercises/17-detection-engineering.md):
tạo traffic, viết rule riêng, đo FPR/FNR, evade chính rule của mình.
