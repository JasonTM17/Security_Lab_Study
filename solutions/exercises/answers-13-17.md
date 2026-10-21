# Answer key · Bài 13–17 — nâng cao

---

## Bài 13 · Upload / XXE / Stored XSS

| Checklist | Đáp án |
|---|---|
| `.html` chạy script vuln; 415 hardened | Upload `<script>alert(1)</script>` as `x.html` → `GET /uploads/x.html` serve `text/html` → thực thi. Hardened: whitelist ext + `application/octet-stream` + `X-Content-Type-Options: nosniff` → 415. |
| XXE đọc `secrets.txt` + cờ | `<!ENTITY x SYSTEM "file:///secrets.txt">` → nội dung bí mật; `file:///flag-xxe.txt` → `FLAG{xxe-...}` nộp CTF #7. |
| Stored XSS raw vs escaped | Vuln: post `<svg/onload=alert(1)>` → mọi visitor load trang đều chạy (kém XSS reflected vì không cần lừa click link). Hardened: `esc()` → hiển thị chữ. |
| "Cùng origin" nguy hiểm | File upload được serve từ `127.0.0.1:3000` → JS trong file chạy trong origin lab → đọc được session cookie `/api/me` của nạn nhân xem file. Nếu serve từ domain/cdn tách biệt thì tấm chắn same-origin bảo vệ. → Upload phải: whitelist ext + MIME sniff + Content-Disposition + domain riêng. |

---

## Bài 14 · Prototype Pollution & Mass Assignment

| Checklist | Đáp án |
|---|---|
| Cờ #8 + #9 | Xem `solutions/ctf/ctf-06-10.md` §CTF-8/9. |
| Vì sao key nhiễm *enumerable* | `Object.prototype.x = v` thêm own-enumerable property vào prototype → `Object.keys(Object.prototype)` thấy được (lab dùng để show `protoPolluted`). Nếu gán qua `defineProperty` non-enumerable thì vẫn nhiễm nhưng ẩn — đáng sợ hơn. |
| Dòng lỗ hổng trong `unsafeMerge` | `dst[k] = src[k]` khi `k="__proto__"` — không check key nguy hiểm; `src[k]` object → recurse vào `Object.prototype`. `safeMerge` lọc `__proto__`/`constructor`/`prototype` trước khi gán. |
| 1 CVE thật | lodash.merge CVE-2018-16487 / CVE-2019-10744 (proto pollution, CVSS 9.8); jQuery.extend CVE-2019-11358; Rails strong-params ra đời vì mass assignment GitHub 2012 (Egor Homakov push vào rails/rails repo). |

---

## Bài 15 · Blind SQLi

| Checklist | Đáp án |
|---|---|
| Trọn cờ CTF #10 | Xem writeup + solver: oracle `AND substr(flag,N,1)='X'`, ~N×10 request. |
| Script tự động + đếm request | `solve-all.mjs` §solve10: 30 vị trí × ≤61 charset. Với cờ `FLAG{blind-` + 12 hex + `}`: lý tưởng ~24 ký tự hiệu quả × ~10 thử trung bình ≈ 240 request; binary search `>'g'` cắt còn ~120. |
| Time-based blind còn tồn tại | Khi response byte-giống-hệt nhau (chỉ 200 chung), inject `SLEEP`/`sqlite sleep` không có — nhưng có thể gây độ trễ bằng LIKE trên string dài / RANDOMBLOB. Trên thật: `AND sleep(2)` (MySQL), `AND pg_sleep(2)` (PG) → oracle theo *thời gian* thay vì status. |
| Detect-rule `/track` theo IP | Rule `blind-sqli` trong `detect.js`: `r.path.includes('/track?code=') && /[ ']|%20|%27/i.test(r.path)` → `byIp` count ≥5 trong cửa sổ → alert. Đã bắt thật: `"kind":"blind-sqli","detail":"10 request oracle /track?code="`. |

---

## Bài 16 · Reset Token & DOM XSS

| Checklist | Đáp án |
|---|---|
| Chiếm `dave` không gọi /request | `md5('dave')[0:12]` = `8277e0910d75` → POST `/api/reset/confirm` `{token:'8277e0910d75',password:'owned123'}` → login `dave/owned123` → `/api/me` là dave. `node src/cli.js codec hash md5 dave` tính nhanh. |
| `sha256(username)` an toàn hơn không? | **Không** — vẫn deterministic function(username): attacker tính được mọi token. Vấn đề không phải hàm băm mà là *input khả dĩ đoán*. Token phải là `crypto.randomBytes(32)` + exp + one-time — entropy ở GIÁ TRỊ, không ở thuật toán. |
| `/dom#<svg onload=...>` trên 2 bản | vuln: hash → `innerHTML` → `<svg>` execute (browser vẫn cho onload chạy với svg/img — khác `<script>` inline bị nuốt khi innerHTML). hardened: `textContent` → hiện chữ raw. Payload đặt SAU `#` → server log/`detect` không bao giờ thấy. |
| 2 sink nguy hiểm khác | `eval()`, `document.write()`, `setTimeout('string')`, `element.srcdoc`, `location.href` gán `javascript:`, `insertAdjacentHTML`, `outerHTML`. Rule chung: DOM sink nhận string-HTML/string-code = nguy hiểm; textContent/textNode = an toàn. |

---

## Bài 17 · Detection Engineering

| Checklist | Đáp án |
|---|---|
| Rule mới + test | Mẫu rule `rate-limit-401-burst`: đếm ≥20 resp 401 cùng IP/60s → `brute-force-creds`. Test: spawn lab, bắn 25 login sai, `detect` ra alert. (Detect.js hiện có `brute-force` cho path — biến thể 401 nâng cao hơn.) |
| Vì sao behavioral > signature cho blind-SQli | Signature `/\bOR\b\s+\d+=\d+/` bị evade bằng `OR 2>1`, `OR'x'LIKE'x'`, case, comment `OR/**/1=1`. Behavioral (N request oracle cùng IP trên cùng endpoint) bắt *hành vi rút dữ liệu* — đổi payload vẫn dính. Cần cả hai: signature nhanh-rẻ, behavioral bắt evasion. |
| FPR/FNR | FPR = false positive rate — rule báo động trên traffic sạch (alert fatigue). FNR = false negative rate — tấn công thật trượt qua (nguy hiểm hơn). Trade-off: nới regex → FNR↓ FPR↑; thêm ngưỡng (≥N req/IP) → FPR↓ FPR↑ (attacker chậm hơn trượt). Tuning = đo trên log thật, không đoán. |
| Mô hình "đo" của lab | `reqLog` ring buffer 2000 entries `{t,ip,method,path,status}` → `detect` phân tích sau fact (offline SIEM thu nhỏ). Thật: fluentd/Vector → Elasticsearch → rule engine — cùng tư tưởng log→rule→alert. |
