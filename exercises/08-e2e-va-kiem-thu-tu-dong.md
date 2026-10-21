# Bài 08 — E2E và kiểm thử tự động: đọc PASS/FAIL như một kỹ sư

> Mục tiêu: chạy thành thạo 2 tầng kiểm thử tự động của SecLab — `npm test`
> (unit/integration) và `npm run e2e` (54 check HTTP tự khởi động server) —
> và hiểu kỹ thuật **vuln/hardened đối chứng**: cùng một tính năng được khẳng
> định CẢ HAI phía (vuln phải còn lỗi, hardened phải đã vá). Ma trận check đầy
> đủ nằm ở [docs/07-e2e-checklist.md](../docs/07-e2e-checklist.md).

## Phần A — `npm test`: tầng unit/integration

### Chuẩn bị

Không cần mở server — test tự dựng CSDL/lab trong bộ nhớ và tự đóng.

### Thực hành

```bash
npm test
```

### Việc cần làm

1. Đọc 3 dòng tổng kết ở cuối (dạng TAP, tiền tố `ℹ`):

   ```
   ℹ tests 115
   ℹ pass 115
   ℹ fail 0
   ```

   Kỳ vọng: **fail 0**. Con số `tests` có thể tăng khi project thêm test mới
   (tại thời điểm cập nhật tài liệu là 115) — điều bắt buộc là `fail 0`.
2. Chạy đúng MỘT file để xem runner cô lập thế nào:

   ```bash
   node --test tests/guard.test.js
   ```

   Đây là file chứa test quan trọng nhất: "TỪ CHỐI mục tiêu IP public — kể cả
   khi có `--i-own-this-target`". Lớp chặn pháp lý của cả công cụ được khoá
   bằng test, không phải bằng lời hứa.
3. Thử "phá" một lần để biết FAIL trông ra sao: sửa tạm 1 assertion trong
   `tests/ratelimiter.test.js` (ví dụ đổi một `assert.equal` thành giá trị sai),
   chạy lại → thấy `✖` + `ℹ fail 1`, rồi **hoàn tác** (`git checkout
   tests/ratelimiter.test.js`) và chạy lại cho xanh. Bạn vừa chứng minh bộ test
   thật sự kiểm tra điều gì đó, chứ không phải always-pass.

## Phần B — `npm run e2e`: tầng đối chứng vuln/hardened

### Chuẩn bị

Cũng KHÔNG cần mở `npm run serve` — e2e tự khởi động hub + lab vuln + lab
hardened trên các port tạm, chạy xong tự đóng. Đây là điểm khác lớn nhất so với
các lệnh CLI ở các bài trước.

### Thực hành

```bash
npm run e2e
```

### Việc cần làm

1. Đọc dòng tổng kết:

   ```
   ═══ E2E TỔNG KẾT: 54/54 PASS, 0 FAIL ═══
   ```

   Mỗi check nằm trong 7 nhóm (ký hiệu đầu tên check): **A** hub (8) ·
   **B** hardened — luồng hợp lệ (17) · **C** vuln — lỗ hổng phải TỒN TẠI (10) ·
   **D** rate limit (2) · **F** CTF + log blue-team (8) ·
   **G** lỗ hổng mở rộng LAB-09..15 đối chứng (8) · **E** dọn dẹp (1).
   Đếm lại cho khớp 54.
2. Câu hỏi mấu chốt: vì sao **C1. SQLi boolean-based → lộ TOÀN BỘ người dùng**
   lại là check PASS? Vì e2e khẳng định lab vuln **còn** lộ dữ liệu — nếu ai đó
   "vá nhầm" bản vuln, C1 sẽ FAIL và nhắc người ta khôi phục giá trị giảng dạy.
   Test bảo vệ cả hai phía của cặp vuln/hardened.
3. Chỉ ra ít nhất 1 cặp đối chứng bằng tên check: `B3` (SQLi trong search →
   **0 dòng**, parameterized) đối lại với `C1` (cùng kiểu payload trên vuln →
   **lộ ≥4 email**). Cùng hành vi, hai kỳ vọng ngược nhau — đó là bằng chứng
   "đã vá" có thể kiểm chứng máy, thay vì lời nói.
4. Xem exit code — CI (`.github/workflows/ci.yml`) dựa vào nó:

   ```bash
   npm run e2e ; echo $?      # Git Bash — 0 khi 54/54 PASS
   ```

   `tests/e2e.mjs` gọi `process.exit(1)` nếu có bất kỳ check FAIL nào, nên CI
   đỏ đúng khi đối chứng bị phá.
5. (Mở rộng) Đọc bảng tầng 2 trong docs/07 — browser E2E qua trình duyệt thật
   (30 kịch bản, cookie jar thật, chụp màn hình) — để thấy tầng HTTP check được
   cái gì và trình duyệt thật bổ sung gì.

✅ **Hoàn thành khi:** cả hai lệnh xanh (`npm test` fail 0 · `npm run e2e`
54/54 PASS), giải thích được vì sao nhóm C "lỗ hổng phải tồn tại" cũng là PASS,
và nêu được 1 cặp check B/C đối chứng bằng đúng tên.

## Câu hỏi tự vấn (trả lời được là đã hiểu)

1. Vì sao `npm run e2e` không cần bạn mở `npm run serve` trước, trong khi
   `node src/cli.js recon` thì cần?
2. Nếu `npm test` báo `fail 5` ngay sau khi bạn `git pull` — bạn kết luận gì
   trước tiên: tool hỏng, lab hỏng, hay có thay đổi code chưa chạy kèm test?
3. Con số 115 test và 54 check E2E đo hai tầng khác nhau ở điểm nào (đơn vị đo,
   thứ cần dựng, thời gian chạy)?
4. Bạn vừa thêm 1 route mới vào lab hardened. Phải thêm check nhóm nào vào
   `tests/e2e.mjs` để route đó được bảo vệ bởi đối chứng vuln/hardened?
5. Vì sao test chặn mục tiêu public phải chạy được **mà không cần mạng**?
   (gợi ý: guard phải từ chối TRƯỚC khi có byte nào được gửi đi.)
