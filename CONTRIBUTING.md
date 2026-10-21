# Đóng góp cho SecLab

Cảm ơn bạn muốn đóng góp! SecLab là **dự án giáo dục** — mọi PR phải giữ được
hai nguyên tắc không thương lượng:

1. **Mô hình an toàn**: mọi module chủ động phải đi qua `assertAuthorizedTarget()`
   trong `src/guard.js`; mục tiêu public bị chặn cứng; lab chỉ bind `127.0.0.1`.
2. **Mọi lỗ hổng mới phải có cặp vuln/hardened** — giá trị dạy học nằm ở đối chứng
   "lỗi còn → đã vá", và phải có test cho CẢ HAI phía.

## Chạy thử

```bash
npm test          # unit + integration (node --test)
npm run e2e       # 54 check HTTP tự dựng 3 server — bắt buộc xanh trước khi PR
node src/cli.js doctor
```

## Quy ước code

- Node ≥ 22.5, **không thêm dependency ngoài** — chỉ thư viện chuẩn.
- ESM (`"type": "module"`), tiếng Việt cho docs/comment dạy học.
- Mỗi lỗ hổng đánh số `LAB-xx` và ghi rõ trong comment đầu `src/lab/app.js`.
- Thêm endpoint → cập nhật: `vulnscan.js` (probe), `detect.js` (pattern),
  `tests/e2e.mjs` (check đối chứng), `docs/04-cheat-sheet.md`, `docs/08`, exercises.

## Commit

Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`…), mỗi commit một việc.
PR cần: mô tả thay đổi + bằng chứng test (`npm test` + `npm run e2e` PASS).
