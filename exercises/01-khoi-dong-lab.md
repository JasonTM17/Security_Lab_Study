# Bài 01 · Khởi động lab

**Mục tiêu:** chạy được mục tiêu thực hành và kiểm chứng công cụ hoạt động.

## 1. Kiểm tra môi trường

```bash
node --version        # cần ≥ 22.5 (lab dùng node:sqlite có sẵn)
npm run doctor
```

Kỳ vọng: Node ≥22 OK, `node:sqlite khả dụng`, port 3000 rảnh, có CI workflow.

## 2. Chạy bộ test

```bash
npm test
```

Kỳ vọng: **71 pass, 0 fail** — bao gồm test chặn mục tiêu public (quan trọng nhất).

## 3. Khởi động lab (bản CỐ Ý DỄ TỔN THƯƠNG)

```bash
npm run serve
```

Mở http://127.0.0.1:3000 bằng trình duyệt. Bạn thấy badge **LAB VULN** màu đỏ.
Danh sách tài khoản lab: `alice/alice123` (admin), `bob/bob45678`,
`carol/carol90ab`, `dave/dave-cd34`.

## 4. Chạy bản ĐÃ VÁ ở port khác (để so sánh ở các bài sau)

Terminal thứ hai:

```bash
npm run serve:hardened -- --port 3001
```

Badge **LAB HARDENED** màu xanh ở http://127.0.0.1:3001.

## 5. Thử lớp chặn an toàn (để hiểu công cụ không phải đồ chơi tấn công)

```bash
node src/cli.js recon http://8.8.8.8
```

Kỳ vọng: **TỪ CHỐI** kèm giải thích pháp lý (Điều 287 BLHS 2015). Đây là hành vi
đúng: công cụ dạy bảo mật phải dạy cả giới hạn của nó.

## ✅ Hoàn thành khi

- [ ] `npm test` xanh 71/71
- [ ] Hai lab chạy song song: 3000 (vuln) và 3001 (hardened)
- [ ] Hiểu vì sao `recon http://8.8.8.8` bị từ chối
