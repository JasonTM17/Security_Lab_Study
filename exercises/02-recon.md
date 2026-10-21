# Bài 02 · Recon — thu thập thông tin

**Mục tiêu:** hiểu bước 1 của mọi kiểm thử hợp lệ: biết mục tiêu chạy gì trước
khi tìm lỗi.

```bash
node src/cli.js recon http://127.0.0.1:3000
```

## Quan sát

1. **IP & phạm vi** — `127.0.0.1`, phạm vi `loopback`. Mọi module chỉ hoạt động
   trong phạm vi này (hoặc dải riêng có cờ xác nhận).
2. **Fingerprint** — server này trả header nghèo nàn? Trong thực tế, header
   `X-Powered-By: Express`, `Server: nginx/1.24` chính là "tự khai" cho kẻ tấn
   công biết công nghệ → họ tìm CVE đúng phiên bản.
3. **Port scan** — recon dò các port phổ biến (80, 443, 3000, 8080…). Bạn thấy
   port nào mở ngoài 3000? Đó là bề mặt tấn công (attack surface).
4. **robots.txt** — lab khai `Disallow: /admin` — hi hữu: file "dành cho bot"
   lại là bản đồ khu vực nhạy cảm cho kẻ tấn công.

## Nghiệm thu thập bằng tay

```bash
curl -i http://127.0.0.1:3000/ | head -20        # xem nguyên bản headers
curl -s http://127.0.0.1:3000/robots.txt
curl -s http://127.0.0.1:3001/ -I                # headers của bản hardened
```

Câu hỏi phản biện: bản hardened giấu gì mà bản vuln không giấu?

## ✅ Hoàn thành khi

- [ ] Đọc được output recon, chỉ ra ≥2 thông tin "có giá trị cho kẻ tấn công"
- [ ] Giải thích được: vì sao prod nên tắt `X-Powered-By`
