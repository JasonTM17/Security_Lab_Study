# 01 · Pháp lý và đạo đức — ĐỌC TRƯỚC KHI LÀM GÌ KHÁC

## 1. Vì sao SecLab không nhắm được vào web "trên mạng"

Mọi lệnh chủ động của SecLab (recon / scan / loadtest / slowloris) đi qua một lớp
chặn cứng ở `src/guard.js`:

| Mục tiêu | Kết quả |
|---|---|
| `127.0.0.1`, `::1`, `localhost` | ✅ Cho phép — đây là lab của bạn |
| Dải riêng `10.x`, `172.16–31.x`, `192.168.x` | ⚠️ Chỉ cho phép khi có cờ `--i-own-this-target` |
| Mọi địa chỉ public trên Internet | ❌ **Từ chối cứng, không có lối tắt** |

Đây không phải giới hạn kỹ thuật tạm thời — đó là thiết kế có chủ đích, đúng chuẩn
đạo đức nghề (ethics) của ngành an toàn thông tin.

## 2. Cơ sở pháp lý (Việt Nam)

- **Điều 287 Bộ luật Hình sự 2015 (sửa đổi 2017)** — *Tội gây cản trở hoặc làm tê
  liệt hoạt động của mạng máy tính, mạng viễn thông, phương tiện điện tử*:
  hành vi DoS/DDoS thuộc tội này, khung hình phạt cao nhất lên tới nhiều năm tù.
- **Điều 288 BLHS** — đưa hoặc sử dụng trái phép thông tin trên mạng.
- **Luật An ninh mạng 2018** — cấm hành vi xâm nhập, cản trở, làm tê liệt hệ thống.
- **Bộ luật Dân sự / Nghị định 14/2022** — bồi thường thiệt hại do xâm nhập, làm
  hỏng dữ liệu.

Câu nói phổ biến trong nghề: *" pentest không có giấy phép = phạm tội, dù ý tưởng
của bạn đúng, payload của bạn đẹp, và nạn nhân 'chắc chắn không để ý'."*

## 3. Khi nào kiểm thử là HỢP PHÁP

1. **Hệ thống của chính bạn** (lab local, VPS bạn thuê, tên miền bạn sở hữu).
2. **Có sự cho phép bằng văn bản** của chủ hệ thống (scope rõ ràng: IP nào, thời
   gian nào, kỹ thuật nào được phép) — gọi là *Rules of Engagement*.
3. **Sàn bug bounty** với chính sách công khai (họ ghi rõ được test gì, không
   được test gì).

Ngoài ba trường hợp trên: không làm. Không có ngoại lệ "nhỏ thôi", "1 packet thôi".

## 4. Học đúng bài bản — lộ trình chuẩn ngành

Lộ trình mà SecLab hỗ trợ (và lộ trình mà các chứng chỉ CEH/OSCP dùng):

1. **Recon** — thu thập thông tin mục tiêu CỦA MÌNH (headers, port, công nghệ).
2. **Scanning** — tìm lỗ hổng bằng scanner (ở đây: `scan`).
3. **Exploitation (lab)** — khai thác thủ công trên lab để hiểu bản chất.
4. **Denial of Service (lab)** — hiểu vì sao server sập và **cách phòng thủ**.
5. **Reporting** — viết báo cáo: phát hiện → bằng chứng → mức độ → cách vá.

Bước 4 là nơi hầu hết người mới hiểu sai: nghề bảo mật không phải "đánh sập
người khác", mà là **đo và vá trước khi kẻ xấu làm**. Bởi vậy SecLab đi kèm
module phòng thủ (rate limiter, security headers, limit_conn) — bạn học cả
hai phía trong một vòng lặp: tấn công lab → quan sát → vá → chứng minh đã vá xong.

## 5. Tuyên bố miễn trừ

SecLab phục vụ mục đích giáo dục. Mọi dữ liệu trong lab là giả lập. Tác giả
không chịu trách nhiệm nếu bạn dùng công cụ này vào mục đích bất hợp pháp —
và thiết kế của công cụ đã chủ động ngăn điều đó.
