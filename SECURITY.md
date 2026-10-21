# Chính sách bảo mật

## Phạm vi

SecLab là **công cụ giáo dục chạy cục bộ**. Lab cố ý có lỗ hổng — đó là tính
năng, không phải bug. Lỗ hổng chỉ được coi là vấn đề cần báo cáo khi nó cho
phép ảnh hưởng **ra ngoài** mô hình lab, ví dụ:

- Lỗi trong `src/guard.js` khiến module chủ động đánh được mục tiêu public.
- Lab lắng nghe trên địa chỉ khác `127.0.0.1`, hoặc XXE/traversal chạm đĩa thật
  thay vì filesystem ảo.
- Lệnh CLI lộ/ghi file ngoài `reports/` mà không qua guard.
- Command injection ở `/tools/ping` thoát khỏi scope "chỉ người dùng trên máy
  chủ lab" (ví dụ lab bị expose ra mạng do lỗi binding).

Lỗ hổng **cố tình** của bản vuln (SQLi, XSS…) KHÔNG phải báo cáo — nó là bài học.

## Báo cáo

Mở **GitHub Issue** hoặc liên hệ tác giả qua hồ sơ GitHub. Mô tả: endpoint/lệnh,
kỳ vọng an toàn bị phá, cách tái hiện. Không đăng PoC công khai nếu nó có thể
bị lạm dụng trước khi vá.

## Bản hỗ trợ

Chỉ nhánh `main` mới nhất. Không có bản phát hành LTS.
