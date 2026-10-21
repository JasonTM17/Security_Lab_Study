// Security headers — lớp phòng thủ phản ánh cấu hình web an toàn.
// Mỗi header được giải thích để bạn hiểu "vì sao phải có nó".

export const HEADERS_DOC = [
  {
    name: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:",
    why: 'Chặn XSS: trình duyệt chỉ thực thi script từ nguồn đáng tin cậy, inline <script> bị cấm.',
  },
  {
    name: 'X-Content-Type-Options',
    value: 'nosniff',
    why: 'Không cho trình duyệt "đoán" kiểu nội dung — chống MIME-sniffing attack.',
  },
  {
    name: 'X-Frame-Options',
    value: 'DENY',
    why: 'Chặn nhúng trang trong iframe — chống clickjacking.',
  },
  {
    name: 'Referrer-Policy',
    value: 'no-referrer',
    why: 'Không rò rỉ URL (có thể chứa token) sang trang bên ngoài.',
  },
  {
    name: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
    why: 'Ép trình duyệt dùng HTTPS trong 1 năm — chống downgrade attack & SSL-strip.',
    httpsOnly: true,
  },
  {
    name: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=()',
    why: 'Không cho trang dùng camera/mic/vị trí — giảm bề mặt tấn công.',
  },
];

/** Middleware gắn bộ header bảo mật. Dùng bởi server hardened. */
export function securityHeaders(req, res, next) {
  for (const h of HEADERS_DOC) {
    if (h.httpsOnly && req.socket.encrypted !== true && req.headers['x-forwarded-proto'] !== 'https') {
      continue; // HSTS chỉ có ý nghĩa khi chạy HTTPS thật
    }
    res.setHeader(h.name, h.value);
  }
  next();
}
