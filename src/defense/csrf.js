// csrf.js — Token chống CSRF gắn với session (kỹ thuật "synchronizer token").
// Ý tưởng: server phát hành token = HMAC(secret, sessionId) nhúng vào form;
// khi nhận POST, tính lại và so sánh THỜI GIAN HẰNG. Trang độc hại không đọc
// được token (same-origin policy) nên không forge được request hợp lệ.
import crypto from 'node:crypto';

/** Tạo secret CSRF riêng cho một instance lab (mỗi lần khởi động một khoá). */
export function createCsrfSecret() {
  return crypto.randomBytes(16).toString('hex');
}

/** Phát hành token cho một session id. */
export function issueCsrfToken(secret, sessionId) {
  return crypto.createHmac('sha256', String(secret)).update(`csrf:${sessionId}`).digest('hex');
}

/** Kiểm tra token — timingSafeEqual để không rò rỉ qua timing. */
export function verifyCsrfToken(secret, sessionId, token) {
  if (!token) return false;
  const expected = issueCsrfToken(secret, sessionId);
  const a = Buffer.from(String(token));
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
