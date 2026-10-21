// jwtx.js — JWT tối giản phục vụ BÀI HỌC về token (HS256 + alg=none).
// Triển khai bằng tay trên node:crypto để bạn ĐỌC được từng bước:
//   token = base64url(header) "." base64url(payload) "." base64url(HMAC-SHA256(...))
// Bản vuln của lab cố tình: ký bằng secret yếu + CHẤP NHẬN alg=none.
// Bản hardened: secret ngẫu nhiên mạnh + verify chặt (alg, exp, signature).
// ⚠ Đây là code dạy học — production hãy dùng thư viện JWT đã audit (jose…).
import crypto from 'node:crypto';

const b64url = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const b64urlDecode = (s) => {
  const clean = String(s).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(clean, 'base64');
};

const signInput = (header, payload) => `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
const hmac = (secret, data) => crypto.createHmac('sha256', String(secret)).update(data).digest();

/** Giải mã JWT thành { header, payload, signature } — KHÔNG kiểm tra chữ ký. */
export function jwtDecode(token) {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(b64urlDecode(parts[0]).toString('utf8')),
      payload: JSON.parse(b64urlDecode(parts[1]).toString('utf8')),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

/**
 * Ký JWT. alg='HS256' → HS256(secret); alg='none' → phần chữ ký RỖNG
 * (đúng chuẩn token alg=none mà nhiều thư viện cấu hình sai vẫn nuốt).
 */
export function jwtSign(payload, secret, { alg = 'HS256', header: extraHeader = {} } = {}) {
  const header = { alg, typ: 'JWT', ...extraHeader };
  const input = signInput(header, payload);
  const sig = alg === 'none' ? '' : b64url(hmac(secret, input));
  return `${input}.${sig}`;
}

/**
 * Xác minh JWT.
 * @param {string} token
 * @param {string} secret  khoá HMAC
 * @param {{allowNone?: boolean, checkExp?: boolean}} opts
 *        allowNone=true là CHỦ ĐÍCH DỄ TỔN THƯƠNG (bản vuln của lab).
 * @returns {{ok:boolean, payload?:object, error?:string}}
 */
export function jwtVerify(token, secret, { allowNone = false, checkExp = true } = {}) {
  const decoded = jwtDecode(token);
  if (!decoded) return { ok: false, error: 'malformed' };
  const { header, payload } = decoded;
  const parts = String(token).split('.');
  const input = `${parts[0]}.${parts[1]}`;

  if (header.alg === 'none') {
    if (!allowNone) return { ok: false, error: 'alg_none_rejected' };
  } else if (header.alg === 'HS256') {
    const expected = hmac(secret, input);
    const got = b64urlDecode(parts[2] || '');
    if (expected.length !== got.length || !crypto.timingSafeEqual(expected, got)) {
      return { ok: false, error: 'bad_signature' };
    }
  } else {
    return { ok: false, error: 'unsupported_alg' };
  }

  if (checkExp && typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) {
    return { ok: false, error: 'expired' };
  }
  return { ok: true, payload };
}
