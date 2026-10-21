// jwttool.js — Công cụ JWT phục vụ bài LAB-11: decode, forge, verify, crack.
// Hoạt động HOÀN TOÀN CỤC BỘ (crypto thuần, không mạng) — giống jwt.io offline —
// nên không cần guard ủy quyền. Bài học:
//   • JWT chỉ là base64url — ai cũng ĐỌC được payload, đừng nhét bí mật vào.
//   • alg=none: thư viện cấu hình sai sẽ nuốt token KHÔNG chữ ký.
//   • HS256 với secret yếu → crack được bằng từ điển (chữ ký = HMAC(key, data)).
import fs from 'node:fs';
import { jwtDecode, jwtSign, jwtVerify } from '../lab/jwtx.js';

export { jwtDecode, jwtSign, jwtVerify };

// Từ điển secret yếu phổ biến — đủ để dạy "vì sao khoá HMAC phải dài & ngẫu nhiên".
export const DEFAULT_WORDLIST = [
  'secret', 'secret123', 'password', '123456', '12345678', 'qwerty', 'letmein',
  'changeme', 'admin', 'root', 'toor', 'test', 'demo', 'dev', 'development',
  'jwt', 'jwtsecret', 'jwt-secret', 'token', 'auth', 'key', 'private', 'public',
  'default', 'supersecret', 'mysecret', 'hmac', 'HS256', 'secretkey', 'shhhhh',
  'iloveyou', 'monkey', 'dragon', 'master', 'seclab', 'lab', 'example', 'sample',
  'keyboard cat', 'your-256-bit-secret', 'my-secret-key',
];

/** Crack secret HS256 bằng từ điển. Trả về { secret, tried } hoặc { secret: null, tried }. */
export function crackJwt(token, wordlist = DEFAULT_WORDLIST) {
  const decoded = jwtDecode(token);
  if (!decoded || decoded.header.alg !== 'HS256') {
    return { secret: null, tried: 0, reason: 'token không phải HS256 hoặc malformed' };
  }
  for (const secret of wordlist) {
    if (jwtVerify(token, secret, { checkExp: false }).ok) return { secret, tried: wordlist.indexOf(secret) + 1 };
  }
  return { secret: null, tried: wordlist.length };
}

/** Nạp wordlist từ file (mỗi dòng một secret). */
export function loadWordlist(file) {
  const words = fs
    .readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (!words.length) throw new Error(`Wordlist rỗng: ${file}`);
  return words;
}
