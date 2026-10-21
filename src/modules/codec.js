// codec.js — Bộ công cụ mã hóa/giải mã nền tảng cho học an toàn thông tin.
//
// Dạy "vốn từ vựng" mà mọi dân ATTT dùng hằng ngày: base64 (mã hoá credential
// trong HTTP Basic Auth / JWT), hex (dump dữ liệu gốc), URL-encoding (payload
// trong query string), ROT13 (mã hoá cổ điển để hiểu tinh thần substitution),
// và băm (hash) — cùng bài học vì sao MD5/SHA-1 đã chết.
// Toàn bộ là hàm thuần, không mạng — không dính guard ủy quyền.
import crypto from 'node:crypto';

export function b64Encode(text) {
  return Buffer.from(String(text), 'utf8').toString('base64');
}

export function b64Decode(text) {
  return Buffer.from(String(text), 'base64').toString('utf8');
}

export function hexEncode(text) {
  return Buffer.from(String(text), 'utf8').toString('hex');
}

export function hexDecode(text) {
  const clean = String(text).replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Chuỗi hex không hợp lệ (cần số hex chẵn ký tự)');
  }
  return Buffer.from(clean, 'hex').toString('utf8');
}

export function urlEncode(text) {
  return encodeURIComponent(String(text));
}

export function urlDecode(text) {
  return decodeURIComponent(String(text));
}

const ROT13_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ROT13_LOWER = 'abcdefghijklmnopqrstuvwxyz';
// Xoay RIÊNG từng khối hoa/thường (Z→M, z→m) — xoay cả chuỗi 52 ký tự sẽ
// trượt chữ hoa sang chữ thường, sai bản chất của ROT13.
const ROT13_SHIFTED = ROT13_UPPER.slice(13) + ROT13_UPPER.slice(0, 13) + ROT13_LOWER.slice(13) + ROT13_LOWER.slice(0, 13);

/** ROT13 — thay mỗi chữ cái bằng chữ cách đúng 13 vị trí (tự nghịch đảo). */
export function rot13(text) {
  return String(text).replace(/[a-z]/gi, (ch) => {
    const i = (ROT13_UPPER + ROT13_LOWER).indexOf(ch);
    return i === -1 ? ch : ROT13_SHIFTED[i] ?? ch;
  });
}

/** Băm văn bản với thuật toán cho trước (sha256 | sha1 | md5) — dùng node:crypto. */
export function hashText(algorithm, text) {
  const algo = String(algorithm).toLowerCase().replace('-', '');
  if (!['sha256', 'sha1', 'md5'].includes(algo)) {
    throw new Error(`Thuật toán không hỗ trợ: ${algorithm} (chọn sha256 | sha1 | md5)`);
  }
  return crypto.createHash(algo).update(String(text), 'utf8').digest('hex');
}

/** Giải thích dạy học cho một cặp mã hoá. */
export function explain(op) {
  const notes = {
    b64enc: 'Base64: biểu diễn nhị phân bằng 64 ký tự an toàn cho văn bản. KHÔNG phải mã hoá bảo mật — giải được ngay. Gặp trong HTTP Basic Auth, phần header của JWT, data-URI.',
    b64dec: 'Giải Base64 — kỹ năng "đọc trộm" cơ bản nhất: chuỗi kết thúc bằng = và chỉ chứa A–Z a–z 0–9 + / thường là base64.',
    hexenc: 'Hex: mỗi byte thành 2 ký tự 0-9a-f — cách "nhìn thô" dữ liệu gốc, dùng khi phân tích payload, file, hash.',
    hexdec: 'Giải hex về văn bản đọc được — ví dụ khi bắt gói Wireshark thấy payload dạng hex.',
    urlenc: 'URL-encoding: ký tự đặc biệt thành %XX để đặt an toàn vào query string — payload SQLi/XSS hầu như luôn phải qua bước này.',
    urldec: 'Giải URL-encoding — đọc lại payload gốc từ URL đã mã hoá (như trong log server).',
    rot13: 'ROT13: mã hoá thay thế cổ điển, dịch 13 vị trí bảng chữ. Tự nghịch đảo (rot13 hai lần = gốc). Học để hiểu tinh thần cipher thay thế và vì sao nó yếu.',
    hash: 'Hash: ánh xạ một chiều thành chuỗi cố định. Cùng input → cùng output; không đảo ngược được. Nhưng MD5/SHA-1 đã bị tìm ra va chạm (collision) nên CHẾT về bảo mật — chỉ còn dùng kiểm tra toàn vẹn không đối thủ. Chuẩn hiện nay: SHA-256 trở lên, và cho mật khẩu phải là bcrypt/Argon2 (chậm + salt).',
  };
  return notes[op] || '';
}

/** Chạy một thao tác codec từ CLI. Trả về chuỗi kết quả (đã ghi chú dạy học). */
export function runCodec(op, text) {
  const map = {
    b64enc: () => b64Encode(text),
    b64dec: () => b64Decode(text),
    hexenc: () => hexEncode(text),
    hexdec: () => hexDecode(text),
    urlenc: () => urlEncode(text),
    urldec: () => urlDecode(text),
    rot13: () => rot13(text),
  };
  const fn = map[op];
  if (!fn) {
    throw new Error(`Thao tác không rõ: "${op}". Các thao tác: b64enc | b64dec | hexenc | hexdec | urlenc | urldec | rot13 (và "hash <thuật-toán> <văn-bản>")`);
  }
  return fn();
}
