// hub/serve — server tĩnh cho Hub học an toàn thông tin.
//
// Nguyên tắc an toàn của server này:
//   • Bind CỨNG 127.0.0.1 — không bao giờ lắng nghe ngoài máy mình.
//   • Chỉ phục vụ file trong thư mục hub/ của project: đường dẫn được resolve
//     rồi đối chiếu tiền tố tuyệt đối (mitigation path-traversal), cấm '..'.
//   • Chỉ phục vụ extension trong danh sách cho phép; không chạy thứ gì cả.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { c } from '../utils/color.js';

const HUB_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'hub');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.md': 'text/markdown; charset=utf-8',
};

/** Chuẩn hoá URL path thành file tuyệt đối an toàn trong HUB_DIR, hoặc null. */
export function resolveSafe(urlPath) {
  let clean;
  try {
    clean = decodeURIComponent(String(urlPath || '/').split('?')[0]);
  } catch {
    // Percent-encoding lỗi (vd GET /%.) — decodeURIComponent ném URIError ngay
    // trong request handler; nuốt lỗi ở đây (→ 403) thay vì để một request duy
    // nhất làm chết process hub (CLI không đăng ký uncaughtException).
    return null;
  }
  if (clean.includes('..') || clean.includes('\\')) return null;
  if (clean === '/') clean = '/index.html';
  const abs = path.resolve(HUB_DIR, '.' + clean);
  if (abs !== HUB_DIR && !abs.startsWith(HUB_DIR + path.sep)) return null;
  const ext = path.extname(abs).toLowerCase();
  if (!MIME[ext]) return null;
  return { abs, ext };
}

function send(res, code, body, type) {
  res.writeHead(code, {
    'Content-Type': type,
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

/** Khởi động Hub server. Trả về http.Server đang listen trên 127.0.0.1. */
export function createHubServer({ port = 4000 } = {}) {
  const server = http.createServer((req, res) => {
    const found = resolveSafe(req.url);
    if (!found) {
      send(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
      return;
    }
    let body;
    try {
      body = fs.readFileSync(found.abs);
    } catch {
      send(res, 404, '404 — không tìm thấy trang', 'text/plain; charset=utf-8');
      return;
    }
    send(res, 200, body, MIME[found.ext]);
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

export function hubBanner(port) {
  return [
    '',
    `  ${c.bold('SECHUB — Hub học An toàn thông tin')}`,
    `  Đang chạy tại ${c.bold(`http://127.0.0.1:${port}`)} (chỉ truy cập được từ máy này)`,
    `  Mở trong trình duyệt để xem 9 chuyên mục học tập + mục lục.`,
    c.gray('  Nhấn Ctrl+C để dừng.\n'),
  ].join('\n');
}
