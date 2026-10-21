// Lab web app — CỐ Ý có lỗ hổng ở bản 'vuln' để thực hành, và bản 'hardened'
// đã vá đầy đủ để so sánh. Chạy CHỈ bind 127.0.0.1 (loopback), không bao giờ
// mở ra LAN/Internet.
//
// Lỗ hổng được cố tình cài ở bản vuln (mỗi cái một bài học):
//   LAB-01 SQL Injection       /search?q= , POST /login
//   LAB-02 Reflected XSS       /search?q= , trang 404
//   LAB-03 IDOR                /api/users/:id
//   LAB-04 Path Traversal      /download?name=  (hệ thống file ẢO — an toàn tuyệt đối)
//   LAB-05 Thiếu security headers + cookie không có cờ bảo mật
//   LAB-06 Thiếu rate limit    (so sánh với bản hardened)
//   LAB-07 Thiếu kiểm soát truy cập /admin
//   LAB-08 Verbose error page  (rò rỉ stack trace)
//   LAB-09 Command Injection   /tools/ping?host=  (exec nối chuỗi — CTF #5)
//   LAB-10 CSRF                POST /settings/email  (thiếu token chống CSRF)
//   LAB-11 JWT yếu             POST /api/token , GET /api/profile  (secret123 + alg=none — CTF #6)
//   LAB-12 Open Redirect       /redirect?to=
//   LAB-13 Unrestricted Upload POST /upload + GET /uploads/:name (stored XSS qua file)
//   LAB-14 XXE (mô phỏng)      POST /api/import  (entity → VFS ảo, an toàn tuyệt đối — CTF #7)
//   LAB-15 Stored XSS          /guestbook  (comment render không escape)
//   LAB-16 Prototype Pollution POST/GET /api/config  (merge không lọc __proto__ — CTF #8)
//   LAB-17 Mass Assignment     POST /api/register    (nhận trội role=admin — CTF #9)
//   LAB-18 Blind SQLi          /track?code=          (oracle boolean → rút cờ từng ký tự — CTF #10)
//   LAB-19 Reset token yếu     /api/reset/*          (md5(username) dự đoán được)
//   LAB-20 DOM-based XSS       /dom                  (location.hash → innerHTML — KHÔNG lọt vào log server!)
import http from 'node:http';
import crypto from 'node:crypto';
import { exec, execFile } from 'node:child_process';
import { tokenBucketLimiter } from '../defense/ratelimiter.js';
import { securityHeaders } from '../defense/headers.js';
import { createCsrfSecret, issueCsrfToken, verifyCsrfToken } from '../defense/csrf.js';
import { createLabDb } from '../db.js';
import { jwtSign, jwtVerify } from './jwtx.js';

// Hệ thống file ảo cho bài Path Traversal — KHÔNG đụng vào ổ đĩa thật.
const VFS = {
  'files/invoice-2026.pdf': '%PDF-1.4\n% Lab invoice — dữ liệu giả lập cho bài tập.\n1 0 obj << >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF',
  'files/readme.txt': 'Thu muc files/ cua lab. Thu ?name=../secrets.txt o ban vuln :)',
  'secrets.txt': 'LAB_SECRET{path-traversal-demo}\nDanh sach tai khoan noi bo (gia lap): alice/bob/carol/dave',
};

// Định nghĩa thử thách CTF của lab (chế độ vuln mới giải được — bản hardened
// chính là bài học "lỗ hổng đã vá thì cờ không lấy được").
const CHALLENGE_DEFS = [
  {
    id: 1,
    flagKey: 'sql',
    title: 'SQL Injection — dump toàn bộ người dùng',
    points: 30,
    hint: "Bản vuln nối chuỗi từ khoá vào câu LIKE. Payload ' OR 1=1 -- làm điều kiện LUÔN ĐÚNG và trả về tất cả người dùng — trong đó có một người dùng ẩn (không bao giờ hiện khi tìm bình thường) mà email chính là cờ FLAG{sqli-...}.",
  },
  {
    id: 2,
    flagKey: 'trav',
    title: 'Path Traversal — đọc file cờ ngoài thư mục được phép',
    points: 25,
    hint: "/download?name=... chỉ được phép đọc trong files/. File cờ flag-ctf.txt nằm Ở GỐC (ngoài files/) và KHÔNG xuất hiện trong /files listing — hãy leo ra ngoài bằng ../ (bản hardened chặn bằng kiểm tra prefix, hãy thử cả hai bản để thấy khác biệt).",
  },
  {
    id: 3,
    flagKey: 'idor',
    title: 'IDOR — đánh cắp apiKey của dave',
    points: 25,
    hint: '/api/users/:id ở bản vuln không hề kiểm tra phiên đăng nhập. apiKey của dave (id=4) đã được thay bằng cờ theo phiên — hãy so sánh với bản hardened (401/403).',
  },
  {
    id: 4,
    flagKey: 'admin',
    title: 'Broken Access Control — vào trang admin',
    points: 20,
    hint: 'Bản vuln không kiểm tra quyền ở /admin. Mở thẳng trang đó, cờ nằm ngay trong nội dung admin giả lập.',
  },
  {
    id: 5,
    flagKey: 'cmd',
    title: 'Command Injection — đọc biến môi trường của server',
    points: 25,
    hint: "/tools/ping?host= nối chuỗi thẳng vào shell. Nối lệnh bằng & (Windows cmd) hoặc ; (Linux sh) sau host hợp lệ: `127.0.0.1 & set SECLAB` hoặc `127.0.0.1; env | grep SECLAB` — biến SECLAB_CTF_CMD chứa cờ. Bản hardened dùng execFile + whitelist ký tự nên không chêm được lệnh.",
  },
  {
    id: 6,
    flagKey: 'jwt',
    title: 'JWT yếu — giả mạo token của service account',
    points: 25,
    hint: "POST /api/token (alice/alice123) để lấy JWT thật, decode bằng `node src/cli.js jwt decode <token>`. Bản vuln ký bằng secret yếu 'secret123' (crack bằng `jwt crack`) VÀ chấp nhận alg=none (`jwt forge --alg none`). Forge payload {\"sub\":\"ctfsvc\"} rồi GET /api/profile để lấy cờ.",
  },
  {
    id: 7,
    flagKey: 'xxe',
    title: 'XXE — đọc file cờ qua XML external entity',
    points: 20,
    hint: 'POST /api/import nhận XML. Bản vuln xử lý <!ENTITY x SYSTEM "file://..."> trên filesystem ảo — thử file:///flag-xxe.txt rồi tham chiếu &x; trong <item>. Bản hardened từ chối DOCTYPE hoàn toàn.',
  },
  {
    id: 8,
    flagKey: 'proto',
    title: 'Prototype Pollution — nhiễm Object.prototype',
    points: 30,
    hint: 'POST /api/config merge JSON ĐỆ QUY không lọc key nguy hiểm. Gửi {"__proto__":{"isAdmin":true}} — dst.__proto__ chính là Object.prototype nên key bị ghi xuyên vào prototype toàn cục. GET /api/config xem protoPolluted + cờ. Bản hardened lọc __proto__/constructor/prototype.',
  },
  {
    id: 9,
    flagKey: 'mass',
    title: 'Mass Assignment — tự đăng ký tài khoản admin',
    points: 25,
    hint: 'POST /api/register của bản vuln copy TOÀN BỘ field client gửi — kể cả từ query string (?role=admin). Đăng ký user mới kèm role=admin, đăng nhập, rồi GET /api/me: role=admin + cờ. Bản hardened whitelist chỉ username+password.',
  },
  {
    id: 10,
    flagKey: 'blind',
    title: 'Blind SQLi — rút cờ từng ký tự qua oracle boolean',
    points: 40,
    hint: "/track?code= chỉ trả found/404 — không lộ dữ liệu trực tiếp. Xác nhận oracle: code=AB-100' AND 1=1 -- (found) vs AND 1=2 -- (404). Rút từng ký tự của cờ: AB-100' AND (SELECT substr(flag,N,1) FROM ctf_blind)='X' -- với N=1,2,3...",
  },
];
const TOTAL_POINTS = CHALLENGE_DEFS.reduce((s, c) => s + c.points, 0);

export { esc } from './html.js';
import { esc } from './html.js';
import { renderDashboard, renderBlueDashboard, DASH_CSS, RED_JS, BLUE_JS } from './dashboard.js';
import { analyzeLog, RULES_INFO } from '../modules/detect.js';

function send(res, status, body, headers = {}) {
  res.statusCode = status;
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(body);
}

function html(res, status, body, extra = {}) {
  send(res, status, body, { 'Content-Type': 'text/html; charset=utf-8', ...extra });
}

function json(res, status, obj, extra = {}) {
  send(res, status, JSON.stringify(obj, null, 2), { 'Content-Type': 'application/json; charset=utf-8', ...extra });
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function readBody(req, limitBytes = vulnModeNoLimit()) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(Object.assign(new Error('payload_too_large'), { code: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function vulnModeNoLimit() {
  return 64 * 1024 * 1024; // bản vuln: gần như không giới hạn (đó chính là một lỗi)
}

function parseForm(body) {
  const out = {};
  for (const [k, v] of new URLSearchParams(body)) out[k] = v;
  return out;
}

// Parser multipart/form-data TỐI GIẢN cho bài upload — chỉ lấy part đầu có filename.
// (Parser thật phức tạp hơn nhiều; bản tối giản đủ để minh hoạ Unrestricted Upload.)
function parseMultipart(body, contentType) {
  const m = /boundary=([^;]+)/.exec(contentType || '');
  if (!m) return null;
  for (const part of String(body).split('--' + m[1])) {
    const idx = part.indexOf('\r\n\r\n');
    if (idx === -1) continue;
    const head = part.slice(0, idx);
    const content = part.slice(idx + 4).replace(/\r\n$/, '');
    const fn = /filename="([^"]*)"/.exec(head);
    if (fn) return { filename: fn[1], content };
  }
  return null;
}

// ---- Prototype Pollution (LAB-16) ----
// ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG: merge đệ quy KHÔNG lọc key. Với {"__proto__":{...}},
// dst['__proto__'] trỏ tới Object.prototype → các key con bị GHI XUYÊN vào
// prototype toàn cục → mọi object trong process đều "kế thừa" giá trị độc.
function unsafeMerge(dst, src) {
  if (!src || typeof src !== 'object') return dst;
  for (const k of Object.keys(src)) {
    if (src[k] && typeof src[k] === 'object') {
      if (dst[k] === null || typeof dst[k] !== 'object') dst[k] = {};
      unsafeMerge(dst[k], src[k]);
    } else {
      dst[k] = src[k];
    }
  }
  return dst;
}

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
// Đã vá: lọc key nguy hiểm + chỉ recurse vào OWN property (không đi theo chain).
function safeMerge(dst, src) {
  if (!src || typeof src !== 'object') return dst;
  for (const k of Object.keys(src)) {
    if (DANGEROUS_KEYS.has(k)) continue;
    if (src[k] && typeof src[k] === 'object') {
      if (!Object.hasOwn(dst, k) || dst[k] === null || typeof dst[k] !== 'object') dst[k] = {};
      safeMerge(dst[k], src[k]);
    } else {
      dst[k] = src[k];
    }
  }
  return dst;
}

const page = (title, body, mode) => `<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="color-scheme" content="dark"><title>${title} — SecLab [${mode.toUpperCase()}]</title>
<style>:root{color-scheme:dark}html{background:#0b1220;color:#e2e8f0}
body{font-family:system-ui,Segoe UI,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem}
a{color:#4ade80}.mode{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:700}
.vuln{background:#450a0a;color:#fca5a5}.hardened{background:#052e16;color:#86efac}
code,pre{background:#1e293b;color:#e2e8f0}pre{padding:12px;overflow:auto}</style></head>
<body><span class="mode ${mode}">LAB ${mode.toUpperCase()}</span>
<h1>${title}</h1>
${body}
<hr><p><a href="/">Trang chủ</a> · <a href="/lab"><b>🔴 Red Team</b></a> · <a href="/blue"><b>🔵 Blue Team</b></a> · <a href="/search?q=alice">/search</a> · <a href="/login">/login</a> · <a href="/api/users/2">/api/users/2</a> · <a href="/download?name=readme.txt">/download</a> · <a href="/slow">/slow</a> · <a href="/_lab/metrics">/_lab/metrics</a></p></body></html>`;

/**
 * Tạo HTTP server của lab.
 * @param {{mode?: 'vuln'|'hardened', rateLimit?: {capacity?: number, refillPerSec?: number}}} opts
 *        rateLimit chỉ nên đặt khác mặc định trong test E2E (bucket lớn để các
 *        check luồng không flake); nhóm test rate limit dùng đúng mặc định 20/4s.
 */
export async function createLabApp(opts = {}) {
  const { mode = 'vuln' } = opts;
  const hardened = mode === 'hardened';
  const db = await createLabDb({ mode });
  const metrics = { total: 0, byPath: {}, startedAt: new Date().toISOString() };
  const sessions = new Map(); // sid -> {id, name, role}

  const limiter = tokenBucketLimiter(opts.rateLimit ?? { capacity: 20, refillPerSec: 4 });

  // ---- Chế độ CTF: cờ ngẫu nhiên THEO PHIÊN (mỗi lần khởi động lab khác nhau) ----
  const randHex = (n) => crypto.randomBytes(n).toString('hex');
  const ctf = { enabled: !hardened, solved: new Set(), flags: {}, score: 0 };
  const vfs = { ...VFS }; // bản VFS per-instance (bản vuln thêm file cờ)

  // JWT: bản vuln cố tình ký bằng SECRET YẾU trong từ điển (bài học brute-force
  // khoá HMAC); bản hardened dùng khoá ngẫu nhiên 256-bit theo phiên.
  const VULN_JWT_SECRET = 'secret123';
  const jwtSecret = hardened ? randHex(32) : VULN_JWT_SECRET;
  const csrfSecret = createCsrfSecret(); // khoá phát hành CSRF token (bản hardened)
  const guestbook = []; // comment in-memory cho bài Stored XSS (cap 100)
  const labConfig = { theme: 'dark', lang: 'vi' }; // cấu hình demo cho bài Prototype Pollution
  const resetTokens = new Map(); // token ngẫu nhiên → { user, exp } (bản hardened)

  if (!hardened) {
    ctf.flags.sql = `FLAG{sqli-${randHex(6)}}`;
    ctf.flags.trav = `FLAG{trav-${randHex(6)}}`;
    ctf.flags.idor = `FLAG{idor-${randHex(6)}}`;
    ctf.flags.admin = `FLAG{admin-${randHex(6)}}`;
    ctf.flags.cmd = `FLAG{cmd-${randHex(6)}}`;
    ctf.flags.jwt = `FLAG{jwt-${randHex(6)}}`;
    ctf.flags.xxe = `FLAG{xxe-${randHex(6)}}`;
    ctf.flags.proto = `FLAG{proto-${randHex(6)}}`;
    ctf.flags.mass = `FLAG{mass-${randHex(6)}}`;
    ctf.flags.blind = `FLAG{blind-${randHex(6)}}`;
    db.setBlindFlag(ctf.flags.blind);
    // Cờ command-injection nằm trong BIẾN MÔI TRƯỜNG của tiến trình lab —
    // chỉ đọc được bằng cách chêm lệnh vào /tools/ping (set / env).
    process.env.SECLAB_CTF_CMD = ctf.flags.cmd;
    // Người dùng ẩn: tên không khớp mọi từ khoá bình thường, chỉ lộ khi dump 1=1.
    db.addUser({ id: 99, name: 'zz_ctf_hidden', password: randHex(8), role: 'user', email: ctf.flags.sql, apiKey: 'LAB-KEY-CTF-0099' });
    db.setApiKey(4, ctf.flags.idor);
    vfs['flag-ctf.txt'] = `${ctf.flags.trav}\nCờ CTF — file ở GỐC, ngoài thư mục files/ được phép; chỉ đọc được qua path traversal.`;
    vfs['flag-xxe.txt'] = `${ctf.flags.xxe}\nCờ CTF — chỉ đọc được qua XXE entity file:///flag-xxe.txt trong POST /api/import.`;
    // /etc/passwd giả lập cho bài XXE — cảm giác "đọc file hệ thống" mà không đụng đĩa thật.
    vfs['etc/passwd'] = 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\nlab-svc:x:1001:1001::/nonexistent:/usr/sbin/nologin';
  }

  // Log request phục vụ bài blue-team (module detect) — chỉ trong bộ nhớ, cap 500.
  const reqLog = [];

  const server = http.createServer(async (req, res) => {
    metrics.total += 1;
    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = u.pathname.replace(/\/+$/, '') || '/';
    metrics.byPath[path] = (metrics.byPath[path] || 0) + 1;
    const logEntry = { t: Date.now(), method: req.method, path: u.pathname + u.search, ua: req.headers['user-agent'] || '', ip: req.socket.remoteAddress || '', status: 0 };
    reqLog.push(logEntry);
    if (reqLog.length > 500) reqLog.shift();
    res.on('finish', () => { logEntry.status = res.statusCode; }); // status ghi sau khi response xong

    try {
      if (hardened) {
        securityHeaders(req, res, () => {});
        await new Promise((resolve, reject) => limiter(req, res, (e) => (e ? reject(e) : resolve())));
        if (res.writableEnded) return; // đã trả 429
      }
      await route(req, res, u, path, { hardened, db, metrics, sessions });
    } catch (err) {
      if (err && err.code === 413) {
        return json(res, 413, { error: 'payload_too_large' });
      }
      if (hardened) {
        console.error('[lab] lỗi:', err.message); // log nội bộ, KHÔNG lộ ra response
        return html(res, 500, page('Lỗi', '<p>Đã xảy ra lỗi. Vui lòng thử lại sau.</p>', 'hardened'));
      }
      // Bản vuln: lộ nguyên stack trace — lỗi "Verbose Error Page" (LAB-08)
      html(
        res,
        500,
        page('Internal Server Error', `<h2>Stack trace (lộ lỗ hổng!)</h2><pre>${esc(err && err.stack ? err.stack : String(err))}</pre>`, 'vuln')
      );
    }
  });

  // Chống slowloris kiểu nginx limit_conn: đếm các kết nối "CHƯA hoàn tất request
  // đầu tiên" theo IP. Vượt ngưỡng → hẹn huỷ sau GRACE: kết nối bình thường
  // (browser, load-test) hoàn tất request trong vài mili-giây nên không bao giờ
  // dính hẹn; slowloris cố tình không hoàn tất → đúng 2s bị cắt.
  const HALF_OPEN_LIMIT = 10;
  const HALF_OPEN_GRACE_MS = 2_000;
  const perIp = new Map();

  server.on('connection', (socket) => {
    const ip = socket.remoteAddress || 'unknown';
    const entry = perIp.get(ip) || { unhealthy: 0 };
    entry.unhealthy += 1;
    perIp.set(ip, entry);
    socket.__seclabHealthy = false;

    let graceTimer = null;
    if (hardened && entry.unhealthy > HALF_OPEN_LIMIT) {
      graceTimer = setTimeout(() => {
        if (socket.__seclabHealthy === false && !socket.destroyed) {
          socket.destroy(); // chủ động cắt kết nối "nửa request" quá hạn
        }
      }, HALF_OPEN_GRACE_MS);
    }

    socket.once('close', () => {
      if (graceTimer) clearTimeout(graceTimer);
      const e = perIp.get(ip);
      if (!e) return;
      if (socket.__seclabHealthy !== true) e.unhealthy = Math.max(0, e.unhealthy - 1);
      if (e.unhealthy === 0) perIp.delete(ip);
    });
  });
  server.on('request', (req) => {
    const s = req.socket;
    if (s && s.__seclabHealthy === false) {
      s.__seclabHealthy = true;
      const e = perIp.get(s.remoteAddress || 'unknown');
      if (e) e.unhealthy = Math.max(0, e.unhealthy - 1);
    }
  });

  async function route(req, res, u, path, ctx) {
    const { hardened, db, sessions } = ctx;
    const q = u.searchParams;
    const cookies = parseCookies(req);
    const session = cookies.session ? sessions.get(cookies.session) : undefined;

    // ---------- /lab — Dashboard Red Team (chọn mục tiêu) ----------
    // Asset tách riêng: CSP hardened (script-src/style-src 'self') cấm inline.
    if (path === '/_lab/dash.css' && req.method === 'GET') {
      return send(res, 200, DASH_CSS, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'no-store' });
    }
    if (path === '/_lab/dash-red.js' && req.method === 'GET') {
      return send(res, 200, RED_JS, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' });
    }
    if (path === '/_lab/dash-blue.js' && req.method === 'GET') {
      return send(res, 200, BLUE_JS, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' });
    }
    if (path === '/lab' && req.method === 'GET') {
      return html(res, 200, renderDashboard(hardened ? 'hardened' : 'vuln'));
    }

    // ---------- /blue — Dashboard Blue Team (SOC console) ----------
    if (path === '/blue' && req.method === 'GET') {
      return html(res, 200, renderBlueDashboard(hardened ? 'hardened' : 'vuln', RULES_INFO));
    }

    // ---------- /_lab/alerts — engine phát hiện chạy trên request log ----------
    if (path === '/_lab/alerts' && req.method === 'GET') {
      return json(res, 200, { ...analyzeLog(reqLog), rules: RULES_INFO, mode: hardened ? 'hardened' : 'vuln' });
    }

    // ---------- trang chủ ----------
    if (path === '/' && req.method === 'GET') {
      const items = [
        '<li><a href="/search?q=alice">/search?q=... — tìm người dùng (SQLi + XSS)</a></li>',
        '<li><a href="/login">/login — đăng nhập (SQLi bypass)</a></li>',
        '<li><a href="/api/users/2">/api/users/:id — dữ liệu người dùng (IDOR)</a></li>',
        '<li><a href="/download?name=readme.txt">/download?name=... — tải file (Path Traversal)</a></li>',
        '<li><a href="/tools/ping?host=127.0.0.1">/tools/ping?host= — chẩn đoán mạng (Command Injection)</a></li>',
        '<li><a href="/settings">/settings — đổi email (CSRF)</a></li>',
        '<li><a href="/guestbook">/guestbook — sổ lưu niệm (Stored XSS)</a></li>',
        '<li><a href="/upload">/upload — tải file lên (Unrestricted Upload)</a></li>',
        '<li><a href="/redirect?to=/">/redirect?to= — chuyển hướng (Open Redirect)</a></li>',
        '<li>POST /api/token → JWT · GET /api/profile — xác thực token (JWT yếu)</li>',
        '<li>POST /api/import — nhập XML (XXE mô phỏng trên filesystem ảo)</li>',
        '<li>POST /api/config — cập nhật cấu hình JSON (Prototype Pollution)</li>',
        '<li>POST /api/register — đăng ký tài khoản (Mass Assignment)</li>',
        '<li><a href="/track?code=AB-100">/track?code= — tra mã vận đơn (Blind SQLi)</a></li>',
        '<li><a href="/api/reset/request?user=alice">/api/reset/* — quên mật khẩu (reset token yếu)</a></li>',
        '<li><a href="/dom">/dom — trang hiển thị hash (DOM-based XSS)</a></li>',
        '<li><a href="/slow">/slow — endpoint chậm 3s (demo tải)</a></li>',
        '<li><a href="/lab"><b>/lab — 🔴 Red Team: chọn mục tiêu (20 bài, lọc &amp; theo tiến độ)</b></a></li>',
        '<li><a href="/blue"><b>/blue — 🔵 Blue Team: SOC console, live feed &amp; alerts</b></a></li>',
        '<li><a href="/_lab/metrics">/_lab/metrics — bộ đếm request của lab</a></li>',
      ].join('\n');
      return html(
        res,
        200,
        page(
          'Chào mừng đến SecLab',
          `<p>Lab web <b>${hardened ? 'ĐÃ VÁ (hardened)' : 'CỐ Ý DỄ TỔN THƯƠNG (vuln)'}</b>. Dữ liệu 100% giả lập.</p><ul>${items}</ul>` +
            (hardened ? '' : `<p>Thử: <code>/search?q=' OR 1=1 --</code></p>`),
          hardened ? 'hardened' : 'vuln'
        )
      );
    }

    // ---------- /login ----------
    if (path === '/login') {
      if (req.method === 'GET') {
        return html(
          res,
          200,
          page(
            'Đăng nhập',
            `<form method="POST" action="/login">
        <label>Tên đăng nhập <input name="username"></label><br><br>
        <label>Mật khẩu <input name="password" type="password"></label><br><br>
        <button>Đăng nhập</button></form>
        <p>Tài khoản lab: alice/alice123 (admin), bob/bob45678, carol/carol90ab, dave/dave-cd34</p>`,
            hardened ? 'hardened' : 'vuln'
          )
        );
      }
      if (req.method === 'POST') {
        const body = parseForm(await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit()));
        const result = hardened ? db.loginSafe(body.username, body.password) : db.login(body.username, body.password);
        if (result.ok) {
          const sid = crypto.randomBytes(16).toString('hex');
          sessions.set(sid, result.user);
          const flags = hardened ? '; Path=/; HttpOnly; SameSite=Strict' : ''; // vuln: không có cờ bảo mật
          res.setHeader('Set-Cookie', `session=${sid}${flags}`);
          return html(res, 200, page('Đăng nhập', `<p>Xin chào <b>${hardened ? esc(result.user.name) : result.user.name}</b> (role: ${result.user.role}). <a href="/logout">Đăng xuất</a></p>`, hardened ? 'hardened' : 'vuln'));
        }
        const msg = hardened
          ? '<p>Sai tên đăng nhập hoặc mật khẩu.</p>'
          : `<p>Sai thông tin đăng nhập!</p><pre>${esc(result.error || '')}</pre>` +
            `<p>Gợi ý lab: username = <code>' OR 1=1 --</code>, password tuỳ ý.</p>`;
        return html(res, 401, page('Đăng nhập thất bại', msg, hardened ? 'hardened' : 'vuln'));
      }
    }

    if (path === '/logout' && req.method === 'GET') {
      if (cookies.session) sessions.delete(cookies.session);
      res.setHeader('Set-Cookie', 'session=; Path=/; Max-Age=0');
      return html(res, 200, page('Đăng xuất', '<p>Đã đăng xuất.</p>', hardened ? 'hardened' : 'vuln'));
    }

    // ---------- /search (SQLi + XSS) ----------
    if (path === '/search' && req.method === 'GET') {
      const term = q.get('q') || '';
      const result = hardened ? db.searchUsersSafe(term) : db.searchUsers(term);
      const rowsHtml = result.rows
        .map((r) => `<tr><td>${r.id}</td><td>${hardened ? esc(r.name) : r.name}</td><td>${hardened ? esc(r.role) : r.role}</td><td>${hardened ? esc(r.email) : r.email}</td></tr>`)
        .join('');
      const body =
        `<p>Kết quả cho từ khoá: <b>${hardened ? esc(term) : term}</b></p>
         <form><input name="q" value="${hardened ? esc(term) : term}"><button>Tìm</button></form>
         <table border="1" cellpadding="6"><tr><th>ID</th><th>Tên</th><th>Role</th><th>Email</th></tr>${rowsHtml}</table>` +
        (result.error ? `<h3>Lỗi CSDL (lộ chi tiết!)</h3><pre>${esc(result.error)}</pre>` : '');
      return html(res, 200, page('Tìm kiếm người dùng', body, hardened ? 'hardened' : 'vuln'));
    }

    // ---------- /api/users/:id (IDOR) ----------
    const m = path.match(/^\/api\/users\/(\d+)$/);
    if (m && req.method === 'GET') {
      const id = Number(m[1]);
      if (hardened) {
        if (!session) return json(res, 401, { error: 'unauthorized', message: 'Cần đăng nhập để xem dữ liệu người dùng.' });
        if (session.id !== id && session.role !== 'admin') {
          return json(res, 403, { error: 'forbidden', message: 'Bạn chỉ được xem dữ liệu của chính mình.' });
        }
      }
      const user = db.getUserById(id);
      if (!user) return json(res, 404, { error: 'not_found' });
      return json(res, 200, user); // chứa cả email + apiKey (dữ liệu giả lập)
    }

    if (path === '/api/me' && req.method === 'GET') {
      const out = session ? { ...session } : { user: null };
      // CTF #9: user TỰ ĐĂNG KÝ (id >= 100) mà role là admin → đã leo quyền qua
      // mass assignment (alice admin thật có id=1 nên không tính).
      if (!hardened && session && session.role === 'admin' && session.id >= 100) {
        out.flag = ctf.flags.mass;
      }
      return json(res, 200, out);
    }

    // ---------- /download (Path Traversal trên VFS ảo) ----------
    if (path === '/download' && req.method === 'GET') {
      const name = q.get('name') || '';
      const p = posixJoin('files', name);
      if (hardened && (p.includes('..') || !p.startsWith('files/'))) {
        return json(res, 400, { error: 'invalid_path', message: 'Đường dẫn không hợp lệ.' });
      }
      const content = vfs[p];
      if (content === undefined) return json(res, 404, { error: 'not_found', path: p });
      return send(res, 200, content, { 'Content-Type': 'text/plain; charset=utf-8' });
    }

    // ---------- /slow ----------
    if (path === '/slow' && req.method === 'GET') {
      const ms = Math.min(Number(q.get('ms')) || 3000, 10000);
      await new Promise((r) => setTimeout(r, ms));
      return json(res, 200, { ok: true, delayedMs: ms });
    }

    // ---------- /admin ----------
    if (path === '/admin' && req.method === 'GET') {
      if (hardened) {
        if (!session || session.role !== 'admin') {
          return json(res, 403, { error: 'forbidden', message: 'Chỉ admin.' });
        }
      }
      // bản vuln: KHÔNG kiểm tra gì cả — missing authorization (CTF: cờ nằm ngay đây)
      const adminBody = hardened
        ? '<p>Danh sách người dùng, cài đặt hệ thống… (nội dung admin nhạy cảm giả lập)</p>'
        : `<p>Danh sách người dùng, cài đặt hệ thống… (nội dung admin nhạy cảm giả lập)</p><p>Mã kích hoạt nội bộ: <code>${ctf.flags.admin}</code></p>`;
      return html(res, 200, page('Bảng điều khiển Admin', adminBody, hardened ? 'hardened' : 'vuln'));
    }

    // ---------- /tools/ping (Command Injection — LAB-09) ----------
    if (path === '/tools/ping' && req.method === 'GET') {
      const host = String(q.get('host') || '127.0.0.1').slice(0, 200);
      const countFlag = process.platform === 'win32' ? '-n' : '-c';
      const render = (out) =>
        html(
          res,
          200,
          page(
            'Ping chẩn đoán',
            `<form><input name="host" value="${esc(host)}" size="40"><button>Ping</button></form><pre>${esc(out)}</pre>` +
              (hardened
                ? ''
                : '<p>Gợi ý lab: <code>127.0.0.1 &amp; whoami</code> (Windows) · <code>127.0.0.1; id</code> (Linux)</p>'),
            hardened ? 'hardened' : 'vuln'
          )
        );
      if (hardened) {
        // Đã vá: whitelist ký tự + execFile (không qua shell → không có injection).
        if (!/^[a-zA-Z0-9.-]{1,64}$/.test(host)) {
          return json(res, 400, { error: 'invalid_host', message: 'Host chỉ được chứa [a-zA-Z0-9.-].' });
        }
        return execFile('ping', [countFlag, '2', host], { timeout: 6000, windowsHide: true }, (err, stdout, stderr) =>
          render(String(stdout || '') + String(stderr || err || ''))
        );
      }
      // ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG: nối chuỗi input vào lệnh shell.
      exec(`ping ${countFlag} 2 ${host}`, { timeout: 8000, windowsHide: true, maxBuffer: 256 * 1024 }, (err, stdout, stderr) =>
        render(String(stdout || '') + String(stderr || '') + (err && !stderr ? `\n[exit ${err.code ?? err.message}]` : ''))
      );
      return;
    }

    // ---------- /settings + POST /settings/email (CSRF — LAB-10) ----------
    if (path === '/settings' && req.method === 'GET') {
      if (!session) {
        return html(res, 200, page('Cài đặt', '<p>Bạn cần <a href="/login">đăng nhập</a> trước.</p>', hardened ? 'hardened' : 'vuln'));
      }
      const csrfField = hardened ? `<input type="hidden" name="csrf" value="${issueCsrfToken(csrfSecret, cookies.session)}">` : '';
      return html(
        res,
        200,
        page(
          'Cài đặt tài khoản',
          `<p>Email hiện tại: <b>${esc(session.email || '(chưa đặt)')}</b></p>
           <form method="POST" action="/settings/email">${csrfField}
             <label>Email mới <input name="email" value="attacker@evil.example"></label>
             <button>Đổi email</button></form>
           <p>Một trang độc hại có thể auto-submit form POST tới endpoint này — trình duyệt TỰ đính kèm
              cookie phiên của nạn nhân. Đó là CSRF.</p>`,
          hardened ? 'hardened' : 'vuln'
        )
      );
    }
    if (path === '/settings/email' && req.method === 'POST') {
      if (!session) return json(res, 401, { error: 'unauthorized', message: 'Cần đăng nhập.' });
      const body = parseForm(await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit()));
      if (hardened) {
        // Đã vá: kiểm Origin (nếu trình duyệt gửi) + bắt buộc CSRF token khớp session.
        const origin = String(req.headers.origin || '');
        if (origin && !origin.startsWith(`http://${req.headers.host}`)) {
          return json(res, 403, { error: 'bad_origin', message: 'Origin không khớp host — nghi CSRF.' });
        }
        if (!verifyCsrfToken(csrfSecret, cookies.session, body.csrf)) {
          return json(res, 403, { error: 'csrf_failed', message: 'Thiếu hoặc sai CSRF token.' });
        }
      }
      session.email = String(body.email || '').slice(0, 120);
      const note = hardened
        ? '✅ Request có CSRF token hợp lệ và Origin đúng.'
        : '⚠ Request được chấp nhận MÀ KHÔNG cần token — trang web khác hoàn toàn có thể đổi email của bạn!';
      return html(res, 200, page('Đã đổi email', `<p>Email mới: <b>${esc(session.email)}</b></p><p>${note}</p>`, hardened ? 'hardened' : 'vuln'));
    }

    // ---------- JWT lab (LAB-11): POST /api/token + GET /api/profile ----------
    if (path === '/api/token' && req.method === 'POST') {
      const body = parseForm(await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit()));
      // loginSafe cho CẢ hai bản — bài học ở đây là TOKEN, không phải SQLi.
      const result = db.loginSafe(body.username, body.password);
      if (!result.ok) return json(res, 401, { error: 'bad_credentials' });
      const now = Math.floor(Date.now() / 1000);
      const token = jwtSign({ sub: result.user.name, role: result.user.role, iat: now, exp: now + 3600 }, jwtSecret);
      return json(res, 200, {
        token,
        huong_dan: 'GET /api/profile?token=<jwt> hoặc header: Authorization: Bearer <jwt>',
        ...(hardened ? {} : { ghi_chu_lab: "Bản vuln ký bằng secret yếu trong từ điển — thử: node src/cli.js jwt crack <token>" }),
      });
    }
    if (path === '/api/profile' && req.method === 'GET') {
      const authz = String(req.headers.authorization || '');
      const token = authz.startsWith('Bearer ') ? authz.slice(7).trim() : String(q.get('token') || '');
      const v = jwtVerify(token, jwtSecret, { allowNone: !hardened, checkExp: hardened });
      if (!v.ok) return json(res, 401, { error: 'invalid_token', reason: v.error });
      const out = { profile: { user: v.payload.sub, role: v.payload.role || 'user' } };
      // 'ctfsvc' là service account nội bộ — không ai đăng nhập được (chỉ có được
      // qua GIẢ MẠO token), nên cờ ở đây chứng minh được bạn đã forge JWT.
      if (!hardened && v.payload.sub === 'ctfsvc') out.flag = ctf.flags.jwt;
      return json(res, 200, out);
    }

    // ---------- /redirect (Open Redirect — LAB-12) ----------
    if (path === '/redirect' && req.method === 'GET') {
      const to = String(q.get('to') || '/');
      // Đã vá: chỉ cho phép path nội bộ bắt đầu bằng "/" (không phải "//" protocol-relative, không chứa backslash).
      if (hardened && (!to.startsWith('/') || to.startsWith('//') || to.includes('\\'))) {
        return json(res, 400, { error: 'invalid_target', message: 'Chỉ cho phép chuyển hướng tới path nội bộ.' });
      }
      res.statusCode = 302;
      res.setHeader('Location', to);
      return res.end();
    }

    // ---------- /upload + /uploads/:name (Unrestricted Upload — LAB-13) ----------
    if (path === '/upload' && req.method === 'GET') {
      return html(
        res,
        200,
        page(
          'Tải file lên',
          `<form method="POST" action="/upload" enctype="multipart/form-data"><input type="file" name="file"><button>Tải lên</button></form>
           <p>Hoặc urlencoded: <code>POST /upload</code> với field <code>name</code> + <code>content</code>.</p>
           <p>File được phục vụ lại tại <code>/uploads/&lt;tên&gt;</code>${
             hardened
               ? ' — whitelist đuôi file + ép Content-Type text/plain.'
               : ' — <b>không kiểm tra đuôi file</b>, .html được trả về text/html (stored XSS qua upload).'
           }</p>`,
          hardened ? 'hardened' : 'vuln'
        )
      );
    }
    if (path === '/upload' && req.method === 'POST') {
      const raw = await readBody(req, hardened ? 512 * 1024 : vulnModeNoLimit());
      const ct = String(req.headers['content-type'] || '');
      let name = '';
      let content = '';
      if (ct.includes('multipart/form-data')) {
        const m = parseMultipart(raw, ct);
        if (m) ({ filename: name, content } = m);
      } else {
        const f = parseForm(raw);
        name = f.name || '';
        content = f.content || '';
      }
      const base = String(name).split(/[\\/]/).pop().slice(0, 80);
      if (!base) return json(res, 400, { error: 'missing_file' });
      if (hardened) {
        // Đã vá: whitelist extension + tên file sanitize.
        const ALLOWED_EXT = ['.txt', '.md', '.csv', '.png', '.jpg', '.jpeg', '.pdf'];
        const ext = base.includes('.') ? base.slice(base.lastIndexOf('.')).toLowerCase() : '';
        if (!ALLOWED_EXT.includes(ext)) {
          return json(res, 415, { error: 'bad_file_type', message: `Chỉ cho phép: ${ALLOWED_EXT.join(', ')}`, ext });
        }
      }
      const safe = base.replace(/[^a-zA-Z0-9._-]/g, '_');
      vfs[`files/uploads/${safe}`] = String(content).slice(0, 256 * 1024);
      return html(
        res,
        200,
        page('Đã tải lên', `<p>Đã lưu <code>${esc(safe)}</code> (${content.length} bytes) → <a href="/uploads/${encodeURIComponent(safe)}">/uploads/${esc(safe)}</a></p>`, hardened ? 'hardened' : 'vuln')
      );
    }
    const um = path.match(/^\/uploads\/([^/]+)$/);
    if (um && req.method === 'GET') {
      const key = `files/uploads/${decodeURIComponent(um[1])}`;
      const content = vfs[key];
      if (content === undefined) return json(res, 404, { error: 'not_found' });
      const ext = key.includes('.') ? key.slice(key.lastIndexOf('.')).toLowerCase() : '';
      const MIME = {
        '.html': 'text/html; charset=utf-8',
        '.htm': 'text/html; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.pdf': 'application/pdf',
      };
      // Bản vuln phục vụ theo đúng MIME của file → file .html upload lên CHẠY ĐƯỢC
      // script (stored XSS qua upload). Bản hardened ép text/plain cho mọi file.
      return send(res, 200, content, { 'Content-Type': hardened ? 'text/plain; charset=utf-8' : MIME[ext] || 'text/plain; charset=utf-8' });
    }

    // ---------- /api/import (XXE mô phỏng trên VFS — LAB-14) ----------
    if (path === '/api/import' && req.method === 'POST') {
      const xml = await readBody(req, hardened ? 64 * 1024 : 1024 * 1024);
      // Đã vá: parser từ chối DTD hoàn toàn — chống XXE ở gốc.
      if (hardened && /<!DOCTYPE|<!ENTITY/i.test(xml)) {
        return json(res, 400, { error: 'dtd_prohibited', message: 'XML parser từ chối DOCTYPE/ENTITY — cấu hình chống XXE.' });
      }
      // Bản vuln: "parser" nghiệp dân resolve <!ENTITY x SYSTEM "file://...">
      // bằng cách tra VFS ảo — mô phỏng XXE mà không đụng đĩa thật.
      const entities = {};
      if (!hardened) {
        for (const m of xml.matchAll(/<!ENTITY\s+([^\s]+)\s+SYSTEM\s+"file:\/\/([^"]+)"\s*>/gi)) {
          const key = m[2].replace(/^\/+/, '');
          entities[m[1]] = vfs[key] ?? `[file không tồn tại: ${key}]`;
        }
      }
      const resolved = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/gi)].map((m) =>
        m[1].replace(/&([A-Za-z0-9_-]+);/g, (s, n) => entities[n] ?? s)
      );
      return json(res, 200, { imported: resolved.length, items: resolved });
    }

    // ---------- /guestbook (Stored XSS — LAB-15) ----------
    if (path === '/guestbook' && req.method === 'GET') {
      const list =
        guestbook
          .map((g) => `<li><b>${hardened ? esc(g.who) : g.who}</b>: ${hardened ? esc(g.msg) : g.msg} <i>(${g.t})</i></li>`)
          .join('') || '<li><i>chưa có lời nhắn</i></li>';
      return html(
        res,
        200,
        page(
          'Sổ lưu niệm',
          `<ul>${list}</ul><form method="POST" action="/guestbook"><input name="msg" placeholder="Lời nhắn của bạn" size="50"><button>Gửi</button></form>` +
            (hardened ? '' : '<p>Gợi ý lab: lời nhắn được render KHÔNG escape — thử <code>&lt;svg/onload=alert(1)&gt;</code></p>'),
          hardened ? 'hardened' : 'vuln'
        )
      );
    }
    if (path === '/guestbook' && req.method === 'POST') {
      const body = parseForm(await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit()));
      if (guestbook.length >= 100) guestbook.shift();
      guestbook.push({ who: session?.name || 'guest', msg: String(body.msg || '').slice(0, 500), t: new Date().toISOString().slice(11, 19) });
      res.statusCode = 303; // POST → redirect về GET (PRG pattern)
      res.setHeader('Location', '/guestbook');
      return res.end();
    }

    // ---------- /api/config (Prototype Pollution — LAB-16) ----------
    if (path === '/api/config' && req.method === 'POST') {
      const raw = await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit());
      let payload;
      try {
        payload = JSON.parse(raw);
      } catch {
        return json(res, 400, { error: 'bad_json', message: 'Body phải là JSON hợp lệ.' });
      }
      const merged = hardened ? safeMerge(labConfig, payload) : unsafeMerge(labConfig, payload);
      return json(res, 200, { ok: true, config: merged });
    }
    if (path === '/api/config' && req.method === 'GET') {
      // Key nhiễm vào Object.prototype trở thành ENUMERABLE → liệt kê được.
      const polluted = Object.keys(Object.prototype);
      const out = {
        config: labConfig,
        protoPolluted: polluted,
        ghi_chu: hardened
          ? 'safeMerge() lọc __proto__/constructor/prototype — Object.prototype sạch.'
          : 'unsafeMerge() đi xuyên __proto__ — thử POST {"__proto__":{"isAdmin":true}} rồi GET lại endpoint này.',
      };
      if (!hardened && polluted.length > 0) {
        out.flag = ctf.flags.proto;
        out.canh_bao = `Object.prototype đang chứa key lạ: ${polluted.join(', ')} — mọi object trong process đều "kế thừa" nó. Restart lab để sạch.`;
      }
      return json(res, 200, out);
    }

    // ---------- /api/register (Mass Assignment — LAB-17) ----------
    if (path === '/api/register' && req.method === 'POST') {
      const body = parseForm(await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit()));
      // Bản vuln còn gộp cả QUERY STRING vào field — "đọc input từ nhiều nguồn
      // không phân biệt" khiến ?role=admin lọt vào ngay cả khi form không có field đó.
      const fields = hardened ? body : { ...Object.fromEntries(q), ...body };
      if (!fields.username || !fields.password) {
        return json(res, 400, { error: 'missing_fields', message: 'Cần username + password.' });
      }
      if (db.findUser(fields.username)) {
        return json(res, 409, { error: 'user_exists', message: 'Tên đăng nhập đã tồn tại.' });
      }
      const id = 100 + db.countUsers();
      const newUser = hardened
        ? // Đã vá: WHITELIST — chỉ nhận đúng field cần thiết, role gán cứng 'user'.
          { id, name: String(fields.username).slice(0, 40), password: String(fields.password).slice(0, 64), role: 'user', email: '', apiKey: `LAB-KEY-SELF-${id}` }
        : // ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG: copy mọi field (role, email, apiKey... tuỳ ý).
          { id, name: String(fields.username).slice(0, 40), password: String(fields.password).slice(0, 64), role: String(fields.role || 'user'), email: String(fields.email || ''), apiKey: `LAB-KEY-SELF-${id}` };
      db.addUser(newUser);
      return json(res, 201, {
        ok: true,
        user: { id: newUser.id, name: newUser.name, role: newUser.role },
        huong_dan: 'Đăng nhập qua POST /login rồi xem GET /api/me.',
        ...(hardened ? {} : { ghi_chu: 'Bản vuln copy mọi field — kể cả role. Thử: POST /api/register?role=admin' }),
      });
    }

    // ---------- /track (Blind SQLi oracle — LAB-18) ----------
    if (path === '/track' && req.method === 'GET') {
      const code = String(q.get('code') || '').slice(0, 500);
      const result = hardened ? db.trackShipmentSafe(code) : db.trackShipment(code);
      const body = result.found
        ? `<p>Mã vận đơn <b>${hardened ? esc(code) : code}</b>: <b>TỒN TẠI</b> trong hệ thống.</p>`
        : `<p>Mã vận đơn <b>${hardened ? esc(code) : code}</b>: không tìm thấy.${result.error ? ' <i>(lỗi truy vấn lộ ra response!)</i>' : ''}</p>`;
      const hint = hardened
        ? ''
        : `<p>Oracle boolean — thử: <code>/track?code=AB-100' AND 1=1 --</code> vs <code>AND 1=2 --</code>. Cờ nằm trong bảng <code>ctf_blind</code>, cột <code>flag</code> — rút từng ký tự bằng substr().</p>`;
      return html(res, result.found ? 200 : 404, page('Tra cứu vận đơn', body + `<form><input name="code" value="${hardened ? esc(code) : code}" size="45"><button>Tra</button></form>` + hint, hardened ? 'hardened' : 'vuln'));
    }

    // ---------- /api/reset/* (Reset token yếu — LAB-19) ----------
    if (path === '/api/reset/request' && req.method === 'GET') {
      const user = String(q.get('user') || '').slice(0, 40);
      const exists = !!db.findUser(user);
      if (hardened) {
        // Đã vá: token ngẫu nhiên 128-bit, lưu server-side, hết hạn 10 phút, dùng 1 lần.
        // Thực tế token được GỬI EMAIL — lab trả về để demo (đã đánh dấu demo_token).
        const t = crypto.randomBytes(16).toString('hex');
        if (exists) resetTokens.set(t, { user, exp: Date.now() + 600_000 });
        return json(res, 200, { ok: true, message: 'Nếu user tồn tại, link reset đã được "gửi email" (giả lập).', ...(exists ? { demo_token: t } : {}) });
      }
      // ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG: token = md5(username)[0:12] — hoàn toàn dự
      // đoán được, không lưu server, không hết hạn. Ai biết username là reset được.
      const token = crypto.createHash('md5').update(user).digest('hex').slice(0, 12);
      return json(res, 200, {
        ok: true,
        user,
        token,
        ghi_chu: 'Bản vuln: token = md5(username) cắt 12 ký tự — DỰ ĐOÁN ĐƯỢC. Tự tính md5 của "carol" rồi POST /api/reset/confirm để chiếm tài khoản.',
      });
    }
    if (path === '/api/reset/confirm' && req.method === 'POST') {
      const body = parseForm(await readBody(req, hardened ? 8 * 1024 : vulnModeNoLimit()));
      const { user = '', token = '' } = body;
      const newpass = String(body.newpass || 'pwned123').slice(0, 64);
      if (!db.findUser(user)) return json(res, 404, { error: 'not_found' });
      if (hardened) {
        const rec = resetTokens.get(token);
        if (!rec || rec.exp < Date.now() || rec.user !== user) {
          return json(res, 403, { error: 'invalid_token', message: 'Token sai, hết hạn hoặc đã dùng.' });
        }
        resetTokens.delete(token); // one-time use
      } else {
        const expect = crypto.createHash('md5').update(user).digest('hex').slice(0, 12);
        if (token !== expect) {
          return json(res, 403, { error: 'invalid_token', ghi_chu: 'Gợi ý: token = md5(username)[0:12].' });
        }
      }
      db.setPassword(user, newpass);
      return json(res, 200, { ok: true, message: `Đã đổi mật khẩu của ${esc(user)} → "${esc(newpass)}". Đăng nhập thử qua /login hoặc POST /api/token.` });
    }

    // ---------- /dom (DOM-based XSS — LAB-20) ----------
    if (path === '/dom' && req.method === 'GET') {
      // ĐIỂM ĐẶC BIỆT: payload nằm trong location.hash — phần sau dấu # KHÔNG BAO
      // GIỜ được gửi lên server → không xuất hiện trong access log → detect/
      // WAF/logs không nhìn thấy. Đây là lý do DOM XSS khó phát hiện phía server.
      const sink = hardened ? 'textContent' : 'innerHTML';
      const body = `
        <p>Trang này đọc <code>location.hash</code> (phần sau dấu #) và render bằng
        <code>${sink}</code>. Payload KHÔNG lên tới server — XSS hoàn toàn phía client.</p>
        <div id="out" style="border:1px solid #334155;padding:12px;min-height:40px"></div>
        ${hardened
          ? '<p>Đã vá: <code>textContent</code> chỉ chèn TEXT — markup hiển thị nguyên văn, không chạy.</p>'
          : '<p>Thử: <a href="/dom#&lt;img%20src=x%20onerror=alert(document.domain)&gt;">/dom#&lt;img src=x onerror=alert(document.domain)&gt;</a> — innerHTML thực thi markup độc.</p>'}
        <script>
          document.getElementById('out').${sink} =
            decodeURIComponent(location.hash.slice(1) || '(hash rỗng — thêm #nội-dung vào URL)');
        </script>`;
      return html(res, 200, page('DOM XSS demo', body, hardened ? 'hardened' : 'vuln'));
    }

    // ---------- /_lab/metrics ----------
    if (path === '/_lab/metrics' && req.method === 'GET') {
      return json(res, 200, { ...metrics, mode: hardened ? 'hardened' : 'vuln' });
    }

    // ---------- /_lab/log — dữ liệu cho bài blue-team (module detect) ----------
    if (path === '/_lab/log' && req.method === 'GET') {
      return json(res, 200, { log: reqLog, mode: hardened ? 'hardened' : 'vuln' });
    }

    // ---------- /_lab/challenges — chế độ CTF ----------
    if (path === '/_lab/challenges' && req.method === 'GET') {
      const list = CHALLENGE_DEFS.map((c) => ({ id: c.id, title: c.title, points: c.points, hint: c.hint, solved: ctf.solved.has(c.id) }));
      return json(res, 200, { enabled: ctf.enabled, challenges: list, score: ctf.score, total: TOTAL_POINTS });
    }

    // ---------- /_lab/verify — nộp cờ CTF (so sánh thời gian hằng) ----------
    if (path === '/_lab/verify' && req.method === 'GET') {
      const id = Number(q.get('id'));
      const flag = String(q.get('flag') || '').trim();
      const def = CHALLENGE_DEFS.find((c) => c.id === id);
      if (!def) return json(res, 404, { error: 'not_found' });
      if (!ctf.enabled) {
        return json(res, 403, {
          ok: false,
          error: 'ctf_disabled',
          message: 'Bản HARDENED đã vá lỗ hổng nên KHÔNG THỂ lấy cờ — đó chính là bài học của chế độ CTF.',
        });
      }
      const expected = ctf.flags[def.flagKey];
      const okFlag =
        expected !== undefined &&
        flag.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(flag), Buffer.from(expected));
      if (okFlag) ctf.solved.add(id);
      ctf.score = [...ctf.solved].reduce((s, cid) => s + (CHALLENGE_DEFS.find((c) => c.id === cid)?.points || 0), 0);
      return json(res, 200, { ok: okFlag, challenge: def.id, solved: [...ctf.solved], score: ctf.score, total: TOTAL_POINTS, count: CHALLENGE_DEFS.length });
    }

    // ---------- /files/ — directory listing (chỉ bản vuln) ----------
    if (path === '/files' || path === '/files/') {
      if (hardened) return json(res, 403, { error: 'forbidden', message: 'Directory listing đã bị tắt.' });
      const items = Object.keys(vfs)
        .filter((k) => k.startsWith('files/')) // file cờ ở gốc KHÔNG được liệt kê
        .map((k) => `<li><a href="/download?name=${encodeURIComponent(k.replace(/^files\//, ''))}">${k}</a></li>`)
        .join('');
      return html(res, 200, page('Index of /files/', `<h2>Index of /files/</h2><ul>${items}</ul>`, 'vuln'));
    }

    // ---------- /robots.txt ----------
    if (path === '/robots.txt') {
      return send(res, 200, 'User-agent: *\nDisallow: /admin\nDisallow: /secrets.txt\n', { 'Content-Type': 'text/plain' });
    }

    // ---------- 404 ----------
    if (hardened) {
      return html(res, 404, page('404', '<p>Không tìm thấy trang.</p>', 'hardened'));
    }
    // bản vuln: phản chiếu req.url thô → Reflected XSS ở trang 404 (LAB-02)
    return html(res, 404, page('404', `<p>Không tìm thấy: <b>${req.url}</b></p>`, 'vuln'));
  }

  function posixJoin(base, name) {
    const parts = `${base}/${name}`.split('/');
    const out = [];
    for (const part of parts) {
      if (part === '' || part === '.') continue;
      if (part === '..') {
        out.pop();
        continue;
      }
      out.push(part);
    }
    return out.join('/');
  }

  if (hardened) {
    // Chống slowloris / kết nối treo: giới hạn thời gian nhận header, body và giữ kết nối.
    server.headersTimeout = 4_000;
    server.requestTimeout = 10_000;
    server.keepAliveTimeout = 5_000;
    server.timeout = 8_000; // socket idle quá 8s → huỷ
  }
  server.mode = mode;
  server.labMetrics = metrics;
  return server;
}
