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
import http from 'node:http';
import crypto from 'node:crypto';
import { tokenBucketLimiter } from '../defense/ratelimiter.js';
import { securityHeaders } from '../defense/headers.js';
import { createLabDb } from '../db.js';

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
];
const TOTAL_POINTS = CHALLENGE_DEFS.reduce((s, c) => s + c.points, 0);

export function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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
<hr><p><a href="/">Trang chủ</a> · <a href="/search?q=alice">/search</a> · <a href="/login">/login</a> · <a href="/api/users/2">/api/users/2</a> · <a href="/download?name=readme.txt">/download</a> · <a href="/slow">/slow</a> · <a href="/_lab/metrics">/_lab/metrics</a></p></body></html>`;

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
  if (!hardened) {
    ctf.flags.sql = `FLAG{sqli-${randHex(6)}}`;
    ctf.flags.trav = `FLAG{trav-${randHex(6)}}`;
    ctf.flags.idor = `FLAG{idor-${randHex(6)}}`;
    ctf.flags.admin = `FLAG{admin-${randHex(6)}}`;
    // Người dùng ẩn: tên không khớp mọi từ khoá bình thường, chỉ lộ khi dump 1=1.
    db.addUser({ id: 99, name: 'zz_ctf_hidden', password: randHex(8), role: 'user', email: ctf.flags.sql, apiKey: 'LAB-KEY-CTF-0099' });
    db.setApiKey(4, ctf.flags.idor);
    vfs['flag-ctf.txt'] = `${ctf.flags.trav}\nCờ CTF — file ở GỐC, ngoài thư mục files/ được phép; chỉ đọc được qua path traversal.`;
  }

  // Log request phục vụ bài blue-team (module detect) — chỉ trong bộ nhớ, cap 500.
  const reqLog = [];

  const server = http.createServer(async (req, res) => {
    metrics.total += 1;
    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = u.pathname.replace(/\/+$/, '') || '/';
    metrics.byPath[path] = (metrics.byPath[path] || 0) + 1;
    reqLog.push({ t: Date.now(), method: req.method, path: u.pathname + u.search, ua: req.headers['user-agent'] || '' });
    if (reqLog.length > 500) reqLog.shift();

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

    // ---------- trang chủ ----------
    if (path === '/' && req.method === 'GET') {
      const items = [
        '<li><a href="/search?q=alice">/search?q=... — tìm người dùng (SQLi)</a></li>',
        '<li><a href="/login">/login — đăng nhập (SQLi bypass)</a></li>',
        '<li><a href="/api/users/2">/api/users/:id — dữ liệu người dùng (IDOR)</a></li>',
        '<li><a href="/download?name=readme.txt">/download?name=... — tải file (Path Traversal)</a></li>',
        '<li><a href="/slow">/slow — endpoint chậm 3s (demo tải)</a></li>',
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
      return json(res, 200, session ? { ...session } : { user: null });
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
      return json(res, 200, { ok: okFlag, challenge: def.id, solved: [...ctf.solved], score: ctf.score, total: TOTAL_POINTS });
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
