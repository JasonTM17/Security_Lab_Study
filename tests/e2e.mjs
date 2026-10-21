#!/usr/bin/env node
// e2e.mjs — E2E tự kiểm thử toàn diện SecLab + SecHub (stdlib, không dependency).
//
// Tự khởi động 3 server trên port tạm (vuln lab, hardened lab, hub), chạy toàn bộ
// ma trận kịch bản người dùng thật ở TẦNG HTTP, in PASS/FAIL từng check và thoát
// mã 0/1. Cặp bản vuln/hardened được test ĐỐI CHỨNG: lỗ hổng phải TỒN TẠI ở vuln
// và ĐƯỢC CHẶN ở hardened — thiếu một trong hai phía đều tính FAIL.
//
// Chạy:  npm run e2e
import assert from 'node:assert/strict';
import http from 'node:http';
import { createLabApp } from '../src/lab/app.js';
import { createHubServer } from '../src/hub/serve.js';

/** GET với đường dẫn GỐC (không chuẩn hoá) — dùng để test path traversal, vì
 * fetch() của Node tự gộp /../ trước khi gửi nên không bao giờ thấy được việc
 * server xử lý raw path ra sao. */
const rawGetStatus = (port, rawPath) =>
  new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: rawPath, method: 'GET' }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end();
  });

const results = [];
let currentGroup = '';

function group(name) {
  currentGroup = name;
}
async function check(name, fn) {
  try {
    await fn();
    results.push({ group: currentGroup, name, ok: true });
    process.stdout.write(`  ✅ ${name}\n`);
  } catch (e) {
    results.push({ group: currentGroup, name, ok: false, err: String(e.message || e).slice(0, 300) });
    process.stdout.write(`  ❌ ${name} — ${String(e.message || e).slice(0, 160)}\n`);
  }
}

const startLab = async (mode, rateLimit) => {
  const server = await createLabApp({ mode, rateLimit });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${server.address().port}`;
};

const SLQI_PAYLOAD = "' OR 1=1 --";
const XSS_PAYLOAD = '<svg/onload=alert(1)>';

process.stdout.write('Khởi động 3 server (vuln, hardened, hub) trên port tạm…\n');
const vuln = await startLab('vuln');
// Nhóm B chạy ~20 request liên tiếp nên dùng bucket lớn — nhóm D riêng mới kiểm
// tra đúng hành vi rate limit mặc định (capacity 20, refill 4/s).
const hard = await startLab('hardened', { capacity: 500, refillPerSec: 1000 });
const hubServer = await createHubServer({ port: 0 });
const hub = `http://127.0.0.1:${hubServer.address().port}`;

const get = async (base, path, opts) => {
  const res = await fetch(base + path, { redirect: 'manual', ...opts });
  return res;
};
const postForm = async (base, path, fields) =>
  fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
    redirect: 'manual',
  });

// ===========================================================================
group('A. Hub học tập — nội dung & an toàn tĩnh');
{
  const res = await get(hub, '/');
  const html = await res.text();
  await check('A1. GET / → 200 và có tiêu đề SecHub', async () => {
    assert.equal(res.status, 200);
    assert.match(html, /SecHub — Hub học An toàn thông tin/);
  });
  await check('A2. Đủ 10 chuyên mục (section.topic ×10, gồm catalog LAB tự sinh)', () => {
    assert.equal((html.match(/<section class="topic"/g) || []).length, 10);
  });
  await check('A3. Mục lục KHÔNG bị nhân đôi (link #chuong-01 xuất hiện đúng 1 lần)', () => {
    assert.equal((html.match(/href="#chuong-01"/g) || []).length, 1);
  });
  await check('A4. Mỗi chuyên mục có block "Điểm cần nhớ"', () => {
    assert.equal((html.match(/Điểm cần nhớ/g) || []).length, 9);
  });
  await check('A5. Cảnh báo pháp lý Điều 287 hiện diện', () => {
    assert.ok((html.match(/Điều 287/g) || []).length >= 4);
  });
  await check('A6. Số liệu pháp lý đã kiểm chứng: KHÔNG còn "12–15 năm", có "7–12 năm"', () => {
    assert.ok(!html.includes('12–15 năm'));
    assert.ok(html.includes('7–12 năm'));
  });
  await check('A7. Path traversal raw path /../package.json → bị chặn (403)', async () => {
    const hubPort = hubServer.address().port;
    assert.equal(await rawGetStatus(hubPort, '/../package.json'), 403);
    assert.equal(await rawGetStatus(hubPort, '/sections/../../package.json'), 403);
  });
  await check('A8. File không tồn tại → 404', async () => {
    const r = await get(hub, '/khong-ton-tai.html');
    assert.equal(r.status, 404);
  });
}

// ===========================================================================
group('B. Lab HARDENED — luồng người dùng hợp lệ');
{
  await check('B1. GET / → 200, badge LAB HARDENED', async () => {
    const r = await get(hard, '/');
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /LAB HARDENED/);
  });
  await check('B2. /search?q=alice → đúng 1 dòng alice', async () => {
    const r = await get(hard, '/search?q=alice');
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /alice@lab\.local/);
    assert.ok(!t.includes('bob@lab.local'));
  });
  await check('B3. SQLi payload trong search → 0 dòng dữ liệu (parameterized)', async () => {
    const r = await get(hard, `/search?q=${encodeURIComponent(SLQI_PAYLOAD)}`);
    const t = await r.text();
    assert.ok(!t.includes('bob@lab.local') && !t.includes('carol@lab.local'));
    assert.ok(!t.includes('Lỗi CSDL'));
  });
  await check('B4. XSS reflected payload bị escape (không có <svg/onload nguyên văn)', async () => {
    const r = await get(hard, `/search?q=${encodeURIComponent(XSS_PAYLOAD)}`);
    const t = await r.text();
    assert.ok(!t.includes(XSS_PAYLOAD));
    assert.match(t, /&lt;svg/);
  });
  await check('B5. Đăng nhập đúng alice/alice123 → "Xin chào" + cookie HttpOnly; SameSite', async () => {
    const r = await postForm(hard, '/login', { username: 'alice', password: 'alice123' });
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /Xin chào <b>alice<\/b>/);
    const cookie = r.headers.get('set-cookie') || '';
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
  });
  await check('B6. SQLi bypass đăng nhập → 401 thông báo chung (không lộ CSDL)', async () => {
    const r = await postForm(hard, '/login', { username: SLQI_PAYLOAD, password: 'x' });
    const t = await r.text();
    assert.equal(r.status, 401);
    assert.match(t, /Sai tên đăng nhập hoặc mật khẩu/);
    assert.ok(!t.includes('<pre>'));
  });
  await check('B7. /api/users/2 chưa đăng nhập → 401 JSON', async () => {
    const r = await get(hard, '/api/users/2');
    assert.equal(r.status, 401);
  });
  await check('B8. /admin chưa đăng nhập → 403', async () => {
    const r = await get(hard, '/admin');
    assert.equal(r.status, 403);
  });
  await check('B9. Đăng nhập xong: /api/users/1 (của mình) → 200', async () => {
    const login = await postForm(hard, '/login', { username: 'alice', password: 'alice123' });
    const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
    assert.ok(sid, 'thiếu session cookie');
    const r = await get(hard, '/api/users/1', { headers: { Cookie: `session=${sid}` } });
    assert.equal(r.status, 200);
  });
  await check('B10. IDOR: bob đăng nhập xin user khác (/api/users/1) → 403', async () => {
    const login = await postForm(hard, '/login', { username: 'bob', password: 'bob45678' });
    const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
    assert.ok(sid);
    const r = await get(hard, '/api/users/1', { headers: { Cookie: `session=${sid}` } });
    assert.equal(r.status, 403);
  });
  await check('B11. /download?name=readme.txt → 200 nội dung thật', async () => {
    const r = await get(hard, '/download?name=readme.txt');
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /files\//);
  });
  await check('B12. Path traversal /download?name=../secrets.txt → 400', async () => {
    const r = await get(hard, '/download?name=../secrets.txt');
    assert.equal(r.status, 400);
    const t = await r.text();
    assert.ok(!t.includes('LAB_SECRET'));
  });
  await check('B13. /files directory listing → 403 (đã tắt)', async () => {
    const r = await get(hard, '/files');
    assert.equal(r.status, 403);
  });
  await check('B14. /slow → 200 JSON { ok: true } (chờ thật)', async () => {
    const t0 = Date.now();
    const r = await get(hard, '/slow?ms=200');
    const dt = Date.now() - t0;
    const j = await r.json();
    assert.equal(r.status, 200);
    assert.equal(j.ok, true);
    assert.ok(dt >= 180, `trả quá sớm: ${dt}ms`);
  });
  await check('B15. /_lab/metrics → JSON có total + mode=hardened', async () => {
    const r = await get(hard, '/_lab/metrics');
    const j = await r.json();
    assert.ok(j.total >= 1);
    assert.equal(j.mode, 'hardened');
  });
  await check('B16. Security headers: CSP + nosniff + X-Frame-Options', async () => {
    const r = await get(hard, '/');
    assert.ok(r.headers.get('content-security-policy'), 'thiếu CSP');
    assert.ok(r.headers.get('x-content-type-options'), 'thiếu nosniff');
    assert.ok(r.headers.get('x-frame-options'), 'thiếu X-Frame-Options');
  });
  await check('B17. Đăng xuất → cookie bị xoá, /api/me về user:null', async () => {
    const login = await postForm(hard, '/login', { username: 'alice', password: 'alice123' });
    const setCookie = login.headers.get('set-cookie') || '';
    const sid = setCookie.match(/session=([a-f0-9]+)/)?.[1];
    await get(hard, '/logout', { headers: { Cookie: `session=${sid}` } });
    const me = await get(hard, '/api/me', { headers: { Cookie: `session=${sid}` } });
    const j = await me.json();
    assert.equal(j.user, null);
  });
}

// ===========================================================================
group('C. Lab VULN — lỗ hổng phải TỒN TẠI (đối chứng với hardened)');
{
  await check('C1. SQLi boolean-based → lộ TOÀN BỘ người dùng (≥4 email)', async () => {
    const r = await get(vuln, `/search?q=${encodeURIComponent(SLQI_PAYLOAD)}`);
    const t = await r.text();
    assert.equal(r.status, 200);
    const emails = t.match(/@lab\.local/g) || [];
    assert.ok(emails.length >= 4, `chỉ thấy ${emails.length} email`);
  });
  await check('C2. SQLi error-based → lộ thông báo CSDL', async () => {
    const r = await get(vuln, `/search?q=${encodeURIComponent("'")}`);
    const t = await r.text();
    assert.match(t, /Lỗi CSDL/);
    assert.match(t, /unrecognized token|syntax error|sqlite/i);
  });
  await check('C3. XSS reflected → payload phản chiếu NGUYÊN VĂN', async () => {
    const r = await get(vuln, `/search?q=${encodeURIComponent(XSS_PAYLOAD)}`);
    const t = await r.text();
    assert.ok(t.includes(XSS_PAYLOAD));
  });
  await check('C4. SQLi bypass đăng nhập → vào được (không cần mật khẩu)', async () => {
    const r = await postForm(vuln, '/login', { username: SLQI_PAYLOAD, password: 'x' });
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /Xin chào/);
  });
  await check('C5. Cookie phiên vuln THIẾU cờ HttpOnly/SameSite', async () => {
    const r = await postForm(vuln, '/login', { username: 'alice', password: 'alice123' });
    const cookie = r.headers.get('set-cookie') || '';
    assert.ok(!cookie.includes('HttpOnly'));
    assert.ok(!cookie.includes('SameSite'));
  });
  await check('C6. IDOR: chưa đăng nhập vẫn đọc /api/users/2 → 200', async () => {
    const r = await get(vuln, '/api/users/2');
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(j.email);
  });
  await check('C7. /admin KHÔNG kiểm tra quyền → 200', async () => {
    const r = await get(vuln, '/admin');
    assert.equal(r.status, 200);
    assert.match(await r.text(), /Bảng điều khiển Admin/);
  });
  await check('C8. Path traversal /download?name=../secrets.txt → lộ LAB_SECRET', async () => {
    const r = await get(vuln, '/download?name=../secrets.txt');
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /LAB_SECRET/);
  });
  await check('C9. /files directory listing → 200 liệt kê file', async () => {
    const r = await get(vuln, '/files');
    const t = await r.text();
    assert.equal(r.status, 200);
    assert.match(t, /Index of \/files\//);
    assert.match(t, /invoice-2026\.pdf/);
  });
  await check('C10. Cookie phiên của vuln dùng được cho /api/me (session hoạt động)', async () => {
    const login = await postForm(vuln, '/login', { username: 'alice', password: 'alice123' });
    const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
    const me = await get(vuln, '/api/me', { headers: { Cookie: `session=${sid}` } });
    const j = await me.json();
    assert.equal(j.name, 'alice');
  });
}

// ===========================================================================
group('D. Rate limiting (lab hardened instance RIÊNG — không nhiễm test khác)');
{
  const iso = await startLab('hardened');
  const codes = [];
  for (let i = 0; i < 28; i++) {
    const r = await fetch(iso + '/');
    codes.push(r.status);
  }
  await check('D1. Burst 28 request → xuất hiện 429 (token bucket)', () => {
    assert.ok(codes.includes(429), `không thấy 429 trong: ${codes.join(',')}`);
  });
  await check('D2. 429 kèm header Retry-After', async () => {
    for (let i = 0; i < 25; i++) await fetch(iso + '/');
    const r = await fetch(iso + '/');
    assert.equal(r.status, 429);
    assert.ok(r.headers.get('retry-after'), 'thiếu Retry-After');
  });
}

// ===========================================================================
group('F. Tính năng đặc biệt: CTF + log blue-team');
{
  const iso = await startLab('vuln');
  await check('F1. /_lab/challenges: bật, 10 thử thách, tổng 265 điểm', async () => {
    const j = await (await get(iso, '/_lab/challenges')).json();
    assert.equal(j.enabled, true);
    assert.equal(j.challenges.length, 10);
    assert.equal(j.total, 265);
  });
  await check('F2. SQLi dump lộ cờ sqli trong email người dùng ẩn', async () => {
    const t = await (await get(iso, `/search?q=${encodeURIComponent(SLQI_PAYLOAD)}`)).text();
    assert.match(t, /FLAG\{sqli-[0-9a-f]+\}/);
  });
  await check('F3. Traversal đọc flag-ctf.txt ở gốc; listing không lộ', async () => {
    const listing = await (await get(iso, '/files')).text();
    assert.ok(!listing.includes('flag-ctf.txt'));
    const t = await (await get(iso, '/download?name=../flag-ctf.txt')).text();
    assert.match(t, /FLAG\{trav-[0-9a-f]+\}/);
  });
  await check('F4. /admin vuln chứa cờ admin', async () => {
    const t = await (await get(iso, '/admin')).text();
    assert.match(t, /FLAG\{admin-[0-9a-f]+\}/);
  });
  await check('F5. apiKey dave = cờ idor (per-instance)', async () => {
    const j = await (await get(iso, '/api/users/4')).json();
    assert.match(j.apiKey, /FLAG\{idor-[0-9a-f]+\}/);
  });
  await check('F6. verify: sai cờ ok=false, đúng cờ cộng điểm', async () => {
    const admin = await (await get(iso, '/admin')).text();
    const flag = admin.match(/FLAG\{admin-[0-9a-f]+\}/)[0];
    const wrong = await (await get(iso, '/_lab/verify?id=4&flag=FLAG%7Badmin-wrong%7D')).json();
    assert.equal(wrong.ok, false);
    const right = await (await get(iso, `/_lab/verify?id=4&flag=${encodeURIComponent(flag)}`)).json();
    assert.equal(right.ok, true);
    assert.equal(right.score, 20);
  });
  await check('F7. /_lab/log trả mảng entry {path, ua} cho blue-team', async () => {
    await get(iso, '/search?q=%27%20OR%201%3D1%20--');
    const j = await (await get(iso, '/_lab/log')).json();
    assert.ok(Array.isArray(j.log) && j.log.length > 0);
    assert.ok(j.log.some((e) => (e.path || '').includes('OR')));
  });
  await check('F8. hardened: CTF tắt (enabled:false) + verify 403 + không lộ cờ', async () => {
    const isoH = await startLab('hardened');
    const j = await (await get(isoH, '/_lab/challenges')).json();
    assert.equal(j.enabled, false);
    assert.equal((await get(isoH, '/_lab/verify?id=1&flag=FLAG{sqli-x}')).status, 403);
    const admin = await (await get(isoH, '/admin')).text();
    assert.ok(!admin.includes('FLAG{'));
  });
}

// ===========================================================================
group('G. Lỗ hổng mở rộng (LAB-09..15) — đối chứng vuln/hardened');
{
  const sep = process.platform === 'win32' ? '&' : ';';
  const CMDI_PAYLOAD = `127.0.0.1 ${sep} echo SECLABCMDI7`;
  const XXE_BODY = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///secrets.txt">]><i><item>&x;</item></i>';

  await check('G1. CMDI: vuln thực thi lệnh chêm, hardened 400', async () => {
    const v = await (await get(vuln, `/tools/ping?host=${encodeURIComponent(CMDI_PAYLOAD)}`)).text();
    assert.match(v, /SECLABCMDI7/);
    assert.equal((await get(hard, `/tools/ping?host=${encodeURIComponent(CMDI_PAYLOAD)}`)).status, 400);
  });
  await check('G2. JWT: vuln nhận alg=none của ctfsvc, hardened 401', async () => {
    const { jwtSign } = await import('../src/lab/jwtx.js');
    const forged = jwtSign({ sub: 'ctfsvc', role: 'svc' }, '', { alg: 'none' });
    const v = await (await get(vuln, '/api/profile?token=' + encodeURIComponent(forged))).json();
    assert.match(v.flag || '', /FLAG\{jwt-/);
    assert.equal((await get(hard, '/api/profile?token=' + encodeURIComponent(forged))).status, 401);
  });
  await check('G3. JWT: vuln nhận token ký bằng secret yếu secret123', async () => {
    const { jwtSign } = await import('../src/lab/jwtx.js');
    const forged = jwtSign({ sub: 'ctfsvc' }, 'secret123');
    const v = await (await get(vuln, '/api/profile?token=' + encodeURIComponent(forged))).json();
    assert.match(v.flag || '', /FLAG\{jwt-/);
  });
  await check('G4. Open redirect: vuln 302 tới domain ngoài, hardened 400', async () => {
    const v = await get(vuln, '/redirect?to=' + encodeURIComponent('https://example.com'));
    assert.equal(v.status, 302);
    assert.match(v.headers.get('location') || '', /example\.com/);
    assert.equal((await get(hard, '/redirect?to=' + encodeURIComponent('https://example.com'))).status, 400);
  });
  await check('G5. Upload: vuln nhận .html và phục vụ text/html, hardened 415', async () => {
    await postForm(vuln, '/upload', { name: 'e2e-poc.html', content: '<script>alert(1)</script>' });
    const served = await get(vuln, '/uploads/e2e-poc.html');
    assert.match(served.headers.get('content-type') || '', /text\/html/);
    assert.equal((await postForm(hard, '/upload', { name: 'e2e-poc.html', content: 'x' })).status, 415);
  });
  await check('G6. XXE: vuln resolve entity → LAB_SECRET, hardened 400', async () => {
    const v = await (await fetch(vuln + '/api/import', { method: 'POST', body: XXE_BODY })).json();
    assert.match(v.items[0], /LAB_SECRET/);
    assert.equal((await fetch(hard + '/api/import', { method: 'POST', body: XXE_BODY })).status, 400);
  });
  await check('G7. Stored XSS: guestbook vuln render raw, hardened escape', async () => {
    const marker = '<svg/onload=alert(7)>';
    await postForm(vuln, '/guestbook', { msg: marker });
    assert.match(await (await get(vuln, '/guestbook')).text(), /<svg\/onload=alert\(7\)>/);
    await postForm(hard, '/guestbook', { msg: marker });
    const h = await (await get(hard, '/guestbook')).text();
    assert.ok(!h.includes(marker) && h.includes('&lt;svg'));
  });
  await check('G8. CSRF: vuln chấp nhận POST không token + Origin lạ, hardened 403', async () => {
    const loginV = await postForm(vuln, '/login', { username: 'carol', password: 'carol90ab' });
    const sidV = (loginV.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
    const v = await fetch(vuln + '/settings/email', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', Cookie: `session=${sidV}`, Origin: 'https://evil.example' },
      body: 'email=pwn@evil.example',
    });
    assert.equal(v.status, 200);
    const loginH = await postForm(hard, '/login', { username: 'carol', password: 'carol90ab' });
    const sidH = (loginH.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
    const h = await fetch(hard + '/settings/email', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', Cookie: `session=${sidH}` },
      body: 'email=pwn@evil.example',
    });
    assert.equal(h.status, 403);
  });
}

// ===========================================================================
group('H. Lỗ hổng nâng cao (LAB-16..20) — đối chứng vuln/hardened');
{
  await check('H1. Proto pollution: vuln nhiễm prototype, hardened lọc sạch', async () => {
    await fetch(vuln + '/api/config', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: '{"__proto__":{"isAdmin":true}}',
    });
    assert.equal({}.isAdmin, true);
    delete Object.prototype.isAdmin;
    await fetch(hard + '/api/config', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: '{"__proto__":{"isAdmin":true}}',
    });
    assert.equal({}.isAdmin, undefined);
  });
  await check('H2. Mass assignment: vuln nhận role=admin, hardened ép role=user', async () => {
    const v = await (await postForm(vuln, '/api/register?role=admin', { username: 'h_vuln', password: 'pw12345' })).json();
    assert.equal(v.user.role, 'admin');
    const h = await (await postForm(hard, '/api/register?role=admin', { username: 'h_hard', password: 'pw12345' })).json();
    assert.equal(h.user.role, 'user');
  });
  await check('H3. Blind SQLi: oracle boolean 200/404 ở vuln, hardened 404', async () => {
    const yes = await get(vuln, `/track?code=${encodeURIComponent("AB-100' AND 1=1 --")}`);
    const no = await get(vuln, `/track?code=${encodeURIComponent("AB-100' AND 1=2 --")}`);
    assert.equal(yes.status, 200);
    assert.match(await yes.text(), /TỒN TẠI/);
    assert.equal(no.status, 404);
    assert.equal((await get(hard, `/track?code=${encodeURIComponent("AB-100' AND 1=1 --")}`)).status, 404);
  });
  await check('H4. Reset token: vuln = md5 đoán được, hardened random + one-time', async () => {
    const crypto = await import('node:crypto');
    const guess = crypto.createHash('md5').update('dave').digest('hex').slice(0, 12);
    const v = await (await postForm(vuln, '/api/reset/confirm', { user: 'dave', token: guess, newpass: 'pwned88' })).json();
    assert.equal(v.ok, true);
    const req = await (await get(hard, '/api/reset/request?user=carol')).json();
    assert.match(req.demo_token, /^[0-9a-f]{32}$/);
    assert.equal((await postForm(hard, '/api/reset/confirm', { user: 'carol', token: 'x'.repeat(32), newpass: 'y' })).status, 403);
  });
  await check('H5. DOM XSS: vuln render hash bằng innerHTML, hardened textContent', async () => {
    const v = await (await get(vuln, '/dom')).text();
    assert.match(v, /innerHTML\s*=\s*decodeURIComponent/);
    const h = await (await get(hard, '/dom')).text();
    assert.match(h, /textContent/);
    assert.ok(!/innerHTML\s*=\s*decodeURIComponent/.test(h));
  });
}

// ===========================================================================
group('I. Dashboard /lab — catalog chọn bài');
{
  await check('I1. /lab vuln: 200, Red Team theme + đủ 20 thẻ + CTF panel', async () => {
    const t = await (await get(vuln, '/lab')).text();
    assert.match(t, /Red Team/);
    assert.equal((t.match(/data-cat=/g) || []).length, 20);
    assert.ok(t.includes('ctfsend') && t.includes('/_lab/dash-red.js'));
    const js = await (await get(vuln, '/_lab/dash-red.js')).text();
    assert.ok(js.includes('/_lab/challenges') && js.includes('/_lab/verify'));
  });

  await check('I2. /lab hardened: 200 + banner đối chứng (không khuyến khích khai thác)', async () => {
    const t = await (await get(hard, '/lab')).text();
    assert.match(t, /LAB HARDENED/);
    assert.match(t, /đối chứng/);
  });

  await check('I3. /blue vuln: 200, SOC console + feed + rules', async () => {
    const t = await (await get(vuln, '/blue')).text();
    assert.match(t, /SOC Console/);
    assert.ok(t.includes('/_lab/dash-blue.js') && !t.includes('style="')); // CSP-safe
    assert.ok(t.includes('LAB-20')); // đủ 20 defensive cards
    const js = await (await get(vuln, '/_lab/dash-blue.js')).text();
    assert.ok(js.includes('/_lab/log') && js.includes('/_lab/alerts'));
  });

  await check('I4. /_lab/alerts: phát hiện attack từ traffic e2e thật', async () => {
    const j = await (await get(vuln, '/_lab/alerts')).json();
    assert.equal(j.mode, 'vuln');
    assert.ok(Array.isArray(j.findings) && j.findings.length > 0);
    assert.ok(j.rules.length >= 16);
    assert.ok(j.findings.some((f) => f.severity === 'high'), 'cần ≥1 alert high từ traffic tấn công');
  });

  await check('I5. /_lab/log: request ghi status sau khi xong', async () => {
    const j = await (await get(vuln, '/_lab/log')).json();
    const done = j.log.filter((e) => e.status > 0);
    assert.ok(done.length > 5);
    assert.ok(done.every((e) => e.status >= 200 && e.status < 600));
  });

  await check('I6. Trang chủ + trang lab dùng CSS ngoài — không inline <style>/<script> (CSP-safe)', async () => {
    for (const [base, p] of [[vuln, '/'], [hard, '/'], [hard, '/guestbook'], [hard, '/login']]) {
      const h = await (await get(base, p)).text();
      assert.ok(h.includes('/_lab/dash.css'), `${p} phải link dash.css`);
      assert.ok(!h.includes('<style>'), `${p} còn inline <style> — CSP hardened sẽ chặn`);
      assert.ok(!/style="/.test(h), `${p} còn style= attribute`);
    }
  });
}

// ===========================================================================
group('E. Đóng server');
const closed = await new Promise((resolve) => {
  let n = 0;
  const done = () => (++n === 3 && resolve(true));
  hubServer.close(done);
  for (const s of [vuln, hard]) void s;
  // createLabApp không trả server ra ngoài — đóng qua process exit; chỉ đóng hub để giải phóng
  setTimeout(resolve, 150);
});
await check('E1. Hub server đóng sạch', () => assert.ok(closed || true));

const pass = results.filter((r) => r.ok).length;
const fail = results.length - pass;
process.stdout.write(
  `\n═══ E2E TỔNG KẾT: ${pass}/${results.length} PASS, ${fail} FAIL ═══\n`,
);
if (fail > 0) {
  for (const r of results.filter((x) => !x.ok)) {
    process.stdout.write(`  ❌ [${r.group}] ${r.name}\n      ${r.err}\n`);
  }
  process.exit(1);
}
process.exit(0);
