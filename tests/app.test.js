// Test tích hợp lab app: bản vuln phải dính probe, bản hardened phải chống lại được.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createLabApp } from '../src/lab/app.js';

async function start(mode) {
  const server = await createLabApp({ mode });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { server, url };
}

const vulnBox = {};
const hardBox = {};

before(async () => {
  Object.assign(vulnBox, await start('vuln'));
  Object.assign(hardBox, await start('hardened'));
});
after(() => {
  for (const b of [vulnBox, hardBox]) {
    b.server.close();
    b.server.closeAllConnections?.();
  }
});

const get = (base, path) => fetch(base + path, { signal: AbortSignal.timeout(8000) });

// ---------- BẢN VULN: lỗ hổng phải tồn tại ----------
test('vuln: SQLi boolean-based trả về toàn bộ người dùng', async () => {
  const res = await get(vulnBox.url, `/search?q=${encodeURIComponent("' OR 1=1 --")}`);
  const body = await res.text();
  const emails = body.match(/@lab\.local/g) || [];
  assert.ok(emails.length >= 4, `kỳ vọng >=4 email, thấy ${emails.length}`);
});

test('vuln: SQLi error-based lộ thông báo lỗi CSDL', async () => {
  const res = await get(vulnBox.url, `/search?q=${encodeURIComponent("'")}`);
  const body = await res.text();
  assert.match(body, /unrecognized token|syntax error|sqlite/i);
});

test('vuln: XSS phản chiếu nguyên văn payload', async () => {
  const marker = '<svg/onload=alert(1)>';
  const res = await get(vulnBox.url, `/search?q=${encodeURIComponent(marker)}`);
  assert.match(await res.text(), /<svg\/onload=alert\(1\)>/);
});

test('vuln: IDOR — đọc dữ liệu user khác khi chưa đăng nhập', async () => {
  const res = await get(vulnBox.url, '/api/users/2');
  const body = await res.text();
  assert.equal(res.status, 200);
  assert.match(body, /apiKey/);
});

test('vuln: path traversal đọc được secrets.txt (trên VFS ảo)', async () => {
  const res = await get(vulnBox.url, `/download?name=${encodeURIComponent('../secrets.txt')}`);
  assert.match(await res.text(), /LAB_SECRET/);
});

test('vuln: thiếu security headers', async () => {
  const res = await get(vulnBox.url, '/');
  assert.ok(!res.headers.has('content-security-policy'), 'vuln không được có CSP');
});

test('vuln: /admin mở tự do', async () => {
  const res = await get(vulnBox.url, '/admin');
  assert.equal(res.status, 200);
});

// ---------- BẢN HARDENED: phải chống lại được ----------
test('hardened: có đầy đủ security headers', async () => {
  const res = await get(hardBox.url, '/');
  assert.ok(res.headers.has('content-security-policy'));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
});

test('hardened: SQLi boolean-based không còn hiệu lực', async () => {
  const res = await get(hardBox.url, `/search?q=${encodeURIComponent("' OR 1=1 --")}`);
  const body = await res.text();
  const emails = body.match(/@lab\.local/g) || [];
  assert.ok(emails.length <= 1, `payload phải vô hiệu, thấy ${emails.length} email`);
});

test('hardened: XSS bị escape', async () => {
  const marker = '<svg/onload=alert(1)>';
  const res = await get(hardBox.url, `/search?q=${encodeURIComponent(marker)}`);
  const body = await res.text();
  assert.ok(!body.includes(marker), 'payload không được xuất hiện nguyên văn');
  assert.match(body, /&lt;svg/);
});

test('hardened: IDOR bị chặn (401 khi chưa đăng nhập)', async () => {
  const res = await get(hardBox.url, '/api/users/2');
  assert.equal(res.status, 401);
});

test('hardened: path traversal bị chặn', async () => {
  const res = await get(hardBox.url, `/download?name=${encodeURIComponent('../secrets.txt')}`);
  assert.equal(res.status, 400);
});

// (test /admin đặt TRƯỚC test burst — vì burst làm cạn bucket rate-limit của cùng IP)
test('hardened: /admin yêu cầu admin (403 khi chưa đăng nhập)', async () => {
  const res = await get(hardBox.url, '/admin');
  assert.equal(res.status, 403);
});

test('hardened: rate limiter chặn burst bằng 429', async () => {
  const responses = await Promise.all(
    Array.from({ length: 60 }, () => get(hardBox.url, '/').catch(() => null))
  );
  const limited = responses.filter((r) => r && r.status === 429).length;
  assert.ok(limited >= 10, `kỳ vọng >=10 lần 429, thực tế ${limited}`);
});
