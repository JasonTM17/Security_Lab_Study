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

test('vuln: command injection — chêm lệnh vào /tools/ping', async () => {
  const sep = process.platform === 'win32' ? '&' : ';';
  const marker = 'SECLABCMDIMARKER';
  const res = await get(vulnBox.url, `/tools/ping?host=${encodeURIComponent(`127.0.0.1 ${sep} echo ${marker}`)}`);
  assert.match(await res.text(), new RegExp(marker));
});

test('vuln: open redirect tới domain ngoài', async () => {
  const res = await fetch(vulnBox.url + '/redirect?to=' + encodeURIComponent('https://example.com'), { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location') || '', /example\.com/);
});

test('vuln: upload file .html được phục vụ như text/html', async () => {
  await fetch(vulnBox.url + '/upload', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'name=poc-test.html&content=' + encodeURIComponent('<script>alert(1)</script>'),
  });
  const res = await get(vulnBox.url, '/uploads/poc-test.html');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') || '', /text\/html/);
});

test('vuln: XXE đọc file qua entity trên VFS ảo', async () => {
  const res = await fetch(vulnBox.url + '/api/import', {
    method: 'POST',
    body: '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///secrets.txt">]><i><item>&x;</item></i>',
  });
  const j = await res.json();
  assert.match(j.items[0], /LAB_SECRET/);
});

test('vuln: guestbook lưu và render XSS không escape', async () => {
  await fetch(vulnBox.url + '/guestbook', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'msg=' + encodeURIComponent('<svg/onload=alert(9)>'),
  });
  const res = await get(vulnBox.url, '/guestbook');
  assert.match(await res.text(), /<svg\/onload=alert\(9\)>/);
});

test('vuln: /settings/email đổi email không cần CSRF token', async () => {
  const login = await fetch(vulnBox.url + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=bob&password=bob45678',
    redirect: 'manual',
  });
  const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
  const res = await fetch(vulnBox.url + '/settings/email', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', Cookie: `session=${sid}`, Origin: 'https://evil.example' },
    body: 'email=pwned@evil.example',
  });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /pwned@evil\.example/);
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

test('hardened: command injection bị whitelist chặn, ping hợp lệ vẫn chạy', async () => {
  const sep = process.platform === 'win32' ? '&' : ';';
  const bad = await get(hardBox.url, `/tools/ping?host=${encodeURIComponent(`127.0.0.1 ${sep} whoami`)}`);
  assert.equal(bad.status, 400);
  const ok = await get(hardBox.url, '/tools/ping?host=127.0.0.1');
  assert.equal(ok.status, 200);
});

test('hardened: open redirect tới domain ngoài → 400, path nội bộ → 302', async () => {
  const ext = await fetch(hardBox.url + '/redirect?to=' + encodeURIComponent('https://example.com'), { redirect: 'manual' });
  assert.equal(ext.status, 400);
  const local = await fetch(hardBox.url + '/redirect?to=/slow', { redirect: 'manual' });
  assert.equal(local.status, 302);
});

test('hardened: upload .html → 415, .txt → 200 nhưng ép text/plain', async () => {
  const bad = await fetch(hardBox.url + '/upload', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'name=poc.html&content=x',
  });
  assert.equal(bad.status, 415);
  const ok = await fetch(hardBox.url + '/upload', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'name=ok.txt&content=hello',
  });
  assert.equal(ok.status, 200);
  const served = await get(hardBox.url, '/uploads/ok.txt');
  assert.equal(served.headers.get('content-type'), 'text/plain; charset=utf-8');
});

test('hardened: XXE — DOCTYPE bị từ chối, XML thường vẫn parse', async () => {
  const bad = await fetch(hardBox.url + '/api/import', {
    method: 'POST',
    body: '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///secrets.txt">]><i><item>&x;</item></i>',
  });
  assert.equal(bad.status, 400);
  const ok = await fetch(hardBox.url + '/api/import', { method: 'POST', body: '<import><item>abc</item></import>' });
  const j = await ok.json();
  assert.deepEqual(j.items, ['abc']);
});

test('hardened: guestbook escape stored XSS', async () => {
  await fetch(hardBox.url + '/guestbook', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'msg=' + encodeURIComponent('<svg/onload=alert(9)>'),
  });
  const res = await get(hardBox.url, '/guestbook');
  const body = await res.text();
  assert.ok(!body.includes('<svg/onload=alert(9)>'));
  assert.match(body, /&lt;svg/);
});

test('hardened: /settings/email bắt buộc CSRF token (403 khi thiếu)', async () => {
  const login = await fetch(hardBox.url + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=bob&password=bob45678',
    redirect: 'manual',
  });
  const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
  const noTok = await fetch(hardBox.url + '/settings/email', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', Cookie: `session=${sid}` },
    body: 'email=pwned@evil.example',
  });
  assert.equal(noTok.status, 403);
  const settingsPage = await (await fetch(hardBox.url + '/settings', { headers: { Cookie: `session=${sid}` } })).text();
  const tok = settingsPage.match(/name="csrf" value="([a-f0-9]+)"/)?.[1];
  assert.ok(tok, 'form hardened phải nhúng CSRF token');
  const ok = await fetch(hardBox.url + '/settings/email', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', Cookie: `session=${sid}` },
    body: `email=ok@lab.local&csrf=${tok}`,
  });
  assert.equal(ok.status, 200);
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
