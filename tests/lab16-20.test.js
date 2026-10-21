// Test đối chứng LAB-16..20: bản vuln phải dính, bản hardened phải chặn.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createLabApp } from '../src/lab/app.js';

async function start(mode) {
  const server = await createLabApp({ mode });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
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

const get = (base, path, opts) => fetch(base + path, { signal: AbortSignal.timeout(8000), ...opts });
const post = (base, path, body, headers = { 'content-type': 'application/x-www-form-urlencoded' }) =>
  fetch(base + path, { method: 'POST', headers, body, signal: AbortSignal.timeout(8000) });

// ---------- LAB-16 Prototype Pollution ----------
test('LAB-16 vuln: POST __proto__.isAdmin nhiễm prototype toàn cục', async () => {
  const res = await post(vulnBox.url, '/api/config', '{"__proto__":{"isAdmin":true}}', {
    'content-type': 'application/json',
  });
  const j = await res.json();
  assert.equal(j.ok, true);
  assert.equal({}.isAdmin, true, 'Object.prototype phải bị nhiễm thật');
  delete Object.prototype.isAdmin;
});

test('LAB-16 vuln: GET /api/config sau khi pollute → protoPolluted + cờ', async () => {
  await post(vulnBox.url, '/api/config', '{"__proto__":{"isAdmin":true}}', {
    'content-type': 'application/json',
  });
  const j = await (await get(vulnBox.url, '/api/config')).json();
  assert.ok(j.protoPolluted.includes('isAdmin'));
  assert.match(j.flag, /FLAG\{proto-[0-9a-f]+\}/);
  delete Object.prototype.isAdmin;
});

test('LAB-16 hardened: __proto__ bị lọc, protoPolluted rỗng, không cờ', async () => {
  const res = await post(hardBox.url, '/api/config', '{"__proto__":{"isAdmin":true}}', {
    'content-type': 'application/json',
  });
  const j = await res.json();
  assert.equal(j.ok, true);
  const cfg = await (await get(hardBox.url, '/api/config')).json();
  assert.deepEqual(cfg.protoPolluted, []);
  assert.equal(cfg.flag, undefined);
  assert.equal({}.isAdmin, undefined);
});

// ---------- LAB-17 Mass Assignment ----------
test('LAB-17 vuln: đăng ký kèm role=admin → user nhận quyền admin', async () => {
  const j = await (await post(vulnBox.url, '/api/register?role=admin', 'username=massign1&password=pw12345')).json();
  assert.equal(j.user.role, 'admin');
  assert.equal(j.ok, true);
});

test('LAB-17 vuln: admin giả login → /api/me lộ cờ mass', async () => {
  await post(vulnBox.url, '/api/register?role=admin', 'username=massign2&password=pw12345');
  const login = await post(vulnBox.url, '/login', 'username=massign2&password=pw12345');
  const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
  assert.ok(sid, 'login phải set session cookie');
  const me = await (await get(vulnBox.url, '/api/me', { headers: { cookie: `session=${sid}` } })).json();
  assert.equal(me.role, 'admin');
  assert.match(me.flag, /FLAG\{mass-[0-9a-f]+\}/);
});

test('LAB-17 hardened: role=admin bị phớt lờ → user thường, /api/me sạch', async () => {
  await post(hardBox.url, '/api/register?role=admin', 'username=massign3&password=pw12345');
  const login = await post(hardBox.url, '/login', 'username=massign3&password=pw12345');
  const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
  const me = await (await get(hardBox.url, '/api/me', { headers: { cookie: `session=${sid}` } })).json();
  assert.equal(me.role, 'user');
  assert.equal(me.flag, undefined);
});

test('LAB-17 hardened: field lạ vẫn cho đăng ký nhưng chỉ nhận whitelist', async () => {
  const j = await (await post(hardBox.url, '/api/register', 'username=massign4&password=pw12345&role=admin&isAdmin=true&apiKey=x')).json();
  assert.equal(j.ok, true);
  assert.equal(j.user.role, 'user');
});

// ---------- LAB-18 Blind SQL Injection ----------
test('LAB-18 vuln: oracle boolean — AND 1=1 → 200, AND 1=2 → 404', async () => {
  const yes = await get(vulnBox.url, `/track?code=${encodeURIComponent("AB-100' AND 1=1 --")}`);
  const no = await get(vulnBox.url, `/track?code=${encodeURIComponent("AB-100' AND 1=2 --")}`);
  assert.equal(yes.status, 200);
  assert.match(await yes.text(), /TỒN TẠI/);
  assert.equal(no.status, 404);
});

test('LAB-18 vuln: oracle substr rút ký tự cờ từng cái một', async () => {
  const q = (n, ch) => `AB-100' AND (SELECT substr(flag,${n},1) FROM ctf_blind)='${ch}' --`;
  assert.equal((await get(vulnBox.url, `/track?code=${encodeURIComponent(q(1, 'F'))}`)).status, 200);
  assert.equal((await get(vulnBox.url, `/track?code=${encodeURIComponent(q(6, 'b'))}`)).status, 200);
  assert.equal((await get(vulnBox.url, `/track?code=${encodeURIComponent(q(1, 'Z'))}`)).status, 404);
});

test('LAB-18 hardened: cùng payload → 404 (tham số hoá, coi như chuỗi thường)', async () => {
  const res = await get(hardBox.url, `/track?code=${encodeURIComponent("AB-100' AND 1=1 --")}`);
  assert.equal(res.status, 404);
  const t = await res.text();
  assert.ok(!/TỒN TẠI/.test(t));
});

// ---------- LAB-19 Insecure Reset Token ----------
test('LAB-19 vuln: token reset = md5(username) → đoán được, chiếm account', async () => {
  const crypto = await import('node:crypto');
  const guess = crypto.createHash('md5').update('dave').digest('hex').slice(0, 12);
  // KHÔNG gọi /api/reset/request — tự tính token, chứng minh đoán được
  const j = await (await post(vulnBox.url, '/api/reset/confirm', `user=dave&token=${guess}&newpass=pwned99`)).json();
  assert.equal(j.ok, true);
  // password mới dùng được → chứng minh account takeover
  const tok = await (await post(vulnBox.url, '/api/token', 'username=dave&password=pwned99')).json();
  assert.ok(tok.token, 'đăng nhập bằng password vừa chiếm phải được');
});

test('LAB-19 vuln: token lộ trong response request (trả thẳng về client)', async () => {
  const j = await (await get(vulnBox.url, '/api/reset/request?user=alice')).json();
  assert.match(j.token, /^[0-9a-f]{12}$/);
});

test('LAB-19 hardened: token random 128-bit, sai token → 403, xác nhận đúng → 200', async () => {
  const req = await (await get(hardBox.url, '/api/reset/request?user=bob')).json();
  assert.match(req.demo_token, /^[0-9a-f]{32}$/);
  const bad = await post(hardBox.url, '/api/reset/confirm', 'user=bob&token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&newpass=x');
  assert.equal(bad.status, 403);
  const good = await post(hardBox.url, '/api/reset/confirm', `user=bob&token=${req.demo_token}&newpass=newpass9`);
  assert.equal(good.status, 200);
  // dùng lại lần 2 → token đã xoá (one-time)
  const reuse = await post(hardBox.url, '/api/reset/confirm', `user=bob&token=${req.demo_token}&newpass=again1`);
  assert.equal(reuse.status, 403);
});

// ---------- LAB-20 DOM-based XSS ----------
test('LAB-20 vuln: trang /dom render location.hash bằng innerHTML', async () => {
  const t = await (await get(vulnBox.url, '/dom')).text();
  assert.match(t, /location\.hash/);
  assert.match(t, /innerHTML\s*=\s*decodeURIComponent/);
});

test('LAB-20 hardened: /dom dùng textContent, không innerHTML', async () => {
  const t = await (await get(hardBox.url, '/dom')).text();
  assert.match(t, /textContent/);
  assert.ok(!/innerHTML\s*=\s*decodeURIComponent/.test(t), 'không được gán hash vào innerHTML');
});
