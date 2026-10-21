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

test('CTF: liệt kê 4 thử thách, tổng 100 điểm, cờ per-instance', async () => {
  const list = await listChallenges(vulnUrl);
  assert.equal(list.enabled, true);
  assert.equal(list.challenges.length, 4);
  assert.equal(list.total, 100);
  assert.ok(list.challenges.every((c) => /FLAG|traversal|SQL|apiKey|admin/i.test(c.hint)));
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
  assert.ok(list.total === 100);
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
