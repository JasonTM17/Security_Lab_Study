// unit-gaps.test.js — phủ các khoảng trống kiểm thử được nêu trong review:
//   1) hub resolveSafe: path traversal, backslash, extension lạ, đường dẫn hợp lệ
//   2) db loginSafe / searchUsersSafe: SQLi vô hiệu hoá, đăng nhập đúng thông tin
//   3) report buildMarkdown / buildHtml: tiêu đề, mục tiêu, thứ tự severity, escape
//   4) scraper parseRobots: Crawl-delay, hoà Allow/Disallow cùng độ dài (Allow thắng)
//   5) vulnscan runScan: cổng ủy quyền assertAuthorizedTarget bị khóa bằng test
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveSafe } from '../src/hub/serve.js';
import { createLabDb } from '../src/db.js';
import { buildMarkdown, buildHtml } from '../src/modules/report.js';
import { parseRobots, robotsAllows } from '../src/modules/scraper.js';
import { runScan, CHECKS } from '../src/modules/vulnscan.js';
import { SecurityError } from '../src/guard.js';

// ---------------------------------------------------------------------------
// 1) resolveSafe — phòng thủ path-traversal của Hub server
// ---------------------------------------------------------------------------

const HUB_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'hub');

test('resolveSafe: traversal bằng .. bị chặn', () => {
  assert.equal(resolveSafe('/../../package.json'), null);
  assert.equal(resolveSafe('/sections/../../db.js'), null);
  assert.equal(resolveSafe('/..%2f..%2fpackage.json'), null); // decode → '/../..' → chặn
});

test('resolveSafe: backslash (kể cả %5C đã decode) bị chặn', () => {
  assert.equal(resolveSafe('\\windows\\system32\\config'), null);
  assert.equal(resolveSafe('/..\\..\\package.json'), null);
  assert.equal(resolveSafe('/..%5C..%5Cpackage.json'), null);
});

test('resolveSafe: extension lạ ngoài danh sách cho phép bị chặn', () => {
  assert.equal(resolveSafe('/index.php'), null);
  assert.equal(resolveSafe('/shell.exe'), null);
  assert.equal(resolveSafe('/sections/01-tong-quan.html.exe'), null);
  assert.equal(resolveSafe('/notes.txt'), null);
  assert.equal(resolveSafe('/sections'), null); // không extension
});

test('resolveSafe: đường dẫn hợp lệ trả về file tuyệt đối trong hub/', () => {
  const root = resolveSafe('/');
  assert.ok(root, "'/' phải hợp lệ (map sang index.html)");
  assert.equal(root.ext, '.html');
  assert.equal(root.abs, path.join(HUB_DIR, 'index.html'));

  const page = resolveSafe('/sections/06-mang-giao-thuc.html');
  assert.ok(page);
  assert.equal(page.abs, path.join(HUB_DIR, 'sections', '06-mang-giao-thuc.html'));
  assert.ok(page.abs.startsWith(HUB_DIR + path.sep));
});

test('resolveSafe: query string bị bỏ; extension hoa/thường không quan trọng', () => {
  const q = resolveSafe('/index.html?x=1');
  assert.equal(q.abs, path.join(HUB_DIR, 'index.html'));
  assert.equal(resolveSafe('/INDEX.HTML').ext, '.html');
});

// ---------------------------------------------------------------------------
// 2) db loginSafe / searchUsersSafe — parameterized, SQLi vô hiệu hoá
// ---------------------------------------------------------------------------

let db;

before(async () => {
  db = await createLabDb(); // backend do môi trường quyết định (node:sqlite hoặc memory)
});

test('db: backend chỉ có thể là node:sqlite hoặc memory-simulator', () => {
  assert.ok(['node:sqlite', 'memory-simulator'].includes(db.backend), `backend=${db.backend}`);
});

test('loginSafe: đúng thông tin đăng nhập → ok, KHÔNG lộ apiKey', async () => {
  const r = await db.loginSafe('alice', 'alice123');
  assert.equal(r.ok, true);
  // node:sqlite trả về [Object: null prototype] → spread để so sánh bằng với plain object
  assert.deepEqual({ ...r.user }, { id: 1, name: 'alice', role: 'admin', email: 'alice@lab.local' });
  assert.equal(r.user.apiKey, undefined, 'loginSafe chỉ chọn id/name/role/email');

  const r2 = await db.loginSafe('bob', 'bob45678');
  assert.equal(r2.ok, true);
  assert.equal(r2.user.role, 'user');
});

test('loginSafe: sai mật khẩu → ok:false', async () => {
  const r = await db.loginSafe('alice', 'sai-mat-khau');
  assert.deepEqual(r, { ok: false });
});

test('loginSafe: payload SQLi kinh điển không bypass được', async () => {
  for (const payload of [
    "' OR 1=1 --",
    "alice' --",
    "alice' OR '1'='1",
    "x' UNION SELECT 1,2,3 --",
  ]) {
    const r = await db.loginSafe(payload, 'anything');
    assert.equal(r.ok, false, `payload "${payload}" phải vô hiệu`);
  }
  // payload ở cột mật khẩu cũng vô hiệu (hash của payload không khớp hàng nào)
  const r = await db.loginSafe('alice', "' OR '1'='1");
  assert.equal(r.ok, false);
});

test('searchUsersSafe: tìm đúng, không phân biệt hoa/thường, trả đúng trường', async () => {
  const r = await db.searchUsersSafe('ALI');
  assert.equal(r.rows.length, 1);
  assert.deepEqual(r.rows.map((x) => ({ ...x })), [
    { id: 1, name: 'alice', role: 'admin', email: 'alice@lab.local' },
  ]);

  const rb = await db.searchUsersSafe('bob');
  assert.equal(rb.rows.length, 1);
  assert.equal(rb.rows[0].email, 'bob@lab.local');
});

test('searchUsersSafe: SQLi + wildcard bị vô hiệu hoá, không ném lỗi CSDL', async () => {
  for (const q of ["' OR 1=1 --", "' OR '1'='1", "alice' --", '%', '_', "'", "a%'; DROP TABLE users; --"]) {
    const r = await db.searchUsersSafe(q);
    assert.equal(r.rows.length, 0, `q="${q}" phải trả 0 dòng`);
    assert.equal(r.error, undefined, `q="${q}" không được lỗi cú pháp CSDL`);
  }
});

test('searchUsersSafe so với searchUsers: bản vuln lộ 4 dòng, bản safe không', async () => {
  const vuln = await db.searchUsers("' OR 1=1 --");
  assert.equal(vuln.rows.length, 4, 'bản vuln phải còn lỗ hổng (4 dòng) để test safe có nghĩa');
  const safe = await db.searchUsersSafe("' OR 1=1 --");
  assert.equal(safe.rows.length, 0);
});

// ---------------------------------------------------------------------------
// 3) report buildMarkdown / buildHtml — object scan giả, không ghi file
// ---------------------------------------------------------------------------

const SCAN = {
  target: 'http://127.0.0.1:3000',
  scope: 'loopback',
  startedAt: '2026-10-06T00:00:00.000Z',
  finishedAt: '2026-10-06T00:00:10.000Z',
  summary: { high: 1, medium: 1, passed: 1 },
  findings: [
    { id: 'HDR-001', title: 'Security headers đầy đủ', severity: 'info', vulnerable: false, evidence: 'OK', detail: 'đạt chuẩn', fix: '' },
    { id: 'SQLI-001', title: 'SQL Injection (boolean-based)', severity: 'high', vulnerable: true, evidence: "payload ' OR 1=1 --", detail: 'nối chuỗi SQL', fix: 'parameterized query' },
    { id: 'CKI-001', title: 'Cookie phiên', severity: 'medium', vulnerable: null, evidence: 'không có Set-Cookie', detail: '', fix: '' },
  ],
};

test('buildMarkdown: tiêu đề, mục tiêu, phạm vi, thời gian, tổng kết', () => {
  const md = buildMarkdown(SCAN);
  assert.ok(md.startsWith('# Báo cáo quét SecLab'));
  assert.ok(md.includes('- **Mục tiêu:** http://127.0.0.1:3000 (phạm vi: loopback)'));
  assert.ok(md.includes(SCAN.startedAt) && md.includes(SCAN.finishedAt));
  assert.ok(md.includes('🔴 High: 1 · 🟠 Medium: 1 · ✅ Đạt: 1'));
  assert.ok(md.includes('> SecLab chỉ dùng cho hệ thống bạn sở hữu'));
});

test('buildMarkdown: bảng sắp theo severity (high → medium → info) và icon đúng 3 trạng thái', () => {
  const md = buildMarkdown(SCAN);
  const tSql = md.indexOf('| SQLI-001 | 🔴 high |'); // vulnerable === true → 🔴
  const tCki = md.indexOf('| CKI-001 | ℹ️ medium |'); // vulnerable === null → ℹ️
  const tHdr = md.indexOf('| HDR-001 | ✅ info |'); // vulnerable === false → ✅
  assert.ok(tSql !== -1 && tCki !== -1 && tHdr !== -1, 'mỗi finding phải có 1 dòng bảng');
  assert.ok(tSql < tCki && tCki < tHdr, 'thứ tự bảng phải là high → medium → info');
});

test('buildMarkdown: mục Chi tiết có đủ Bằng chứng/Khái niệm/Cách vá, bỏ trường rỗng', () => {
  const md = buildMarkdown(SCAN);
  assert.ok(md.includes('### SQLI-001 — SQL Injection (boolean-based) [high]'));
  assert.ok(md.includes('- **Bằng chứng:** payload \' OR 1=1 --'));
  assert.ok(md.includes('- **Bằng chứng:** không có Set-Cookie'));
  assert.ok(md.includes('- **Khái niệm:** nối chuỗi SQL'));
  assert.ok(md.includes('- **Cách vá:** parameterized query'));
  // SQLI + HDR có detail (2), chỉ SQLI có fix (1); CKI-001 rỗng nên không có dòng nào riêng nó
  assert.equal(md.split('- **Khái niệm:**').length - 1, 2);
  assert.equal(md.split('- **Cách vá:**').length - 1, 1);
});

test('buildHtml: target trong <title> được escape', () => {
  const scan = { ...SCAN, target: 'http://x/<b>&quo' };
  const html = buildHtml(scan);
  assert.ok(html.includes('<title>SecLab Report — http://x/&lt;b&gt;&amp;quo</title>'));
  assert.ok(!html.includes('<b>&quo</b>') || !html.includes('<title>SecLab Report — http://x/<b>'));
});

test('buildHtml: evidence/detail/fix được escape; class theo 3 trạng thái', () => {
  const scan = {
    ...SCAN,
    findings: [
      { id: 'SQLI-001', title: 'Tiêu đề g', severity: 'high', vulnerable: true, evidence: '<script>alert(1)</script>', detail: 'x', fix: 'y' },
      { id: 'HDR-001', title: 'Tiêu đề o', severity: 'info', vulnerable: false, evidence: 'OK', detail: '', fix: '' },
      { id: 'CKI-001', title: 'Tiêu đề i', severity: 'medium', vulnerable: null, evidence: '-', detail: '', fix: '' },
    ],
  };
  const html = buildHtml(scan);
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!html.includes('<script>alert(1)</script>'), 'evidence không được vào HTML nguyên văn');
  assert.ok(html.includes('<tr class="vuln"'));
  assert.ok(html.includes('<tr class="ok"'));
  assert.ok(html.includes('<tr class="info"'));
  assert.ok(html.includes('🔴 High: 1 · 🟠 Medium: 1 · ✅ Đạt: 1'));
});

// ---------------------------------------------------------------------------
// 4) scraper parseRobots — Crawl-delay và hoà Allow/Disallow cùng độ dài
// ---------------------------------------------------------------------------

test('parseRobots: Crawl-delay nguyên, thập phân, kèm chú thích #', () => {
  assert.equal(parseRobots('User-agent: *\nCrawl-delay: 3').crawlDelayMs, 3000);
  assert.equal(parseRobots('User-agent: *\nCrawl-delay: 0.5').crawlDelayMs, 500);
  assert.equal(parseRobots('User-agent: *\nCrawl-delay: 3 # chậm 3 giây').crawlDelayMs, 3000);
});

test('parseRobots: Crawl-delay sai/negative/không có → null', () => {
  assert.equal(parseRobots('User-agent: *\nCrawl-delay: abc').crawlDelayMs, null);
  assert.equal(parseRobots('User-agent: *\nCrawl-delay: -2').crawlDelayMs, null);
  assert.equal(parseRobots('User-agent: *\nDisallow: /x').crawlDelayMs, null);
});

test('parseRobots: gộp nhóm * và UA riêng — crawl-delay lấy MAX (token truyền tường minh)', () => {
  const r = parseRobots(
    'User-agent: *\nCrawl-delay: 1\nDisallow: /pub\n\nUser-agent: seclab-eduscraper\nCrawl-delay: 5\nDisallow: /own',
    'seclab-eduscraper'
  );
  assert.equal(r.crawlDelayMs, 5000, 'MAX(1000, 5000)');
  assert.deepEqual(r.disallow.sort(), ['/own', '/pub'], 'luật của cả hai nhóm được gộp');
});

test('parseRobots: token mặc định là "seclab-eduscrawler", KHÔNG khớp UA thật "SecLab-EduScraper"', () => {
  // Ghi nhận hành vi thực tế (scraper.js:29 UA "SecLab-EduScraper/1.0" vs scraper.js:116
  // token mặc định "seclab-eduscrawler" — scraper ≠ crawler): nhóm UA thật bị bỏ qua
  // khi gọi parseRobots() không truyền token.
  const real = parseRobots('User-agent: seclab-eduscraper\nCrawl-delay: 5');
  assert.equal(real.crawlDelayMs, null, 'UA thật không được nhận diện bởi token mặc định');
  const token = parseRobots('User-agent: seclab-eduscrawler\nCrawl-delay: 5');
  assert.equal(token.crawlDelayMs, 5000, 'token mặc định được nhận diện');
});

test('robots: hoà Allow/Disallow cùng độ dài → Allow thắng (độc lập thứ tự khai báo)', () => {
  // Cả '/a*bc' (Disallow) và '/ab*c' (Allow) dài 5; tại '/abc' cả hai khớp → hoà.
  const disallowFirst = parseRobots('User-agent: *\nDisallow: /a*bc\nAllow: /ab*c');
  const allowFirst = parseRobots('User-agent: *\nAllow: /ab*c\nDisallow: /a*bc');
  for (const r of [disallowFirst, allowFirst]) {
    assert.equal(robotsAllows(r, '/abc'), true, 'hoà cùng độ dài → Allow thắng');
    assert.equal(robotsAllows(r, '/axbc'), false, 'chỉ Disallow khớp → chặn');
  }
});

test('robots: Disallow dài hơn thì chặn dù có Allow ngắn hơn', () => {
  const r = parseRobots('User-agent: *\nDisallow: /admin/a\nAllow: /admin');
  assert.equal(robotsAllows(r, '/admin/a'), false);
  assert.equal(robotsAllows(r, '/admin'), true);
});

// ---------------------------------------------------------------------------
// 5) vulnscan — cổng ủy quyền của scanner phải chặn mục tiêu không sở hữu
// ---------------------------------------------------------------------------

test('vulnscan runScan: dải riêng không có cờ sở hữu → SecurityError TRƯỚC khi quét', async () => {
  await assert.rejects(() => runScan('http://192.168.1.50:3000'), SecurityError);
});

test('vulnscan CHECKS: đủ 7 probe, id duy nhất, mỗi probe là hàm', () => {
  assert.deepEqual(
    CHECKS.map((c) => c.id),
    ['HDR', 'CKI', 'SQLI', 'XSS', 'IDOR', 'PATH', 'RPS']
  );
  const ids = new Set(CHECKS.map((c) => c.id));
  assert.equal(ids.size, CHECKS.length);
  for (const c of CHECKS) assert.equal(typeof c.fn, 'function', `probe ${c.id} phải là hàm`);
});
