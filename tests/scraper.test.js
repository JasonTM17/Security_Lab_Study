// Test scraper "lịch sự": guard ngược chiều (cho public, chặn nội bộ),
// robots.txt (longest-match, wildcard, crawl-delay), trích xuất HTML,
// và guard redirect (redirect chéo origin bị chặn — mitigation SSRF pivot).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { assertScrapeTarget, parseRobots, robotsAllows, extractFromHtml, globMatch, runCrawl } from '../src/modules/scraper.js';
import { SecurityError } from '../src/guard.js';

// ---------- GUARD: mặc định chặn nội bộ, cho phép public ----------

test('scraper guard: loopback bị chặn MẶC ĐỊNH (ngược với module tấn công)', async () => {
  await assert.rejects(() => assertScrapeTarget('http://127.0.0.1:3000'), SecurityError);
});

test('scraper guard: loopback được phép khi có cờ sở hữu (thực hành trên lab)', async () => {
  const t = await assertScrapeTarget('http://127.0.0.1:3000', { consent: true });
  assert.equal(t.scope, 'loopback');
  assert.equal(t.host, '127.0.0.1');
});

test('scraper guard: dải riêng bị chặn khi không có cờ', async () => {
  await assert.rejects(() => assertScrapeTarget('http://192.168.1.10/'), SecurityError);
});

test('scraper guard: chỉ nhận http/https', async () => {
  await assert.rejects(() => assertScrapeTarget('ftp://example.com', { consent: true }), SecurityError);
});

// ---------- robots.txt ----------

const ROBOTS = `
# robots cho site demo
User-agent: *
Disallow: /admin
Allow: /admin/public
Disallow: /search?*
Crawl-delay: 2

User-agent: BadBot
Disallow: /
`;

test('robots: phân tích đúng nhóm User-agent: * và bỏ qua nhóm khác', () => {
  const r = parseRobots(ROBOTS);
  assert.deepEqual(r.allow, ['/admin/public']);
  assert.deepEqual(r.disallow.sort(), ['/admin', '/search?*']);
  assert.equal(r.crawlDelayMs, 2000);
});

test('robots: longest-match — /admin chặn, /admin/public cho phép', () => {
  const r = parseRobots(ROBOTS);
  assert.equal(robotsAllows(r, '/admin'), false);
  assert.equal(robotsAllows(r, '/admin/secret'), false);
  assert.equal(robotsAllows(r, '/admin/public/page'), true); // Allow dài hơn Disallow → thắng
});

test('robots: wildcard * khớp', () => {
  const r = parseRobots(ROBOTS);
  assert.equal(robotsAllows(r, '/search?q=iphone'), false);
  assert.equal(robotsAllows(r, '/search'), true); // không có query → không khớp '/search?*'
});

test('robots: không có luật khớp → cho phép; không có robots → cho phép', () => {
  const r = parseRobots(ROBOTS);
  assert.equal(robotsAllows(r, '/blog/bai-viet-1'), true);
  assert.equal(robotsAllows(null, '/admin'), true);
});

test('robots: $ neo cuối chuỗi', () => {
  const r = parseRobots('User-agent: *\nDisallow: /*.pdf$');
  assert.equal(robotsAllows(r, '/files/abc.pdf'), false);
  assert.equal(robotsAllows(r, '/files/abc.pdf?x=1'), true);
});

// ---------- Trích xuất HTML ----------

const HTML = `<!doctype html>
<html><head>
  <title>Trang thử nghiệm &amp; học tập</title>
  <meta name="description" content="Mô tả trang demo">
  <script>var secretScriptToken = 1;</script>
</head>
<body>
  <h1>Chào mừng</h1>
  <h2>Mục lục</h2>
  <a href="/about">Giới thiệu</a>
  <a href="https://example.org/out">Liên kết ngoài</a>
  <a href="mailto:x@y.z">Email</a>
  <a href="/lien-ket-lap#toc">Anchor</a>
  <img src="/logo.png">
</body></html>`;

test('html: trích title, meta description, headings', () => {
  const ex = extractFromHtml(HTML, 'https://example.com/');
  assert.equal(ex.title, 'Trang thử nghiệm & học tập');
  assert.equal(ex.metaDescription, 'Mô tả trang demo');
  assert.deepEqual(
    ex.headings.map((h) => h.text),
    ['Chào mừng', 'Mục lục']
  );
});

test('html: đánh dấu same-origin, loại mailto, gỡ #anchor', () => {
  const ex = extractFromHtml(HTML, 'https://example.com/');
  const hrefs = ex.links.map((l) => l.href);
  assert.ok(hrefs.includes('https://example.com/about'));
  assert.ok(hrefs.includes('https://example.com/lien-ket-lap'));
  assert.ok(hrefs.includes('https://example.org/out'));
  const about = ex.links.find((l) => l.href.endsWith('/about'));
  assert.equal(about.sameOrigin, true);
  const out = ex.links.find((l) => l.href.includes('example.org'));
  assert.equal(out.sameOrigin, false);
  assert.ok(!ex.links.some((l) => l.href.startsWith('mailto:')));
  assert.equal(ex.imageCount, 1);
});

test('html: nội dung <script> không bị đếm vào text', () => {
  const ex = extractFromHtml(HTML, 'https://example.com/');
  assert.ok(!ex.textLength.toString().includes('secretScriptToken'));
  const withScript = extractFromHtml('<p>a b</p><script>SECRETSCRIPTBODY</script>', 'https://x.com/');
  const total = withScript.textLength;
  assert.ok(total >= 3 && total <= 5, `textLength=${total}`);
});

// ---------- globMatch (đã thay RegExp động — chống ReDoS từ robots) ----------

test('globMatch: so khớp thuần chuỗi đúng ngữ nghĩa robots', () => {
  assert.equal(globMatch('/a', '/a/b'), true);
  assert.equal(globMatch('/a', '/ab'), true);  // robots là prefix-match: /a chặn cả /ab
  assert.equal(globMatch('/a', '/b/c'), false);
  assert.equal(globMatch('/a*b', '/axxxb'), true);
  assert.equal(globMatch('/*x$', '/ax'), true);  // bắt đầu '/', kết thúc 'x' → khớp
  assert.equal(globMatch('/*x$', '/ax/y'), false); // không kết thúc 'x' → loại
  assert.equal(globMatch('/*x$', '/x'), true);
});

// ---------- Redirect guard (fetchGuarded): redirect phải được kiểm duyệt lại ----------
// Hai server loopback trên port khác nhau = hai origin KHÁC NHAU: entry 302 sang
// origin kia phải bị chặn (đúng kịch bản SSRF pivot: trang public redirect sang
// origin nội bộ mà guard chỉ chạy 1 lần ở đầu crawl).

const listenScraper = (handler) =>
  new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => resolve({ server: s, origin: `http://127.0.0.1:${s.address().port}` }));
  });

test('crawl: redirect chéo origin bị CHẶN — server đích không nhận được request nào', async () => {
  let pivotHits = 0;
  const pivot = await listenScraper((req, res) => {
    pivotHits += 1;
    res.end('<title>INTERNAL-HOME</title>');
  });
  const entry = await listenScraper((req, res) => {
    res.writeHead(302, { Location: `${pivot.origin}/secret-page` });
    res.end();
  });
  try {
    const r = await runCrawl(`${entry.origin}/`, { consent: true, maxPages: 5, depth: 2, delayMs: 300 });
    assert.equal(r.pages.length, 1);
    assert.match(String(r.pages[0].error), /redirect_cross_origin_blocked_by_guard/);
    assert.equal(pivotHits, 0, 'crawler không được phép fetch origin sau redirect');
  } finally {
    entry.server.close();
    pivot.server.close();
  }
});

test('crawl: redirect CÙNG origin được theo đúng luật (302 → 200, nội dung trang đích)', async () => {
  const target = await listenScraper((req, res) => {
    if (req.url === '/old') {
      res.writeHead(302, { Location: '/new' });
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<title>Trang mới</title><h1>Xin chào</h1>');
  });
  try {
    const r = await runCrawl(`${target.origin}/old`, { consent: true, maxPages: 5, depth: 2, delayMs: 300 });
    assert.equal(r.pages.length, 1);
    assert.equal(r.pages[0].status, 200);
    assert.equal(r.pages[0].title, 'Trang mới');
  } finally {
    target.server.close();
  }
});
