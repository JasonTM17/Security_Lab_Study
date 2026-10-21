// Test dashboard /lab + catalog LAB: route trả đủ 20 bài, dữ liệu nhất quán.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createLabApp } from '../src/lab/app.js';
import { LABS, CATEGORIES, CAT_META, LAB_DETECT, renderDashboard, renderBlueDashboard, renderCatalog, DASH_CSS, RED_JS, BLUE_JS } from '../src/lab/dashboard.js';

const box = {};
before(async () => {
  const server = await createLabApp({ mode: 'vuln' });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  box.url = `http://127.0.0.1:${server.address().port}`;
  box.server = server;
});
after(() => {
  box.server.close();
  box.server.closeAllConnections?.();
});

test('GET /lab → 200, Red Team theme + đủ 20 thẻ bài', async () => {
  const res = await fetch(box.url + '/lab');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Red Team/);
  assert.match(html, /Chọn mục tiêu/);
  assert.match(html, /LAB VULN/);
  assert.equal((html.match(/data-cat=/g) || []).length, 20);
  assert.ok(html.includes('LAB-01') && html.includes('LAB-20'));
});

test('card có đủ nút tương tác: filter chip, CTF jump, ex link, POST curl', () => {
  const html = renderDashboard('vuln');
  assert.equal((html.match(/data-setcat=/g) || []).length, 20);
  assert.equal((html.match(/data-setdiff=/g) || []).length, 20);
  assert.equal((html.match(/data-ctfgo=/g) || []).length, 10);
  assert.equal((html.match(/class="ex"/g) || []).length, 20);
  assert.ok(html.includes('github.com/JasonTM17/Security_Lab_Study/blob/main/exercises/'));
  assert.ok(RED_JS.includes('dataset.post') && RED_JS.includes('data-setcat]') && RED_JS.includes('data-ctfgo]'));
});

test('filter nhóm toggle về "all" khi bấm lại (giống độ khó)', () => {
  // Regression: trước đây setCat chỉ gán — bấm lại cùng nhóm vẫn giữ filter
  assert.ok(RED_JS.includes("st.cat===v?'all':v"), 'setCat phải toggle về all');
  assert.ok(RED_JS.includes('st.diff===v?0:v'), 'setDiff toggle về 0');
});

test('dữ liệu LABS: 20 bài, id duy nhất, category hợp lệ', () => {
  assert.equal(LABS.length, 20);
  assert.equal(new Set(LABS.map((l) => l.id)).size, 20);
  for (const l of LABS) assert.ok(CATEGORIES[l.cat], `category lạ: ${l.cat}`);
  for (const l of LABS) assert.ok(l.diff >= 1 && l.diff <= 3);
});

test('CTF mapping: đúng 10 thử thách, id 1..10 không trùng, tổng 265đ', () => {
  const ctf = LABS.filter((l) => l.ctf).map((l) => l.ctf);
  assert.equal(ctf.length, 10);
  assert.deepEqual(
    ctf.map((c) => c.id).sort((a, b) => a - b),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  );
  assert.equal(
    ctf.reduce((s, c) => s + c.pts, 0),
    265
  );
});

test('mỗi bài trỏ tới file exercise tồn tại thật', () => {
  for (const l of LABS) {
    assert.ok(
      fs.existsSync(path.join(process.cwd(), l.ex)),
      `thiếu ${l.ex} cho ${l.id}`
    );
  }
});

test('renderDashboard: hardened hiện banner đối chứng', () => {
  const html = renderDashboard('hardened');
  assert.match(html, /LAB HARDENED/);
  assert.match(html, /đối chứng/);
});

test('renderCatalog: bảng tĩnh đủ 20 dòng + 6 nhóm cho hub', () => {
  const html = renderCatalog();
  assert.equal((html.match(/LAB-\d{2}/g) || []).length, 20);
  assert.equal((html.match(/<h3>/g) || []).length, 6);
});

// ---------- Blue Team SOC console ----------

test('GET /blue → 200, SOC console cyan + đủ 3 khối (feed/rule/defense)', async () => {
  const res = await fetch(box.url + '/blue');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /SOC Console/);
  assert.match(html, /LAB VULN/);
  assert.ok(html.includes('feed') && html.includes('alert') && html.includes('rule'));
});

test('GET /_lab/alerts → phân tích request log, tìm attack pattern', async () => {
  // Tạo traffic tấn công trước
  await fetch(box.url + "/search?q='%20OR%201=1%20--");
  await fetch(box.url + '/admin');
  const res = await fetch(box.url + '/_lab/alerts');
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.mode, 'vuln');
  assert.ok(Array.isArray(j.findings));
  assert.ok(Array.isArray(j.rules));
  const types = j.findings.map((f) => f.type);
  assert.ok(types.includes('sqli'), `thiếu sqli trong: ${types}`);
  assert.ok(types.includes('admin-probe'), `thiếu admin-probe trong: ${types}`);
});

test('/_lab/log: ghi status sau khi response xong (0=in-flight)', async () => {
  await fetch(box.url + '/status-check-404');
  await new Promise((r) => setTimeout(r, 50)); // chờ res.finish
  const j = await (await fetch(box.url + '/_lab/log')).json();
  const e = j.log.find((x) => x.path === '/status-check-404');
  assert.equal(e.status, 404);
});

test('renderBlueDashboard: hardened mode + rules render; JS/CSS tách ngoài cho CSP', () => {
  const html = renderBlueDashboard('hardened', [{ type: 'sqli', label: 'SQLi', severity: 'high' }]);
  assert.match(html, /LAB HARDENED/);
  assert.ok(html.includes('sqli'));
  // CSP hardened: style-src/script-src 'self' — KHÔNG được có <style>/<script> inline hay style=
  assert.ok(!html.includes('<style>'), 'hardened CSP cấm inline <style>');
  assert.ok(!html.includes('<script>${'), 'JS phải tải từ /_lab/dash-*.js');
  assert.ok(!/style="/.test(html), 'hardened CSP cấm attribute style=');
  assert.ok(html.includes('/_lab/dash.css') && html.includes('/_lab/dash-blue.js'));
  assert.ok(BLUE_JS.includes('typeof e.t'), 'client phải xử lý timestamp numeric');
  assert.ok(DASH_CSS.includes('--ac'));
});

test('flagsOf: decode path trước khi match — payload URL-encoded vẫn bị flag', () => {
  // Trích flagsOf ra khỏi BLUE_JS và chạy thử trên payload đã encode
  const m = BLUE_JS.match(/function flagsOf\(e\)\{[\s\S]*?return f;\n\}/);
  assert.ok(m, 'không trích được flagsOf');
  const fn = new Function(`${m[0]};return flagsOf;`)();
  assert.deepEqual(fn({ path: '/search?q=%27%20UNION%20SELECT%201--', method: 'GET' }), ['SQLi']);
  assert.ok(fn({ path: '/search?q=%3Cscript%3Ealert(1)%3C/script%3E', method: 'GET' }).includes('XSS'));
  assert.ok(fn({ path: '/tools/ping?host=127.0.0.1%20%26%20whoami', method: 'GET' }).includes('CMDI'));
  assert.deepEqual(fn({ path: '/search?q=alice', method: 'GET' }), []);
});

test('GET /_lab/dash.css + dash-*.js: asset dashboard phục vụ đúng MIME', async () => {
  const css = await fetch(box.url + '/_lab/dash.css');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /text\/css/);
  for (const f of ['dash-red.js', 'dash-blue.js']) {
    const r = await fetch(box.url + '/_lab/' + f);
    assert.equal(r.status, 200, f);
    assert.match(r.headers.get('content-type'), /javascript/);
  }
});

test('LAB_DETECT: mỗi bài lab có defense map cho blue team', () => {
  for (const l of LABS) {
    assert.ok(LAB_DETECT[l.id], `thiếu LAB_DETECT cho ${l.id}`);
  }
  assert.ok(Object.keys(CAT_META).length >= Object.keys(CATEGORIES).length);
});
