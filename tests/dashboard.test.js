// Test dashboard /lab + catalog LAB: route trả đủ 20 bài, dữ liệu nhất quán.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createLabApp } from '../src/lab/app.js';
import { LABS, CATEGORIES, renderDashboard, renderCatalog } from '../src/lab/dashboard.js';

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

test('GET /lab → 200, đủ 20 thẻ bài + badge vuln', async () => {
  const res = await fetch(box.url + '/lab');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Chọn bài LAB/);
  assert.match(html, /LAB VULN/);
  assert.equal((html.match(/data-cat=/g) || []).length, 20);
  assert.ok(html.includes('LAB-01') && html.includes('LAB-20'));
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
