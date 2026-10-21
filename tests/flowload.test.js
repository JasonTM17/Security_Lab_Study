// Test flowload: luồng người dùng thật chạy được trên lab thật,
// và guard chặn mục tiêu public như mọi module tạo tải.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createLabApp } from '../src/lab/app.js';
import { runFlowTest } from '../src/modules/flowload.js';
import { SecurityError } from '../src/guard.js';

let server;
let baseUrl;

before(async () => {
  server = await createLabApp({ mode: 'vuln' }); // vuln: không rate-limit → đếm được chính xác
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  server.closeAllConnections?.();
});

test('flowtest: chạy đúng luồng mặc định và thống kê theo từng bước', async () => {
  const res = await runFlowTest(baseUrl, { users: 2, iterations: 2, thinkMs: 0, rampUpMs: 0 });
  assert.equal(res.scope, 'loopback');
  assert.equal(res.users, 2);
  assert.equal(res.iterations, 2);
  // 2 user × 2 vòng × 3 bước = 12 request
  assert.equal(res.totals.sent, 12);
  assert.equal(res.steps.length, 3);
  for (const s of res.steps) {
    assert.equal(s.count, 4, `bước "${s.name}" phải có đúng 4 request`);
    assert.ok((s.statusCounts['200'] ?? 0) >= 1, `bước "${s.name}" kỳ vọng có phản hồi 200`);
    assert.equal(s.errors, 0);
  }
  assert.ok(res.chainMs.count === 4, 'phải ghi đủ 4 chuỗi luồng');
  assert.equal(Object.keys(res.statusCounts).join(','), '200');
});

test('flowtest: đường dẫn tuỳ chỉnh được chuẩn hoá (thiếu "/" tự thêm)', async () => {
  const res = await runFlowTest(baseUrl, {
    users: 1,
    iterations: 1,
    thinkMs: 0,
    steps: [{ name: 'không gạch', path: 'robots.txt' }],
  });
  assert.equal(res.steps[0].path, '/robots.txt');
  assert.equal(res.totals.sent, 1);
  assert.equal(res.steps[0].errors, 0);
});

test('flowtest: TỪ CHỐI mục tiêu public như mọi module tạo tải', async () => {
  await assert.rejects(() => runFlowTest('http://93.184.216.34/', { users: 1, iterations: 1 }), SecurityError);
});
