// hub.test.js — kiểm thử Hub server ở TẦNG HTTP qua createHubServer({port:0}).
//
// Phủ đúng khoảng trống được nêu trong review:
//   • ranh giới path-traversal của resolveSafe phải được kiểm chứng với đường
//     dẫn GỐC (fetch() của Node tự gộp /../ trước khi gửi — phải gửi raw qua
//     http.request thì server mới thấy được);
//   • REGRESSION URIError: GET /%. (percent-encoding lỗi) phải trả 403 và KHÔNG
//     được phép giết process — resolveSafe được gọi trực tiếp trong callback
//     http.createServer, một exception không bắt là một request làm sập hub
//     (CLI không đăng ký uncaughtException).
// Phần unit thuần của resolveSafe (traversal/backslash/extension) đã có ở
// tests/unit-gaps.test.js — file này chỉ thêm lớp server.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHubServer } from '../src/hub/serve.js';

let server;
let port;

before(async () => {
  server = await createHubServer({ port: 0 }); // port 0 = OS chọn port rảnh
  port = server.address().port;
});
after(() => new Promise((resolve) => server.close(resolve)));

/** GET với đường dẫn gửi NGUYÊN VĂN (không chuẩn hoá) — cách duy nhất để server
 * thấy raw path, vì mọi HTTP client hiện đại (fetch) tự gộp /../ trước khi gửi. */
const rawGet = (rawPath) =>
  new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: rawPath, method: 'GET' }, (res) => {
      const headers = { ...res.headers };
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers, body }));
    });
    req.on('error', reject);
    req.end();
  });

test('hub server: GET / → 200 text/html chứa SecHub', async () => {
  const r = await rawGet('/');
  assert.equal(r.status, 200);
  assert.match(r.headers?.['content-type'] ?? '', /text\/html/);
  assert.match(r.body, /SecHub/);
});

test('hub server: raw path traversal /../package.json → 403 (không lộ file)', async () => {
  assert.equal((await rawGet('/../package.json')).status, 403);
  assert.equal((await rawGet('/sections/../../package.json')).status, 403);
});

test('hub server: traversal đã encode %2e%2e → 403', async () => {
  assert.equal((await rawGet('/%2e%2e/package.json')).status, 403);
  assert.equal((await rawGet('/..%2fpackage.json')).status, 403);
});

test('hub server: GET /. (URIError regression) → 403 và PROCESS CÒN SỐNG', async () => {
  // Trước khi vá: decodeURIComponent('/%.') ném URIError ngay trong callback
  // createServer → uncaughtException → process thoát non-zero.
  const r = await rawGet('/%.');
  assert.equal(r.status, 403);
  // Request kế tiếp phải vẫn phục vụ bình thường — server không chết.
  const ok = await rawGet('/');
  assert.equal(ok.status, 200);
  assert.match(ok.body, /SecHub/);
});

test('hub server: malformed encoding ở dạng khác (/%%, /%zz) → 403, không crash', async () => {
  assert.equal((await rawGet('/%%')).status, 403);
  assert.equal((await rawGet('/%zz')).status, 403);
  assert.equal((await rawGet('/index.html?x=%zz')).status, 200); // query bị cắt trước decode
});

test('hub server: file không tồn tại → 404', async () => {
  assert.equal((await rawGet('/khong-ton-tai.html')).status, 404);
});
