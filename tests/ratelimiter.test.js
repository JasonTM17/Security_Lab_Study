// Test rate limiter (module phòng thủ).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenBucketLimiter } from '../src/defense/ratelimiter.js';

function fakePair(ip = '127.0.0.1') {
  const req = { socket: { remoteAddress: ip } };
  let status = 200;
  let headers = {};
  let body = '';
  const res = {
    set statusCode(v) { status = v; },
    get statusCode() { return status; },
    setHeader(k, v) { headers[k] = v; },
    end(b) { body = b ?? ''; },
    get _headers() { return headers; },
    get _body() { return body; },
  };
  return { req, res };
}

test('burst vượt capacity → 429 (Retry-After có mặt)', () => {
  const limiter = tokenBucketLimiter({ capacity: 5, refillPerSec: 0.001 });
  let limited = 0;
  for (let i = 0; i < 30; i++) {
    const { req, res } = fakePair();
    limiter(req, res, () => {});
    if (res.statusCode === 429) {
      limited += 1;
      assert.ok(res._headers['Retry-After'], 'phải có Retry-After');
    }
  }
  assert.ok(limited >= 20, `kỳ vọng >=20 lần 429, thực tế ${limited}`);
});

test('client khác nhau có xô riêng, không ảnh hưởng nhau', () => {
  const limiter = tokenBucketLimiter({ capacity: 3, refillPerSec: 0.001 });
  for (let i = 0; i < 3; i++) {
    const { req, res } = fakePair('10.0.0.1');
    limiter(req, res, () => {});
    assert.equal(res.statusCode, 200);
  }
  const { req, res } = fakePair('10.0.0.2');
  limiter(req, res, () => {});
  assert.equal(res.statusCode, 200, 'IP mới còn nguyên token');
});
