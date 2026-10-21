// Test GUARD — lớp an toàn quan trọng nhất: phải chặn mọi mục tiêu public.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyIp, assertAuthorizedTarget, parseTarget, SecurityError } from '../src/guard.js';

test('classifyIp phân loại đúng các dải IP', () => {
  assert.equal(classifyIp('8.8.8.8'), 'public');
  assert.equal(classifyIp('1.1.1.1'), 'public');
  assert.equal(classifyIp('127.0.0.1'), 'loopback');
  assert.equal(classifyIp('127.9.9.9'), 'loopback');
  assert.equal(classifyIp('::1'), 'loopback');
  assert.equal(classifyIp('10.0.0.5'), 'private');
  assert.equal(classifyIp('192.168.1.10'), 'private');
  assert.equal(classifyIp('172.16.0.1'), 'private');
  assert.equal(classifyIp('172.31.255.255'), 'private');
  assert.equal(classifyIp('172.32.0.1'), 'public'); // ngoài 172.16–31
});

test('parseTarget bắt URL sai và tự thêm http://', () => {
  assert.throws(() => parseTarget('http bad url'), SecurityError);
  assert.equal(parseTarget('127.0.0.1:3000').hostname, '127.0.0.1');
  assert.equal(parseTarget('https://127.0.0.1').protocol, 'https:');
});

test('TỪ CHỐI mục tiêu IP public — kể cả khi có --i-own-this-target', async () => {
  await assert.rejects(
    assertAuthorizedTarget('http://8.8.8.8', { consent: true }),
    (e) => e instanceof SecurityError && /TỪ CHỐI/.test(e.message)
  );
  await assert.rejects(
    assertAuthorizedTarget('http://1.1.1.1:8080'),
    SecurityError
  );
});

test('dải riêng: chặn khi thiếu cờ, cho phép khi có --i-own-this-target', async () => {
  await assert.rejects(
    assertAuthorizedTarget('http://192.168.1.50:3000'),
    (e) => /--i-own-this-target/.test(e.message)
  );
  const ok = await assertAuthorizedTarget('http://192.168.1.50:3000', { consent: true });
  assert.equal(ok.scope, 'private');
});

test('cho phép loopback không cần cờ', async () => {
  const a = await assertAuthorizedTarget('http://127.0.0.1:3000');
  assert.equal(a.scope, 'loopback');
  const b = await assertAuthorizedTarget('localhost');
  assert.equal(b.scope, 'loopback');
});

test('tên miền public (nếu phân giải được) phải bị chặn', async () => {
  // dùng tên miền không tồn tại → lỗi phân giải; nếu phân giải được thì phải là public-refuse
  await assert.rejects(
    assertAuthorizedTarget('http://seclab-should-not-resolve.invalid'),
    (e) => /SecurityError|phân giải|TỪ CHỐI/.test(e.name + e.message)
  );
});
