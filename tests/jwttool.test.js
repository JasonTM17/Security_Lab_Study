// Test jwttool.js + lab/jwtx.js — decode/forge/verify/crack JWT (bài LAB-11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jwtDecode, jwtSign, jwtVerify } from '../src/lab/jwtx.js';
import { crackJwt, DEFAULT_WORDLIST } from '../src/modules/jwttool.js';

test('jwt: sign + verify HS256 đúng secret', () => {
  const t = jwtSign({ sub: 'alice', role: 'admin' }, 'khoa-bi-mat');
  const v = jwtVerify(t, 'khoa-bi-mat');
  assert.equal(v.ok, true);
  assert.equal(v.payload.sub, 'alice');
});

test('jwt: sai secret → bad_signature', () => {
  const t = jwtSign({ sub: 'alice' }, 'dung');
  assert.equal(jwtVerify(t, 'sai').ok, false);
});

test('jwt: alg=none bị từ chối mặc định, chỉ qua khi allowNone (kiểu lab vuln)', () => {
  const t = jwtSign({ sub: 'ctfsvc' }, '', { alg: 'none' });
  assert.ok(t.endsWith('.'));
  assert.equal(jwtVerify(t, 'bat-ky').ok, false);
  assert.equal(jwtVerify(t, 'bat-ky', { allowNone: true }).ok, true);
});

test('jwt: token hết hạn bị chặn khi checkExp', () => {
  const t = jwtSign({ sub: 'a', exp: Math.floor(Date.now() / 1000) - 10 }, 'k');
  assert.equal(jwtVerify(t, 'k').error, 'expired');
  assert.equal(jwtVerify(t, 'k', { checkExp: false }).ok, true);
});

test('jwt: decode không cần secret — ai cũng đọc payload', () => {
  const t = jwtSign({ sub: 'alice', admin: true }, 'giu-kin');
  const d = jwtDecode(t);
  assert.equal(d.payload.sub, 'alice');
  assert.equal(d.header.alg, 'HS256');
  assert.equal(jwtDecode('khong.phai.jwt'), null);
  assert.equal(jwtDecode('abc'), null);
});

test('jwt: crack tìm được secret yếu trong từ điển', () => {
  const t = jwtSign({ sub: 'alice' }, 'secret123'); // secret của lab vuln
  const r = crackJwt(t);
  assert.equal(r.secret, 'secret123');
  assert.ok(DEFAULT_WORDLIST.includes('secret123'));
});

test('jwt: crack thất bại với secret mạnh', () => {
  const t = jwtSign({ sub: 'a' }, 'Xk9#mQ2$vL8!nR4@pW7&zT5*yU3');
  assert.equal(crackJwt(t).secret, null);
});
