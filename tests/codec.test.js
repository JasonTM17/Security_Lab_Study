// Test codec.js — bộ mã hoá nền tảng.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64Encode, b64Decode, hexEncode, hexDecode, urlEncode, urlDecode, rot13, hashText, runCodec, explain } from '../src/modules/codec.js';

test('b64: vòng đi-về giữ nguyên văn, hỗ trợ tiếng Việt', () => {
  const s = 'SecLab học ATTT 🔐';
  assert.equal(b64Decode(b64Encode(s)), s);
  assert.equal(b64Encode('test'), 'dGVzdA==');
});

test('hex: vòng đi-về + từ chối chuỗi sai', () => {
  assert.equal(hexDecode(hexEncode('abc')), 'abc');
  assert.throws(() => hexDecode('abc'), /hex/); // lẻ ký tự
  assert.throws(() => hexDecode('zz'), /hex/);
});

test('url: encode payload SQLi đúng chuẩn và giải ngược', () => {
  const p = "' OR 1=1 --";
  assert.equal(urlDecode(urlEncode(p)), p);
  assert.equal(urlEncode('<'), '%3C'); // ký tự đặc biệt bị mã hoá
  assert.equal(urlEncode("'"), "'"); // bài học: dấu ' SỐNG SÓT qua URL nguyên vẹn — lý do payload SQLi dễ lan truyền trong query
});

test('rot13: tự nghịch đảo và vector quen thuộc', () => {
  assert.equal(rot13('Hello'), 'Uryyb');
  assert.equal(rot13(rot13('SecLab ATTT')), 'SecLab ATTT');
  assert.equal(rot13('aBc9!'), 'nOp9!'); // chữ hoa-thường giữ, số/ký tự khác giữ
});

test('hash: vector chuẩn sha256/md5 và từ chối thuật toán lạ', () => {
  assert.equal(hashText('sha256', 'test'), '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
  assert.equal(hashText('md5', 'test'), '098f6bcd4621d373cade4e832627b4f6');
  assert.throws(() => hashText('sha3', 'test'), /không hỗ trợ|sha256/);
});

test('runCodec: điều phối đúng op; op lạ ném lỗi có danh sách', () => {
  assert.equal(runCodec('b64enc', 'x'), 'eA==');
  assert.throws(() => runCodec('nope', 'x'), /b64enc/);
});

test('explain: có bài học cho mọi op và cho hash', () => {
  for (const op of ['b64enc', 'b64dec', 'hexenc', 'hexdec', 'urlenc', 'urldec', 'rot13', 'hash']) {
    assert.ok(explain(op).length > 40, `thiếu giải thích cho ${op}`);
  }
  assert.ok(explain('hash').includes('MD5')); // bài học "MD5/SHA-1 đã chết"
});
