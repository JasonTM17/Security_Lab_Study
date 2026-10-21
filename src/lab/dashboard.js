// dashboard.js — "Chọn bài LAB": catalog 20 lỗ hổng của SecLab.
// Hai nơi dùng:
//   • GET /lab trong lab app → dashboard tương tác (filter, tiến độ, nộp cờ CTF)
//   • scripts/assemble-hub.js → chuyên mục tĩnh "10 · Chọn bài LAB" cho SecHub/Pages
// Một nguồn dữ liệu LABS duy nhất → không bao giờ lệch giữa lab và hub.
import { esc } from './html.js';

export const CATEGORIES = {
  injection: 'Injection',
  xss: 'XSS',
  access: 'Truy cập & File',
  auth: 'Xác thực & Phiên',
  config: 'Cấu hình & Hardening',
  logic: 'Logic nâng cao',
};

export const DIFFS = { 1: 'Cơ bản', 2: 'Trung bình', 3: 'Nâng cao' };

// eps: method + path (GET có thể click mở trên lab sống; POST minh hoạ bằng code)
// payload: gợi ý khai thác để copy — vuln only, KHÔNG phải lời giải đầy đủ
// hard: cách kiểm chứng bản hardened (:3001)
export const LABS = [
  {
    id: 'LAB-01', code: 'sqli', title: 'SQL Injection — đăng nhập & tìm kiếm',
    en: 'SQL Injection', cat: 'injection', diff: 2,
    owasp: 'A03 Injection', cwe: 'CWE-89',
    eps: [
      { m: 'GET', p: '/search?q=alice', label: 'tìm người dùng (LIKE nối chuỗi)' },
      { m: 'POST', p: '/login', label: 'đăng nhập (nối chuỗi WHERE)' },
    ],
    goal: 'Dump toàn bộ bảng users qua LIKE, hoặc bypass đăng nhập không cần mật khẩu.',
    payload: ["/search?q=' OR 1=1 --", "login username=' OR 1=1 -- (password tuỳ ý)"],
    ex: 'exercises/04-tan-cong-lab.md',
    ctf: { id: 1, pts: 30 },
    hard: 'Cùng payload trên :3001 → 0 dòng dữ liệu (parameterized query).',
  },
  {
    id: 'LAB-02', code: 'xss', title: 'Reflected XSS — input in lại nguyên văn',
    en: 'Reflected Cross-Site Scripting', cat: 'xss', diff: 1,
    owasp: 'A03 Injection', cwe: 'CWE-79',
    eps: [
      { m: 'GET', p: '/search?q=<svg/onload=alert(1)>', label: 'kết quả echo q' },
      { m: 'GET', p: '/trang-khong-co-<script>alert(1)</script>', label: 'trang 404 cũng echo path' },
    ],
    goal: 'Chèn markup/script chạy trong trình duyệt — cả trang kết quả lẫn 404.',
    payload: ['/search?q=<svg/onload=alert(document.domain)>', '/search?q=<img src=x onerror=alert(1)>'],
    ex: 'exercises/04-tan-cong-lab.md',
    hard: 'Hardened esc() mọi output → payload hiện dạng chữ &lt;svg&gt;.',
  },
  {
    id: 'LAB-03', code: 'idor', title: 'IDOR — đọc hồ sơ người khác qua id',
    en: 'Insecure Direct Object Reference', cat: 'access', diff: 1,
    owasp: 'A01 Broken Access Control', cwe: 'CWE-639',
    eps: [{ m: 'GET', p: '/api/users/4', label: 'hồ sơ user theo id (không check quyền)' }],
    goal: 'Không đăng nhập vẫn đọc apiKey (chính là cờ CTF) của dave id=4.',
    payload: ['/api/users/4 — apiKey = FLAG{idor-...}', '/api/users/1 (alice admin)'],
    ex: 'exercises/04-tan-cong-lab.md',
    ctf: { id: 3, pts: 25 },
    hard: 'Chưa login → 401; login bob đọc /api/users/4 → 403.',
  },
  {
    id: 'LAB-04', code: 'trav', title: 'Path Traversal — leo ra ngoài files/',
    en: 'Path Traversal / LFI', cat: 'access', diff: 1,
    owasp: 'A01 Broken Access Control', cwe: 'CWE-22',
    eps: [
      { m: 'GET', p: '/files', label: 'listing thư mục files/' },
      { m: 'GET', p: '/download?name=readme.txt', label: 'tải file trong files/' },
    ],
    goal: 'Đọc flag-ctf.txt ở GỐC filesystem ảo — file không xuất hiện trong listing.',
    payload: ['/download?name=../flag-ctf.txt', '/download?name=../secrets.txt'],
    ex: 'exercises/04-tan-cong-lab.md',
    ctf: { id: 2, pts: 25 },
    hard: 'Mọi path chứa .. bị 400; chỉ cho phép prefix files/.',
  },
  {
    id: 'LAB-05', code: 'hdr', title: 'Thiếu security headers & cookie flags',
    en: 'Security Misconfiguration', cat: 'config', diff: 1,
    owasp: 'A05 Security Misconfiguration', cwe: 'CWE-693/1004',
    eps: [{ m: 'GET', p: '/', label: 'mọi response thiếu headers bảo vệ' }],
    goal: 'Quan sát: không CSP, X-Frame-Options, X-Content-Type-Options; cookie session không HttpOnly/SameSite/Secure.',
    payload: ['curl -si http://127.0.0.1:3000/ | head', 'login → xem Set-Cookie thiếu cờ'],
    ex: 'exercises/06-phong-thu-va-bao-cao.md',
    hard: 'Hardened có đủ securityHeaders() + cookie HttpOnly;SameSite=Strict.',
  },
  {
    id: 'LAB-06', code: 'ratelimit', title: 'Thiếu rate limiting — brute force tự do',
    en: 'Missing Rate Limit', cat: 'config', diff: 2,
    owasp: 'A07 Auth Failures', cwe: 'CWE-307',
    eps: [
      { m: 'POST', p: '/login', label: 'thử mật khẩu thoải mái' },
      { m: 'GET', p: '/slow', label: 'endpoint chậm 3s (đo tải)' },
    ],
    goal: 'Bắn hàng chục request/login sai liên tiếp — vuln không hề chặn.',
    payload: ['node src/cli.js loadtest http://127.0.0.1:3000 --path=slow --rps 40 --duration 8'],
    ex: 'exercises/05-mo-phong-tai-va-slowloris.md',
    hard: 'Bản hardened trả 429 sau ~20 request/4s (token bucket).',
  },
  {
    id: 'LAB-07', code: 'access', title: 'Thiếu kiểm soát truy cập — /admin mở toang',
    en: 'Broken Access Control', cat: 'access', diff: 1,
    owasp: 'A01 Broken Access Control', cwe: 'CWE-862',
    eps: [{ m: 'GET', p: '/admin', label: 'trang quản trị không cần quyền' }],
    goal: 'Mở /admin không đăng nhập — cờ CTF #4 hiện ngay trên trang.',
    payload: ['/admin (GET, không cần gì)'],
    ex: 'exercises/04-tan-cong-lab.md',
    ctf: { id: 4, pts: 20 },
    hard: 'Chưa login → 401; không phải admin → 403.',
  },
  {
    id: 'LAB-08', code: 'err', title: 'Verbose error — lộ stack trace & đường dẫn',
    en: 'Verbose Error Disclosure', cat: 'config', diff: 2,
    owasp: 'A05 Security Misconfiguration', cwe: 'CWE-209',
    eps: [
      { m: 'GET', p: "/search?q='", label: 'SQL error in thẳng ra response' },
      { m: 'GET', p: '/crash', label: 'endpoint cố ý ném exception' },
    ],
    goal: 'Đọc thông báo lỗi SQL + stack trace → lộ cấu trúc bảng, framework, đường dẫn file.',
    payload: ["/search?q=' (nháy đơn gây lỗi SQL)", '/crash (xem stack trace đầy đủ)'],
    ex: 'exercises/06-phong-thu-va-bao-cao.md',
    hard: 'Hardened trả thông báo chung chung, lỗi chỉ ghi server-side.',
  },
  {
    id: 'LAB-09', code: 'cmdinj', title: 'OS Command Injection — ping chêm lệnh',
    en: 'OS Command Injection', cat: 'injection', diff: 2,
    owasp: 'A03 Injection', cwe: 'CWE-78',
    eps: [{ m: 'GET', p: '/tools/ping?host=127.0.0.1', label: 'chẩn đoán mạng qua exec()' }],
    goal: 'Nối lệnh sau host bằng & / ; → chạy lệnh tự do; cờ trong biến môi trường SECLAB_CTF_CMD.',
    payload: ['host=127.0.0.1 & set SECLAB (Windows)', 'host=127.0.0.1; env (Linux/macOS)'],
    ex: 'exercises/10-command-injection.md',
    ctf: { id: 5, pts: 25 },
    hard: 'execFile không qua shell + whitelist [a-z0-9.-] → payload 400.',
  },
  {
    id: 'LAB-10', code: 'csrf', title: 'CSRF — đổi email không token',
    en: 'Cross-Site Request Forgery', cat: 'auth', diff: 2,
    owasp: 'A01 Broken Access Control', cwe: 'CWE-352',
    eps: [{ m: 'POST', p: '/settings/email', label: 'đổi email tài khoản' }],
    goal: 'Đăng nhập rồi POST đổi email từ Origin lạ không kèm CSRF token → vẫn 200.',
    payload: ['curl -X POST /settings/email -d "email=evil@x" -H "Origin: http://evil.local" (kèm cookie session)'],
    ex: 'exercises/12-csrf-va-redirect.md',
    hard: 'Thiếu/sai _csrf token hoặc Origin lạ → 403.',
  },
  {
    id: 'LAB-11', code: 'jwt', title: 'JWT yếu — secret123 + alg=none',
    en: 'Weak JWT', cat: 'auth', diff: 2,
    owasp: 'A02 Cryptographic Failures', cwe: 'CWE-347/327',
    eps: [
      { m: 'POST', p: '/api/token', label: 'cấp token HS256' },
      { m: 'GET', p: '/api/profile', label: 'xác thực token (chấp nhận none)' },
    ],
    goal: 'Forge token sub=ctfsvc (không tồn tại trong DB) → /api/profile trả cờ.',
    payload: ['jwt forge --payload={sub:ctfsvc} --alg=none', 'jwt crack <token> → secret123'],
    ex: 'exercises/11-jwt.md',
    ctf: { id: 6, pts: 25 },
    hard: 'Verify từ chối alg=none; khoá ngẫu nhiên 256-bit theo phiên.',
  },
  {
    id: 'LAB-12', code: 'oredir', title: 'Open Redirect — tin Location thô',
    en: 'Unvalidated Redirect', cat: 'config', diff: 1,
    owasp: 'A01 Broken Access Control', cwe: 'CWE-601',
    eps: [{ m: 'GET', p: '/redirect?to=/', label: 'redirect theo param to=' }],
    goal: 'to=https://evil.example → 302 thẳng ra domain ngoài — bệ phóng phishing.',
    payload: ['/redirect?to=https://evil.example', '/redirect?to=//evil.example (scheme-relative)'],
    ex: 'exercises/12-csrf-va-redirect.md',
    hard: 'Chỉ cho phép path nội bộ bắt đầu /; URL ngoài → 400.',
  },
  {
    id: 'LAB-13', code: 'upload', title: 'Unrestricted Upload — tải .html chạy script',
    en: 'Unrestricted File Upload', cat: 'access', diff: 2,
    owasp: 'A05 Security Misconfiguration', cwe: 'CWE-434',
    eps: [
      { m: 'POST', p: '/upload', label: 'tải file lên VFS' },
      { m: 'GET', p: '/uploads/:name', label: 'serve lại file đúng MIME' },
    ],
    goal: 'Upload file .html chứa <script> rồi mở /uploads/x.html — script chạy cùng origin.',
    payload: ['upload x.html chứa <script>alert(1)</script> → GET /uploads/x.html'],
    ex: 'exercises/13-upload-xxe-stored-xss.md',
    hard: 'Whitelist đuôi + octet-stream + nosniff → .html bị 415.',
  },
  {
    id: 'LAB-14', code: 'xxe', title: 'XXE — entity đọc file (mô phỏng trên VFS)',
    en: 'XML External Entity', cat: 'injection', diff: 2,
    owasp: 'A05 Security Misconfiguration', cwe: 'CWE-611',
    eps: [{ m: 'POST', p: '/api/import', label: 'import XML items' }],
    goal: '<!ENTITY x SYSTEM "file:///flag-xxe.txt"> → nội dung file nằm trong response.',
    payload: ['<i><item>&x;</item></i> với DOCTYPE ENTITY file:///flag-xxe.txt'],
    ex: 'exercises/13-upload-xxe-stored-xss.md',
    ctf: { id: 7, pts: 20 },
    hard: 'Mọi body chứa DOCTYPE/ENTITY → 400 dtd_prohibited.',
  },
  {
    id: 'LAB-15', code: 'sxss', title: 'Stored XSS — comment lưu trên server',
    en: 'Stored Cross-Site Scripting', cat: 'xss', diff: 1,
    owasp: 'A03 Injection', cwe: 'CWE-79',
    eps: [
      { m: 'GET', p: '/guestbook', label: 'sổ lưu niệm render comment' },
      { m: 'POST', p: '/guestbook', label: 'gửi comment (không escape)' },
    ],
    goal: 'Post <svg/onload=...> → mọi visitor mở /guestbook đều chạy — nguy hiểm hơn reflected vì không cần lừa click.',
    payload: ['POST /guestbook name=x&msg=<svg/onload=alert(1)>'],
    ex: 'exercises/13-upload-xxe-stored-xss.md',
    hard: 'Comment được esc() trước khi render.',
  },
  {
    id: 'LAB-16', code: 'proto', title: 'Prototype Pollution — merge nhiễm __proto__',
    en: 'Prototype Pollution', cat: 'logic', diff: 3,
    owasp: 'A03 Injection', cwe: 'CWE-1321',
    eps: [
      { m: 'POST', p: '/api/config', label: 'merge JSON vào config' },
      { m: 'GET', p: '/api/config', label: 'xem config + protoPolluted' },
    ],
    goal: '{"__proto__":{"isAdmin":true}} → nhiễm Object.prototype → cờ lộ ở GET.',
    payload: ['{"__proto__":{"isAdmin":true}} → sau đó GET /api/config'],
    ex: 'exercises/14-prototype-pollution-va-mass-assignment.md',
    ctf: { id: 8, pts: 30 },
    hard: 'safeMerge() lọc __proto__/constructor/prototype → protoPolluted rỗng.',
  },
  {
    id: 'LAB-17', code: 'mass', title: 'Mass Assignment — tự gán role=admin',
    en: 'Mass Assignment', cat: 'logic', diff: 3,
    owasp: 'A01 Broken Access Control', cwe: 'CWE-915',
    eps: [
      { m: 'POST', p: '/api/register', label: 'đăng ký — copy mọi field kể cả query' },
      { m: 'GET', p: '/api/me', label: 'hồ sơ phiên hiện tại' },
    ],
    goal: 'Đăng ký kèm ?role=admin → login → /api/me role=admin + cờ.',
    payload: ['POST /api/register?role=admin với username+password mới'],
    ex: 'exercises/14-prototype-pollution-va-mass-assignment.md',
    ctf: { id: 9, pts: 25 },
    hard: 'Whitelist cứng {username,password} → role luôn "user".',
  },
  {
    id: 'LAB-18', code: 'blind', title: 'Blind SQLi — oracle boolean 200/404',
    en: 'Blind SQL Injection', cat: 'injection', diff: 3,
    owasp: 'A03 Injection', cwe: 'CWE-89',
    eps: [{ m: 'GET', p: '/track?code=AB-100', label: 'tra mã vận đơn (2 trạng thái)' }],
    goal: 'Rút cờ từng ký tự từ bảng ẩn ctf_blind bằng substr() qua oracle 200/404 — thử thách khó nhất.',
    payload: ["code=AB-100' AND 1=1 -- (200) vs AND 1=2 -- (404)", "AND substr(flag,N,1)='X' để đoán từng ký tự"],
    ex: 'exercises/15-blind-sqli.md',
    ctf: { id: 10, pts: 40 },
    hard: 'Parameterized → oracle biến mất, mọi payload đều 404.',
  },
  {
    id: 'LAB-19', code: 'reset', title: 'Reset token đoán được — md5(username)',
    en: 'Predictable Reset Token', cat: 'auth', diff: 2,
    owasp: 'A07 Auth Failures', cwe: 'CWE-330',
    eps: [
      { m: 'POST', p: '/api/reset/request', label: 'xin reset token (vuln trả token trong response!)' },
      { m: 'POST', p: '/api/reset/confirm', label: 'đổi mật khẩu bằng token' },
    ],
    goal: 'Token = md5(username)[0:12] → tự tính token của dave, đổi pass, login chiếm account.',
    payload: ['node src/cli.js codec hash md5 dave → 12 ký tự đầu', 'POST confirm {token, password mới}'],
    ex: 'exercises/16-reset-token-va-dom-xss.md',
    hard: 'crypto.randomBytes(16) + TTL 10p + one-time + không lộ token.',
  },
  {
    id: 'LAB-20', code: 'dom', title: 'DOM-based XSS — location.hash → innerHTML',
    en: 'DOM-based XSS', cat: 'xss', diff: 2,
    owasp: 'A03 Injection', cwe: 'CWE-79',
    eps: [{ m: 'GET', p: '/dom', label: 'trang đọc hash bằng JS phía client' }],
    goal: 'Mở /dom#<svg onload=alert(1)> — payload trong fragment KHÔNG bao giờ lên server (telemetry mù).',
    payload: ['/dom#<svg onload=alert(1)>', '/dom#<img src=x onerror=alert(1)>'],
    ex: 'exercises/16-reset-token-va-dom-xss.md',
    hard: 'textContent thay innerHTML → hash hiện dạng chữ.',
  },
];

const DIFF_STARS = ['★', '★★', '★★★'];

function renderEndpoint(ep, interactive) {
  const mp = `${ep.m} ${ep.p}`;
  if (interactive && ep.m === 'GET') {
    return `<li><a href="${esc(ep.p)}" target="_blank" rel="noopener">${esc(mp)}</a>${ep.label ? ` — ${esc(ep.label)}` : ''}</li>`;
  }
  return `<li><code>${esc(mp)}</code>${ep.label ? ` — ${esc(ep.label)}` : ''}</li>`;
}

function renderCard(lab, { interactive = true } = {}) {
  const cat = CATEGORIES[lab.cat];
  const payloads = lab.payload
    .map((p) => `<li><code>${esc(p)}</code> <button class="cp" data-cp="${esc(p)}" title="Sao chép">⧉</button></li>`)
    .join('');
  const ctf = lab.ctf
    ? `<span class="chip ctf">🏆 CTF #${lab.ctf.id} · ${lab.ctf.pts}đ</span>`
    : '';
  return `
<article class="card" data-cat="${lab.cat}" data-diff="${lab.diff}" data-ctf="${lab.ctf ? 1 : 0}" id="${lab.id.toLowerCase()}">
  <header>
    <span class="labid">${lab.id}</span>
    <span class="stars" title="${DIFFS[lab.diff]}">${DIFF_STARS[lab.diff - 1]}</span>
    <span class="chip cat">${esc(cat)}</span>
    ${ctf}
  </header>
  <h3>${esc(lab.title)}</h3>
  <p class="en">${esc(lab.en)} · ${esc(lab.owasp)} · ${esc(lab.cwe)}</p>
  <p class="goal">🎯 ${esc(lab.goal)}</p>
  <ul class="eps">${lab.eps.map((e) => renderEndpoint(e, interactive)).join('')}</ul>
  <details class="hint"><summary>💡 Payload gợi ý (vuln)</summary><ul>${payloads}</ul></details>
  <p class="check">✅ Kiểm chứng hardened: ${esc(lab.hard)}</p>
  <footer>
    <span class="ex">📖 ${esc(lab.ex)}</span>
    <label class="done"><input type="checkbox" data-done="${lab.id}"> Đã xong</label>
  </footer>
</article>`;
}

const DASH_CSS = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,'Segoe UI',sans-serif;background:#0b1220;color:#e2e8f0;margin:0;padding:0 1rem 3rem}
a{color:#4ade80}
code{background:#1e293b;color:#e2e8f0;padding:1px 5px;border-radius:4px;font-size:.85em}
.wrap{max-width:1280px;margin:0 auto}
.mode{display:inline-block;padding:2px 12px;border-radius:12px;font-weight:700;font-size:.85em}
.vuln{background:#450a0a;color:#fca5a5}.hardened{background:#052e16;color:#86efac}
h1{margin:.4rem 0 .2rem}
.sub{color:#94a3b8;margin:0 0 1rem}
.stats{display:flex;gap:.6rem;flex-wrap:wrap;margin:.8rem 0}
.stat{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:.45rem .9rem;font-size:.9rem}
.stat b{color:#4ade80}
.progress{height:10px;background:#1e293b;border-radius:6px;overflow:hidden;margin:.6rem 0 1rem;border:1px solid #334155}
.progress>div{height:100%;background:linear-gradient(90deg,#16a34a,#4ade80);width:0;transition:width .3s}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:1rem 0;padding:.8rem;background:#0f172a;border:1px solid #1e293b;border-radius:12px;position:sticky;top:0;z-index:5}
.filters button,.filters .ftoggle{background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:8px;padding:.35rem .8rem;cursor:pointer;font-size:.85rem}
.filters button.on{background:#166534;color:#dcfce7;border-color:#16a34a}
.filters input[type=search]{background:#1e293b;border:1px solid #334155;color:#e2e8f0;border-radius:8px;padding:.4rem .7rem;min-width:200px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:1rem}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:1rem;display:flex;flex-direction:column;gap:.5rem}
.card.is-done{border-color:#16a34a;opacity:.85}
.card header{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.labid{font-weight:800;color:#fbbf24;letter-spacing:.5px}
.stars{color:#f59e0b;font-size:.85rem}
.chip{border-radius:8px;padding:1px 8px;font-size:.75rem;border:1px solid #334155;color:#94a3b8}
.chip.cat{border-color:#0ea5e9;color:#7dd3fc}
.chip.ctf{border-color:#f59e0b;color:#fcd34d}
.card h3{margin:.1rem 0;font-size:1.05rem}
.en{color:#64748b;font-size:.8rem;margin:0}
.goal{margin:0;font-size:.9rem;color:#c4b5fd}
.eps{margin:0;padding-left:1.2rem;font-size:.85rem}
.eps li{margin:.15rem 0}
.hint{font-size:.85rem}
.hint summary{cursor:pointer;color:#fbbf24}
.hint ul{margin:.4rem 0;padding-left:1.1rem}
.cp{background:none;border:0;color:#64748b;cursor:pointer;font-size:1em;padding:0 2px}
.cp:hover{color:#4ade80}
.check{margin:0;font-size:.8rem;color:#86efac}
.card footer{display:flex;justify-content:space-between;align-items:center;font-size:.75rem;color:#64748b;border-top:1px dashed #1e293b;padding-top:.5rem}
.done{cursor:pointer}
.panel{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:1rem;margin:1.2rem 0}
.panel h2{margin-top:0;font-size:1.1rem}
#ctflist{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.6rem}
.ctfitem{background:#1e293b;border-radius:8px;padding:.6rem;font-size:.85rem}
.ctfitem.solved{border:1px solid #16a34a}
.ctfitem .pts{color:#fcd34d}
.submit{display:flex;gap:.5rem;margin-top:.8rem;flex-wrap:wrap}
.submit input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;border-radius:8px;padding:.45rem .7rem}
.submit input[name=flag]{flex:1;min-width:220px;font-family:monospace}
.submit button{background:#166534;color:#dcfce7;border:0;border-radius:8px;padding:.45rem 1.1rem;cursor:pointer;font-weight:600}
.warn{background:#450a0a;border:1px solid #7f1d1d;border-radius:10px;padding:.6rem .9rem;font-size:.85rem;color:#fca5a5;margin:.8rem 0}
.hide{display:none!important}
@media(max-width:480px){.grid{grid-template-columns:1fr}}
`;

const DASH_JS = `
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
// --- filter theo category/difficulty/ctf/search ---
const st={cat:'all',diff:0,ctf:false,q:''};
function apply(){
  $$('.card').forEach(c=>{
    const ok=(st.cat==='all'||c.dataset.cat===st.cat)
      &&(!st.diff||+c.dataset.diff===st.diff)
      &&(!st.ctf||c.dataset.ctf==='1')
      &&(!st.q||c.textContent.toLowerCase().includes(st.q));
    c.classList.toggle('hide',!ok);
  });
  $('#count').textContent=$$('.card:not(.hide)').length;
}
$$('.fbtn').forEach(b=>b.onclick=()=>{
  if(b.dataset.k==='cat'){st.cat=b.dataset.v;$$('[data-k=cat]').forEach(x=>x.classList.toggle('on',x===b));}
  else{st.diff=st.diff===+b.dataset.v?0:+b.dataset.v;$$('[data-k=diff]').forEach(x=>x.classList.toggle('on',x===b&&st.diff));}
  apply();
});
$('#fctf').onchange=e=>{st.ctf=e.target.checked;apply();};
$('#fsearch').oninput=e=>{st.q=e.target.value.toLowerCase();apply();};
// --- copy payload ---
$$('.cp').forEach(b=>b.onclick=()=>{navigator.clipboard?.writeText(b.dataset.cp);b.textContent='✓';setTimeout(()=>b.textContent='⧉',800);});
// --- tiến độ localStorage ---
const KEY='seclab-lab-done';
const done=new Set(JSON.parse(localStorage.getItem(KEY)||'[]'));
function paint(){
  $$('[data-done]').forEach(cb=>{
    cb.checked=done.has(cb.dataset.done);
    cb.closest('.card').classList.toggle('is-done',cb.checked);
  });
  $('#prog').style.width=(done.size/20*100)+'%';
  $('#progtxt').textContent=done.size+'/20 bài';
}
$$('[data-done]').forEach(cb=>cb.onchange=()=>{
  cb.checked?done.add(cb.dataset.done):done.delete(cb.dataset.done);
  localStorage.setItem(KEY,JSON.stringify([...done]));paint();
});
paint();
// --- CTF live ---
async function loadCtf(){
  try{
    const r=await fetch('/_lab/challenges');const j=await r.json();
    if(!j.enabled){$('#ctflist').innerHTML='<p class="sub">Bản HARDENED — CTF tắt (đó chính là bài học).</p>';return;}
    $('#ctflist').innerHTML=j.challenges.map(c=>
      '<div class="ctfitem'+(c.solved?' solved':'')+'"><b>#'+c.id+'</b> '+c.title+
      ' <span class="pts">'+c.points+'đ</span>'+(c.solved?' ✅':'')+
      '<details><summary>gợi ý</summary><p>'+c.hint+'</p></details></div>').join('');
    $('#score').textContent=j.score+'/'+j.total+'đ';
  }catch(e){$('#ctflist').innerHTML='<p class="sub">Không đọc được /_lab/challenges.</p>';}
}
loadCtf();
$('#ctfsend').onclick=async()=>{
  const id=$('#ctfid').value,flag=$('#ctfflag').value.trim();
  const r=await fetch('/_lab/verify?id='+encodeURIComponent(id)+'&flag='+encodeURIComponent(flag));
  const j=await r.json();
  $('#ctfmsg').textContent=j.ok?'✅ Đúng! +điểm ('+j.score+'/'+j.total+')':'❌ '+(j.message||'Cờ sai — thử lại.');
  if(j.ok){$('#ctfflag').value='';loadCtf();}
};
`;

/** Trang dashboard tương tác — GET /lab trên lab sống. */
export function renderDashboard(mode) {
  const hardened = mode === 'hardened';
  const cards = LABS.map((l) => renderCard(l, { interactive: true })).join('');
  const catBtns = ['all', ...Object.keys(CATEGORIES)]
    .map((k) => `<button class="fbtn ${k === 'all' ? 'on' : ''}" data-k="cat" data-v="${k}">${k === 'all' ? 'Tất cả' : esc(CATEGORIES[k])}</button>`)
    .join('');
  const diffBtns = [1, 2, 3]
    .map((d) => `<button class="fbtn" data-k="diff" data-v="${d}">${DIFF_STARS[d - 1]} ${DIFFS[d]}</button>`)
    .join('');
  const ctfCount = LABS.filter((l) => l.ctf).length;
  const ctfPts = LABS.reduce((s, l) => s + (l.ctf?.pts || 0), 0);
  return `<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Chọn bài LAB — SecLab [${mode.toUpperCase()}]</title>
<style>${DASH_CSS}</style></head><body><div class="wrap">
<p style="margin-top:1rem"><span class="mode ${mode}">LAB ${mode.toUpperCase()}</span></p>
<h1>🧪 Chọn bài LAB — Dashboard thực hành</h1>
<p class="sub">20 lỗ hổng cố ý · mỗi bài có mục tiêu, endpoint, payload gợi ý và cách kiểm chứng bản đã vá.
Đánh dấu "Đã xong" — tiến độ lưu ngay trên trình duyệt của bạn.</p>
<div class="stats">
  <span class="stat">📚 <b>20</b> bài lab</span>
  <span class="stat">🏆 <b>${ctfCount}</b> thử thách CTF · <b>${ctfPts}</b>đ</span>
  <span class="stat">🧭 <b>6</b> nhóm kỹ năng</span>
  <span class="stat">🛡 bản đối chứng: <a href="http://127.0.0.1:3001/lab">127.0.0.1:3001</a></span>
  <span class="stat">Điểm CTF phiên: <b id="score">—</b></span>
</div>
${hardened ? '<p class="warn">⚠ Bạn đang ở bản <b>HARDENED</b> — các lỗ hổng đã vá. Dùng trang này để <b>đối chứng</b>: payload gợi ý phải BỊ CHẶN. Khai thác thật hãy mở <a href="http://127.0.0.1:3000/lab">bản vuln :3000</a>.</p>' : ''}
<div class="progress" title="Tiến độ bài lab"><div id="prog"></div></div>
<p class="sub">Tiến độ của bạn: <b id="progtxt">0/20 bài</b> · đang hiển thị <b id="count">20</b> bài</p>
<div class="filters">
  ${catBtns}
  <span style="color:#334155">|</span>
  ${diffBtns}
  <label class="ftoggle"><input type="checkbox" id="fctf"> chỉ CTF</label>
  <input type="search" id="fsearch" placeholder="🔍 tìm theo tên / CWE / endpoint…">
</div>
<div class="grid">${cards}</div>
<div class="panel" id="ctf">
  <h2>🏆 Nộp cờ CTF ngay tại đây</h2>
  <p class="sub">Khai thác lab → lấy <code>FLAG{...}</code> → chọn thử thách và nộp. Cờ sinh ngẫu nhiên theo phiên — đáp án không thể chép.</p>
  <div id="ctflist"><p class="sub">Đang tải…</p></div>
  <div class="submit">
    <input name="id" id="ctfid" type="number" min="1" max="10" placeholder="#" style="width:70px">
    <input name="flag" id="ctfflag" placeholder="FLAG{...}">
    <button id="ctfsend">Nộp cờ</button>
    <span id="ctfmsg" class="sub" style="align-self:center"></span>
  </div>
</div>
<p class="sub">📚 Giáo trình đầy đủ: <a href="https://jasontm17.github.io/Security_Lab_Study/" target="_blank" rel="noopener">SecHub Online</a> ·
lời giải (SPOILER): <code>solutions/</code> trong repo · <a href="/">trang chủ lab</a> · <a href="/_lab/metrics">/_lab/metrics</a></p>
</div><script>${DASH_JS}</script></body></html>`;
}

/**
 * Catalog tĩnh cho hub/Pages — một bảng đủ 20 bài, nhóm theo category.
 * Trang tương tác đầy đủ nằm tại http://127.0.0.1:3000/lab (lab sống).
 */
export function renderCatalog() {
  const rows = (cat) =>
    LABS.filter((l) => l.cat === cat)
      .map(
        (l) => `<tr>
<td><b>${l.id}</b><br>${DIFF_STARS[l.diff - 1]}</td>
<td><b>${esc(l.title)}</b><br><small>${esc(l.en)} · ${esc(l.cwe)}</small></td>
<td>${l.eps.map((e) => `<code>${esc(e.m)} ${esc(e.p)}</code>`).join('<br>')}</td>
<td>${esc(l.goal)}</td>
<td>${l.ctf ? `🏆 CTF #${l.ctf.id} · ${l.ctf.pts}đ` : '—'}</td>
<td><code>${esc(l.ex)}</code></td>
</tr>`
      )
      .join('');
  const group = (cat) => `
<h3>${esc(CATEGORIES[cat])} <small>(${LABS.filter((l) => l.cat === cat).length} bài)</small></h3>
<table>
<thead><tr><th>Bài</th><th>Lỗ hổng</th><th>Endpoint</th><th>Mục tiêu</th><th>CTF</th><th>Bài tập</th></tr></thead>
<tbody>${rows(cat)}</tbody>
</table>`;
  return Object.keys(CATEGORIES).map(group).join('\n');
}
