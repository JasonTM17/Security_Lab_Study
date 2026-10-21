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

// Màu + mô tả nhóm — dùng cho group header trên dashboard & border thẻ.
export const CAT_META = {
  injection: { color: '#f43f5e', desc: 'Dữ liệu bị trộn vào cú pháp lệnh/query — SQL, shell, XML entity' },
  xss: { color: '#fb923c', desc: 'Script thực thi trong trình duyệt nạn nhân — reflected, stored, DOM' },
  access: { color: '#a78bfa', desc: 'Vượt quyền đọc/ghi đối tượng — IDOR, traversal, admin, upload' },
  auth: { color: '#38bdf8', desc: 'Đánh cắp hoặc giả mạo danh tính — CSRF, JWT, reset token' },
  config: { color: '#facc15', desc: 'Thiếu hàng rào mặc định — headers, rate limit, lỗi chi tiết, redirect' },
  logic: { color: '#4ade80', desc: 'Lỗi ngữ nghĩa ứng dụng — prototype pollution, mass assignment' },
};

// Bài lab → detection rule nào của detect.js sẽ nhìn thấy (log phía blue-team).
// Bài KHÔNG có trong map = telemetry mù — bài học: access log không đủ.
export const LAB_DETECT = {
  'LAB-01': ['sqli'], 'LAB-02': ['xss'], 'LAB-03': [],
  'LAB-04': ['traversal', 'secret-probe'], 'LAB-05': [], 'LAB-06': ['brute-force'],
  'LAB-07': ['admin-probe'], 'LAB-08': [], 'LAB-09': ['cmdinj'],
  'LAB-10': [], 'LAB-11': ['jwt-probe'], 'LAB-12': ['open-redir'],
  'LAB-13': ['upload-abuse'], 'LAB-14': ['xxe'], 'LAB-15': ['xss'],
  'LAB-16': ['proto-pollution'], 'LAB-17': ['mass-assign'], 'LAB-18': ['blind-sqli'],
  'LAB-19': ['reset-probe'], 'LAB-20': [],
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
  const color = CAT_META[lab.cat]?.color || '#334155';
  return `
<article class="card" style="--cat:${color}" data-cat="${lab.cat}" data-diff="${lab.diff}" data-ctf="${lab.ctf ? 1 : 0}" id="${lab.id.toLowerCase()}">
  <header>
    <span class="labid">${lab.id}</span>
    <span class="stars" title="${DIFFS[lab.diff]}">${DIFF_STARS[lab.diff - 1]}</span>
    <span class="chip cat" style="border-color:${color};color:${color}">${esc(cat)}</span>
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

// ─── Theme chung cho cả hai dashboard — mỗi team một accent ───
const DASH_CSS = `
:root{color-scheme:dark;--ac:#ef4444;--ac2:#f97316;--bg:#0a0f1a;--card:#0f172a;--line:#1e293b;--txt:#e2e8f0;--dim:#94a3b8}
*{box-sizing:border-box}
body{font-family:system-ui,'Segoe UI',sans-serif;background:var(--bg);color:var(--txt);margin:0;padding-bottom:3rem}
a{color:var(--ac)}
code{background:#1e293b;color:#e2e8f0;padding:1px 5px;border-radius:4px;font-size:.85em}
.wrap{max-width:1300px;margin:0 auto;padding:0 1rem}
/* ── top nav ── */
.topnav{display:flex;align-items:center;gap:1rem;padding:.7rem 1.2rem;background:#0d1424;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
.brand{font-weight:800;letter-spacing:.5px;font-size:1.05rem}
.brand em{font-style:normal;color:var(--ac)}
.navtab{padding:.35rem .95rem;border-radius:8px;color:var(--dim);text-decoration:none;font-size:.88rem;border:1px solid transparent}
.navtab:hover{color:var(--txt);border-color:var(--line)}
.navtab.on{color:var(--txt);border-color:var(--ac);background:color-mix(in srgb,var(--ac) 14%,transparent)}
.mode{margin-left:auto;display:inline-block;padding:3px 12px;border-radius:12px;font-weight:700;font-size:.8rem}
.vuln{background:#450a0a;color:#fca5a5}.hardened{background:#052e16;color:#86efac}
/* ── hero ── */
.hero{margin:1.2rem 0;padding:1.4rem 1.5rem;border-radius:16px;border:1px solid var(--line);
  background:linear-gradient(135deg,color-mix(in srgb,var(--ac) 16%,var(--card)) 0%,var(--card) 55%)}
.hero h1{margin:.1rem 0 .3rem;font-size:1.7rem}
.hero .tag{color:var(--ac);font-weight:700;letter-spacing:2px;font-size:.75rem;text-transform:uppercase}
.sub{color:var(--dim);margin:0}
.stats{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
.stat{background:#101a30;border:1px solid var(--line);border-radius:10px;padding:.5rem .95rem;font-size:.88rem}
.stat b{color:var(--ac)}
/* ── progress + filters ── */
.progress{height:10px;background:#1e293b;border-radius:6px;overflow:hidden;margin:.8rem 0 .4rem;border:1px solid var(--line)}
.progress>div{height:100%;background:linear-gradient(90deg,var(--ac),var(--ac2));width:0;transition:width .3s}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.9rem 0;padding:.75rem .8rem;background:var(--card);border:1px solid var(--line);border-radius:12px;position:sticky;top:52px;z-index:5}
.filters button,.filters .ftoggle{background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:8px;padding:.35rem .8rem;cursor:pointer;font-size:.85rem}
.filters button.on{background:color-mix(in srgb,var(--ac) 25%,#1e293b);color:#fff;border-color:var(--ac)}
.filters input[type=search]{background:#1e293b;border:1px solid #334155;color:var(--txt);border-radius:8px;padding:.4rem .7rem;min-width:210px}
/* ── group sections ── */
.group{margin:1.4rem 0 .6rem}
.group>h2{display:flex;align-items:center;gap:.55rem;font-size:1.05rem;margin:0 0 .15rem}
.group .dot{width:11px;height:11px;border-radius:50%;flex:none}
.group .gdesc{color:var(--dim);font-size:.82rem;margin:0 0 .6rem 1.6rem}
.group .gcount{color:var(--dim);font-weight:400;font-size:.8rem}
/* ── cards ── */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(370px,1fr));gap:.9rem}
.card{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--cat,#334155);border-radius:12px;padding:1rem;display:flex;flex-direction:column;gap:.5rem;transition:transform .15s,box-shadow .15s}
.card:hover{transform:translateY(-2px);box-shadow:0 6px 22px -8px color-mix(in srgb,var(--cat) 45%,transparent)}
.card.is-done{border-color:#16a34a;border-left-color:#16a34a;opacity:.8}
.card header{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.labid{font-weight:800;color:#fbbf24;letter-spacing:.5px}
.stars{color:#f59e0b;font-size:.85rem}
.chip{border-radius:8px;padding:1px 8px;font-size:.75rem;border:1px solid #334155;color:var(--dim)}
.chip.ctf{border-color:#f59e0b;color:#fcd34d}
.card h3{margin:.1rem 0;font-size:1.02rem}
.en{color:#64748b;font-size:.8rem;margin:0}
.goal{margin:0;font-size:.88rem;color:#c4b5fd}
.eps{margin:0;padding-left:1.2rem;font-size:.85rem}
.eps li{margin:.15rem 0}
.hint{font-size:.85rem}
.hint summary{cursor:pointer;color:#fbbf24}
.hint ul{margin:.4rem 0;padding-left:1.1rem}
.cp{background:none;border:0;color:#64748b;cursor:pointer;font-size:1em;padding:0 2px}
.cp:hover{color:var(--ac)}
.check{margin:0;font-size:.8rem;color:#86efac}
.card footer{display:flex;justify-content:space-between;align-items:center;font-size:.75rem;color:#64748b;border-top:1px dashed var(--line);padding-top:.5rem}
.done{cursor:pointer}
/* ── panels ── */
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.1rem;margin:1.2rem 0}
.panel h2{margin-top:0;font-size:1.05rem}
#ctflist{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.6rem}
.ctfitem{background:#101a30;border-radius:8px;padding:.6rem;font-size:.85rem;border:1px solid transparent}
.ctfitem.solved{border-color:#16a34a}
.ctfitem .pts{color:#fcd34d}
.submit{display:flex;gap:.5rem;margin-top:.8rem;flex-wrap:wrap}
.submit input{background:#1e293b;border:1px solid #334155;color:var(--txt);border-radius:8px;padding:.45rem .7rem}
.submit input[name=flag]{flex:1;min-width:220px;font-family:monospace}
.submit button{background:color-mix(in srgb,var(--ac) 30%,#1e293b);color:#fff;border:1px solid var(--ac);border-radius:8px;padding:.45rem 1.1rem;cursor:pointer;font-weight:600}
.warn{background:#450a0a;border:1px solid #7f1d1d;border-radius:10px;padding:.6rem .9rem;font-size:.85rem;color:#fca5a5;margin:.8rem 0}
.hide{display:none!important}
/* ── blue-team widgets ── */
.feedtbl{width:100%;border-collapse:collapse;font-family:ui-monospace,Consolas,monospace;font-size:.78rem}
.feedtbl td,.feedtbl th{border-bottom:1px solid var(--line);padding:.3rem .5rem;text-align:left;vertical-align:top}
.feedtbl th{color:var(--dim);font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.5px}
.feedtbl tr.sus td{background:rgba(244,63,94,.08)}
.feedtbl .sev-high{color:#f87171;font-weight:700}
.feedtbl .sev-med{color:#fbbf24}
.feedtbl .sev-ok{color:#4ade80}
.feedbox{max-height:340px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.pill{display:inline-block;border-radius:6px;padding:0 6px;font-size:.72rem;font-weight:700}
.pill.high{background:#450a0a;color:#fca5a5}.pill.medium{background:#422006;color:#fcd34d}.pill.low{background:#0c2f26;color:#6ee7b7}
.alert{border:1px solid var(--line);border-left:3px solid var(--ac);border-radius:10px;padding:.7rem .9rem;margin:.5rem 0;background:#101a30}
.alert h4{margin:0 0 .25rem;font-size:.92rem;display:flex;gap:.5rem;align-items:center}
.alert .def{color:#86efac;font-size:.8rem;margin:.35rem 0 0}
.alert .samp{font-family:monospace;font-size:.75rem;color:#94a3b8}
.rules{width:100%;border-collapse:collapse;font-size:.85rem}
.rules td,.rules th{border-bottom:1px solid var(--line);padding:.45rem .6rem;text-align:left;vertical-align:top}
.bluegrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:.8rem}
.bcard{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--cat,#38bdf8);border-radius:10px;padding:.8rem;font-size:.85rem}
.bcard h4{margin:0 0 .3rem;font-size:.92rem}
.bcard .muted{color:#64748b;font-size:.78rem}
.live{display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ade80;margin-right:.4rem;animation:blink 1.2s infinite}
.live.off{background:#475569;animation:none}
@keyframes blink{50%{opacity:.3}}
@media(max-width:480px){.grid{grid-template-columns:1fr}}
`;

const NAV = (mode, active) => `
<nav class="topnav">
  <span class="brand">⚔ Sec<em>Lab</em> Console</span>
  <a class="navtab" href="/">🏠 Trang chủ</a>
  <a class="navtab ${active === 'red' ? 'on' : ''}" href="/lab">🔴 Red Team</a>
  <a class="navtab ${active === 'blue' ? 'on' : ''}" href="/blue">🔵 Blue Team</a>
  <a class="navtab" href="https://jasontm17.github.io/Security_Lab_Study/" target="_blank" rel="noopener">📚 SecHub</a>
  <span class="mode ${mode}">LAB ${mode.toUpperCase()}</span>
</nav>`;

const RED_JS = `
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const st={cat:'all',diff:0,ctf:false,q:''};
function apply(){
  let shown=0;
  $$('.card').forEach(c=>{
    const ok=(st.cat==='all'||c.dataset.cat===st.cat)
      &&(!st.diff||+c.dataset.diff===st.diff)
      &&(!st.ctf||c.dataset.ctf==='1')
      &&(!st.q||c.textContent.toLowerCase().includes(st.q));
    c.classList.toggle('hide',!ok);if(ok)shown++;
  });
  $$('.group').forEach(g=>{g.classList.toggle('hide',![...g.querySelectorAll('.card')].some(c=>!c.classList.contains('hide')))});
  $('#count').textContent=shown;
}
$$('.fbtn').forEach(b=>b.onclick=()=>{
  if(b.dataset.k==='cat'){st.cat=b.dataset.v;$$('[data-k=cat]').forEach(x=>x.classList.toggle('on',x===b));}
  else{st.diff=st.diff===+b.dataset.v?0:+b.dataset.v;$$('[data-k=diff]').forEach(x=>x.classList.toggle('on',x===b&&st.diff));}
  apply();
});
$('#fctf').onchange=e=>{st.ctf=e.target.checked;apply();};
$('#fsearch').oninput=e=>{st.q=e.target.value.toLowerCase();apply();};
$$('.cp').forEach(b=>b.onclick=()=>{navigator.clipboard?.writeText(b.dataset.cp);b.textContent='✓';setTimeout(()=>b.textContent='⧉',800);});
const KEY='seclab-lab-done';
const done=new Set(JSON.parse(localStorage.getItem(KEY)||'[]'));
function paint(){
  $$('[data-done]').forEach(cb=>{
    cb.checked=done.has(cb.dataset.done);
    cb.closest('.card').classList.toggle('is-done',cb.checked);
  });
  $('#prog').style.width=(done.size/20*100)+'%';
  $('#progtxt').textContent=done.size+'/20 mục tiêu';
}
$$('[data-done]').forEach(cb=>cb.onchange=()=>{
  cb.checked?done.add(cb.dataset.done):done.delete(cb.dataset.done);
  localStorage.setItem(KEY,JSON.stringify([...done]));paint();
});
paint();
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

const BLUE_JS = `
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
let paused=false;
const SUS=[
  /('|%27)\\s*(or|and)\\s|\\bunion\\b|\\-\\-(\\s|$)/i,'SQLi',
  /<script|<svg|onerror\\s*=|onload\\s*=|javascript:/i,'XSS',
  /\\.\\.|etc\\/passwd|boot\\.ini/i,'TRAV',
  /\\/admin/i,'ADMIN',
  /\\/redirect.*to=(https?%3a|https?:|\\/\\/)/i,'REDIR',
  /\\/track.*('|%27)/i,'BLIND',
  /\\/api\\/reset\\//i,'RESET',
];
function flagsOf(e){
  const f=[];
  if(/('|%27)\\s*(or|and)\\s|\\bunion\\b/i.test(e.path))f.push('SQLi');
  if(/<script|<svg|onerror|onload|javascript:/i.test(e.path))f.push('XSS');
  if(/\\.\\.|etc\\/passwd|boot\\.ini/i.test(e.path))f.push('TRAV');
  if(/\\/admin/i.test(e.path))f.push('ADMIN');
  if(/\\/redirect.*to=(https?%3a|https?:|\\/\\/)/i.test(e.path))f.push('REDIR');
  if(/\\/track.*('|%27)/i.test(e.path))f.push('BLIND');
  if(/\\/api\\/reset\\//i.test(e.path))f.push('RESET');
  if(e.method==='POST'&&/\\/api\\/config/i.test(e.path))f.push('PROTO');
  if(e.method==='POST'&&/\\/api\\/register.*role=/i.test(e.path))f.push('MASS');
  if(e.method==='POST'&&/\\/api\\/import/i.test(e.path))f.push('XXE');
  if(e.method==='POST'&&/\\/upload/i.test(e.path))f.push('UPLOAD');
  if(/\\/tools\\/ping.*(%26|%3[bB]|%7[cC]|whoami|\\benv\\b|\\bset\\b)/i.test(e.path))f.push('CMDI');
  if(/sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wfuzz|curl\\/|wget|hydra/i.test(e.ua||''))f.push('SCANNER');
  return f;
}
const escH=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
async function feed(){
  if(paused)return;
  try{
    const j=await(await fetch('/_lab/log')).json();
    const log=(j.log||[]).slice(-80).reverse();
    $('#reqcount').textContent=j.log?.length??0;
    $('#feed').innerHTML=log.map(e=>{
      const fl=flagsOf(e);
      const t=typeof e.t==='number'?new Date(e.t).toTimeString().slice(0,8):String(e.t||'—').slice(11,19);
      return '<tr class="'+(fl.length?'sus':'')+'"><td>'+escH(t)+'</td><td>'+escH(e.method||'GET')+'</td>'+
        '<td title="'+escH(e.path)+'">'+escH((e.path||'').slice(0,72))+'</td><td>'+escH(e.ip||'—')+'</td>'+
        '<td>'+(e.status?('<span class="'+(e.status<300?'sev-ok':e.status<400?'sev-ok':e.status<500?'sev-med':'sev-high')+'">'+e.status+'</span>'):'—')+'</td><td>'+fl.map(x=>'<span class="pill high">'+x+'</span>').join(' ')+'</td></tr>';
    }).join('')||'<tr><td colspan="6" class="sub">Chưa có traffic — hãy tấn công lab rồi quay lại.</td></tr>';
  }catch(e){/* lab chết thì giữ nguyên khung */}
}
async function alerts(){
  if(paused)return;
  try{
    const j=await(await fetch('/_lab/alerts')).json();
    $('#alertcount').textContent=j.attacksDetected??0;
    $('#alerts').innerHTML=(j.findings||[]).map(f=>
      '<div class="alert"><h4><span class="pill '+f.severity+'">'+f.severity.toUpperCase()+'</span> '+
      escH(f.label)+' <span class="muted">×'+f.count+'</span></h4>'+
      (f.samples||[]).map(s=>'<div class="samp">› '+escH(s)+'</div>').join('')+
      '<p class="def">🛡 '+escH(f.defense)+'</p></div>').join('')
      ||'<p class="sub">Chưa phát hiện tấn công nào — log sạch.</p>';
  }catch(e){}
}
$('#pausebtn').onclick=()=>{paused=!paused;$('#pausebtn').textContent=paused?'▶ Tiếp tục':'⏸ Tạm dừng';$('#livedot').className='live'+(paused?' off':'');};
feed();alerts();setInterval(feed,2500);setInterval(alerts,5000);
`;

/** Trang dashboard tương tác — GET /lab (Red Team view). */
export function renderDashboard(mode) {
  const hardened = mode === 'hardened';
  const catBtns = ['all', ...Object.keys(CATEGORIES)]
    .map((k) => `<button class="fbtn ${k === 'all' ? 'on' : ''}" data-k="cat" data-v="${k}">${k === 'all' ? '🎯 Tất cả' : esc(CATEGORIES[k])}</button>`)
    .join('');
  const diffBtns = [1, 2, 3]
    .map((d) => `<button class="fbtn" data-k="diff" data-v="${d}">${DIFF_STARS[d - 1]} ${DIFFS[d]}</button>`)
    .join('');
  const ctfCount = LABS.filter((l) => l.ctf).length;
  const ctfPts = LABS.reduce((s, l) => s + (l.ctf?.pts || 0), 0);
  const groups = Object.keys(CATEGORIES)
    .map((cat) => {
      const labs = LABS.filter((l) => l.cat === cat);
      const m = CAT_META[cat];
      return `<section class="group">
  <h2><span class="dot" style="background:${m.color}"></span>${esc(CATEGORIES[cat])} <span class="gcount">· ${labs.length} mục tiêu</span></h2>
  <p class="gdesc">${esc(m.desc)}</p>
  <div class="grid">${labs.map((l) => renderCard(l, { interactive: true })).join('')}</div>
</section>`;
    })
    .join('\n');
  return `<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>🔴 Red Team — Chọn mục tiêu | SecLab [${mode.toUpperCase()}]</title>
<style>${DASH_CSS}</style></head><body>
${NAV(mode, 'red')}
<div class="wrap">
<div class="hero">
  <div class="tag">🔴 Red Team Operations</div>
  <h1>Chọn mục tiêu — 20 lỗ hổng đang chờ</h1>
  <p class="sub">Mỗi mục tiêu gồm endpoint thật, payload gợi ý và cách kiểm chứng bản đã vá.
  Đánh dấu "Đã xong" — tiến độ lưu trên trình duyệt của bạn. Xong xuôi, qua
  <a href="/blue">🔵 Blue Team</a> xem phía phòng thủ nhìn thấy gì.</p>
  <div class="stats">
    <span class="stat">🎯 <b>20</b> mục tiêu</span>
    <span class="stat">🏆 <b>${ctfCount}</b> thử thách CTF · <b>${ctfPts}</b>đ</span>
    <span class="stat">🧭 <b>6</b> nhóm kỹ năng</span>
    <span class="stat">🛡 bản đối chứng: <a href="http://127.0.0.1:3001/lab">127.0.0.1:3001</a></span>
    <span class="stat">Điểm CTF: <b id="score">—</b></span>
  </div>
</div>
${hardened ? '<p class="warn">⚠ Bạn đang ở bản <b>HARDENED</b> — các lỗ hổng đã vá. Payload gợi ý phải BỊ CHẶN. Khai thác thật hãy mở <a href="http://127.0.0.1:3000/lab">bản vuln :3000</a>.</p>' : ''}
<div class="progress"><div id="prog"></div></div>
<p class="sub">Tiến độ: <b id="progtxt">0/20 mục tiêu</b> · đang hiển thị <b id="count">20</b></p>
<div class="filters">
  ${catBtns}
  <span style="color:#334155">|</span>
  ${diffBtns}
  <label class="ftoggle"><input type="checkbox" id="fctf"> chỉ CTF</label>
  <input type="search" id="fsearch" placeholder="🔍 tìm theo tên / CWE / endpoint…">
</div>
${groups}
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
<p class="sub">📚 Giáo trình: <a href="https://jasontm17.github.io/Security_Lab_Study/" target="_blank" rel="noopener">SecHub Online</a> ·
lời giải (SPOILER): <code>solutions/</code> trong repo · <a href="/blue">🔵 Blue Team console</a> · <a href="/_lab/metrics">/_lab/metrics</a></p>
</div><script>${RED_JS}</script></body></html>`;
}

/** Blue Team — SOC console: live request feed + alerts + defense rules (GET /blue). */
export function renderBlueDashboard(mode, rules = []) {
  const hardened = mode === 'hardened';
  const ruleRows = rules
    .map(
      (r) => `<tr>
<td><span class="pill ${r.severity}">${esc(r.severity.toUpperCase())}</span></td>
<td><b>${esc(r.label)}</b><br><code>${esc(r.type)}</code></td>
<td>${esc(r.defense)}</td>
</tr>`
    )
    .join('');
  const blueCards = LABS.map((l) => {
    const color = CAT_META[l.cat]?.color || '#38bdf8';
    const watch = (LAB_DETECT[l.id] || []).length
      ? `🔎 rule: ${LAB_DETECT[l.id].map((t) => `<code>${esc(t)}</code>`).join(' ')}`
      : '⚠ <b>telemetry mù</b> — access log không đủ, cần app-level logging';
    return `<div class="bcard" style="--cat:${color}">
  <h4>${l.id} · ${esc(l.title)}</h4>
  <p class="muted">Phòng thủ: ${esc(l.hard)}</p>
  <p class="muted">${watch}</p>
</div>`;
  }).join('');
  return `<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>🔵 Blue Team — SOC Console | SecLab [${mode.toUpperCase()}]</title>
<style>:root{--ac:#22d3ee;--ac2:#0ea5e9}${DASH_CSS}</style></head><body>
${NAV(mode, 'blue')}
<div class="wrap">
<div class="hero">
  <div class="tag">🔵 Blue Team — Security Operations</div>
  <h1>SOC Console — nhìn attacker như defender</h1>
  <p class="sub">Tấn công ở <a href="/lab">🔴 Red Team</a> → quay lại đây xem telemetry nói gì.
  Feed request trực tiếp + alert từ engine <code>detect.js</code> + bộ luật phòng thủ cho từng bài.</p>
  <div class="stats">
    <span class="stat">📥 <b id="reqcount">—</b> request ghi nhận</span>
    <span class="stat">🚨 <b id="alertcount">—</b> loại tấn công phát hiện</span>
    <span class="stat">📜 <b>${rules.length}</b> detection rule</span>
    <span class="stat">CLI: <code>node src/cli.js detect ${esc(`http://127.0.0.1:3000`)}</code></span>
  </div>
</div>
${hardened ? '<p class="warn">ℹ Bản <b>HARDENED</b> — hầu hết tấn công sẽ bị chặn (400/401/403/415) nhưng request vẫn được log. So sánh feed ở hai bản!</p>' : ''}
<div class="panel">
  <h2><span class="live" id="livedot"></span> Live request feed <button class="ftoggle" id="pausebtn" style="float:right">⏸ Tạm dừng</button></h2>
  <p class="sub">80 request gần nhất · làm mới mỗi 2.5s · hàng đỏ = khớp pattern nghi ngờ</p>
  <div class="feedbox"><table class="feedtbl">
    <thead><tr><th>giờ</th><th>method</th><th>path</th><th>ip</th><th>status</th><th>flags</th></tr></thead>
    <tbody id="feed"><tr><td colspan="6" class="sub">Đang tải…</td></tr></tbody>
  </table></div>
</div>
<div class="panel">
  <h2>🚨 Alerts — engine phát hiện của lab</h2>
  <p class="sub">Cùng logic <code>analyzeLog()</code> mà lệnh <code>detect</code> dùng — chạy server-side trên <code>/_lab/log</code>.</p>
  <div id="alerts"><p class="sub">Đang tải…</p></div>
</div>
<div class="panel">
  <h2>📜 Detection rules — bộ luật hiện có (${rules.length})</h2>
  <table class="rules"><thead><tr><th>Mức</th><th>Rule</th><th>Phòng thủ tương ứng trong lab</th></tr></thead>
  <tbody>${ruleRows}</tbody></table>
</div>
<div class="panel">
  <h2>🛡 Defense checklist — 20 bài lab</h2>
  <p class="sub">Mỗi bài: cách vá (hardened) + detection rule nào canh chừng. Bài ghi "telemetry mù" = giới hạn thật của access log.</p>
  <div class="bluegrid">${blueCards}</div>
</div>
<p class="sub">📖 Đọc thêm: <code>docs/10-detection-engineering.md</code> · <code>docs/11-case-study-thuc-chien.md</code> ·
<a href="/lab">🔴 Red Team dashboard</a> · <a href="/_lab/metrics">/_lab/metrics</a></p>
</div><script>${BLUE_JS}</script></body></html>`;
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
