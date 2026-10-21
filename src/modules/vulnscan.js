// vulnscan.js — Quét lỗ hổng lớp ứng dụng trên mục tiêu ĐÃ ĐƯỢC ỦY QUYỀN.
// Mỗi check trả về một "finding" có: mức độ, bằng chứng, giải thích khái niệm, cách vá.
// Đây là kiểu scanner tương tự OWASP ZAP/Nikto nhưng viết tối giản để bạn ĐỌC CODE.
import { assertAuthorizedTarget } from '../guard.js';
import { fetchPage, sleep } from './http.js';
import { jwtSign } from '../lab/jwtx.js';
import os from 'node:os';

const ENC = encodeURIComponent;

async function sqliProbe(base) {
  // boolean-based: so sánh số kết quả giữa payload "luôn đúng" và "luôn sai"
  const noMatch = await fetchPage(`${base}/search?q=${ENC('zzz--không-tồn-tại')}`);
  const inject = await fetchPage(`${base}/search?q=${ENC("' OR 1=1 --")}`);
  const rowsIn = (body) => (body.match(/<tr><td>/g) || []).length;
  if (inject.ok && rowsIn(inject.body) > rowsIn(noMatch.body || '') && /@lab\.local/.test(inject.body)) {
    return {
      id: 'SQLI-001',
      title: 'SQL Injection (boolean-based) tại /search?q=',
      severity: 'high',
      vulnerable: true,
      evidence: `Payload "' OR 1=1 --" trả về ${rowsIn(inject.body)} dòng (bình thường: ${rowsIn(noMatch.body || '')}), lộ toàn bộ email.`,
      detail:
        "Ứng dụng nối chuỗi input thẳng vào câu SQL. Payload ' OR 1=1 -- làm mệnh đề WHERE luôn đúng → truy vấn trả về toàn bộ bảng. Đây là lỗ hổng nguy hiểm nhất nhóm web: kẻ tấn công đọc/xoá/sửa toàn bộ CSDL.",
      fix: 'Dùng parameterized query / prepared statement (không bao giờ nối chuỗi input vào SQL). Xem src/db.js searchUsersSafe().',
    };
  }
  // error-based: quote gây lỗi SQL lộ ra response
  const err = await fetchPage(`${base}/search?q=${ENC("'")}`);
  if (err.ok && /syntax error|sqlite|sqlerror|you have an error/i.test(err.body)) {
    return {
      id: 'SQLI-002',
      title: 'SQL Injection (error-based) + lộ thông báo lỗi CSDL tại /search?q=',
      severity: 'high',
      vulnerable: true,
      evidence: `Một dấu nháy đơn "'" khiến response chứa thông báo lỗi CSDL: ${err.body.match(/syntax error[^<]*/i)?.[0] || 'sqlite error'}`,
      detail:
        'Lỗi SQL Injection ở trên kèm hành vi lộ thông báo lỗi gốc của CSDL. Thông báo lỗi giúp kẻ tấn công xác nhận điểm chốt và dò cấu trúc bảng.',
      fix: 'Parameterized query + trả về trang lỗi chung chung, log chi tiết ra server-side.',
    };
  }
  return null;
}

async function xssProbe(base) {
  const marker = '<svg/onload=alert(1)>';
  const search = await fetchPage(`${base}/search?q=${ENC(marker)}`);
  if (search.ok && search.body.includes(marker)) {
    return {
      id: 'XSS-001',
      title: 'Reflected XSS tại /search?q= và trang 404',
      severity: 'high',
      vulnerable: true,
      evidence: `Payload ${marker} được phản chiếu NGUYÊN văn (không encode) trong HTML.`,
      detail:
        'Input người dùng được in ra trang mà không mã hoá HTML → kẻ tấn công có thể chèn JavaScript chạy trong trình duyệt nạn nhân (đánh cắp session, chèn keylogger, phishing nội bộ).',
      fix: 'Encode output theo ngữ cảnh (HTML entity), thêm CSP. Xem esc() trong src/lab/app.js ở bản hardened.',
    };
  }
  const notFound = await fetchPage(`${base}/seclab-probe${ENC(marker)}`);
  if (notFound.ok && notFound.status === 404 && notFound.body.includes(marker)) {
    return {
      id: 'XSS-002',
      title: 'Reflected XSS qua trang 404',
      severity: 'high',
      vulnerable: true,
      evidence: `URL không tồn tại chứa payload được phản chiếu nguyên văn trong trang 404.`,
      detail: 'Trang 404 in lại URL mà không encode — vector XSS kinh điển.',
      fix: 'Không phản chiếu URL thô; encode mọi dữ liệu động.',
    };
  }
  return null;
}

async function headerProbe(base) {
  const res = await fetchPage(base + '/');
  if (!res.ok) {
    return { id: 'NET-000', title: 'Không kết nối được mục tiêu', severity: 'info', vulnerable: null, evidence: res.error || '', detail: 'Kiểm tra server lab đã chạy chưa: npm run serve', fix: '' };
  }
  const missing = [];
  const expect = {
    'content-security-policy': 'chống XSS',
    'x-content-type-options': 'chống MIME sniffing',
    'x-frame-options': 'chống clickjacking',
    'referrer-policy': 'chống rò rỉ URL',
    'permissions-policy': 'giới hạn API trình duyệt',
  };
  for (const [name, why] of Object.entries(expect)) {
    if (!res.headers[name]) missing.push(`${name} (${why})`);
  }
  if (missing.length) {
    return {
      id: 'HDR-001',
      title: `Thiếu ${missing.length} security headers`,
      severity: 'medium',
      vulnerable: true,
      evidence: `Thiếu: ${missing.join(', ')}`,
      detail:
        'Security headers là lớp phòng thủ miễn phí của trình duyệt. Thiếu CSP → XSS dễ bị khai thác; thiếu X-Frame-Options → clickjacking; thiếu nosniff → MIME confusion.',
      fix: 'Gắn bộ headers chuẩn ở proxy/reverse-proxy hoặc middleware. Xem src/defense/headers.js.',
    };
  }
  return { id: 'HDR-001', title: 'Security headers đầy đủ', severity: 'info', vulnerable: false, evidence: 'OK', detail: 'Bản hardened đạt chuẩn.', fix: '' };
}

async function cookieProbe(base) {
  const isHttps = base.startsWith('https:');
  const res = await fetchPage(base + '/login', {
    method: 'POST',
    body: 'username=alice&password=alice123',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  const setCookie = res.headers['set-cookie'] || '';
  const missing = [];
  if (setCookie) {
    if (!/httponly/i.test(setCookie)) missing.push('HttpOnly (JS đọc được cookie → đánh cắp qua XSS)');
    if (!/samesite/i.test(setCookie)) missing.push('SameSite (chống CSRF)');
    if (isHttps && !/secure/i.test(setCookie)) missing.push('Secure (chỉ gửi qua HTTPS)');
  }
  if (setCookie && missing.length) {
    return {
      id: 'CKI-001',
      title: 'Cookie phiên thiếu cờ bảo mật',
      severity: 'medium',
      vulnerable: true,
      evidence: `Set-Cookie: ${setCookie.replace(/\s*Path=[^;]*;?/, '')} — thiếu: ${missing.join(', ')}`,
      detail: 'Cookie session không có HttpOnly thì một dòng JavaScript qua XSS là đủ để đánh cắp phiên đăng nhập.',
      fix: 'Set-Cookie: session=...; HttpOnly; SameSite=Strict; Secure (khi chạy HTTPS).',
    };
  }
  if (setCookie) {
    return {
      id: 'CKI-001',
      title: 'Cookie phiên có cờ bảo mật',
      severity: 'info',
      vulnerable: false,
      evidence: `Set-Cookie: ${setCookie}`,
      detail: 'HttpOnly + SameSite đang bật (Secure chỉ đòi hỏi khi chạy HTTPS thật).',
      fix: '',
    };
  }
  return null;
}

async function sensitivePathsProbe(base) {
  const paths = ['/.env', '/.git/config', '/admin', '/backup.sql', '/server-status', '/phpinfo.php', '/files/'];
  const hits = [];
  for (const p of paths) {
    const res = await fetchPage(base + p);
    if (res.ok && res.status === 200 && !(res.headers['content-type'] || '').includes('text/html') === false) {
      // coi 200 kèm nội dung không phải trang lỗi chung chung là "hit"
      if (!/not\s*found|404/i.test(res.body.slice(0, 200))) hits.push({ path: p, status: res.status });
    }
  }
  if (hits.length) {
    return {
      id: 'PATH-001',
      title: `Phát hiện ${hits.length} đường dẫn nhạy cảm truy cập được khi chưa đăng nhập`,
      severity: 'high',
      vulnerable: true,
      evidence: hits.map((h) => `GET ${h.path} → ${h.status}`).join('; '),
      detail:
        '/admin mở tự do = missing authorization. /.env hay /.git/config lộ cấu hình, khoá bí mật, lịch sử mã nguồn. Directory listing (/files/) tiết lộ cấu trúc file.',
      fix: 'Kiểm tra quyền ở mọi route nhạy cảm, chặn truy cập dot-files ở web server, tắt directory listing.',
    };
  }
  return null;
}

async function idorProbe(base) {
  const res = await fetchPage(base + '/api/users/2');
  if (res.ok && res.status === 200 && /apikey|email/i.test(res.body)) {
    return {
      id: 'IDOR-001',
      title: 'IDOR — truy cập dữ liệu người dùng khác khi chưa đăng nhập (/api/users/:id)',
      severity: 'high',
      vulnerable: true,
      evidence: `GET /api/users/2 (không có session) → 200 kèm email + apiKey.`,
      detail:
        'IDOR (Insecure Direct Object Reference): API chỉ nhận tham số id mà không kiểm tra "người này có được xem người kia không". Kẻ tấn công duyệt id=1..n để trích xuất toàn bộ dữ liệu (API scraping).',
      fix: 'Mọi truy cập object phải kiểm tra ownership/role theo session, không tin tham số từ client.',
    };
  }
  return null;
}

async function rateLimitProbe(base) {
  const TOTAL = 60;
  const CONC = 8;
  let limited = 0;
  let done = 0;
  const workers = Array.from({ length: CONC }, async () => {
    while (done < TOTAL) {
      done += 1;
      const res = await fetchPage(base + '/', { timeoutMs: 4000 });
      if (res.status === 429) limited += 1;
    }
  });
  await Promise.all(workers);
  if (limited === 0) {
    return {
      id: 'RPS-001',
      title: `Không có rate limiting (${TOTAL} request dồn dập, 0 lần bị chặn)`,
      severity: 'medium',
      vulnerable: true,
      evidence: `Gửi ${TOTAL} request với ${CONC} luồng song song — tất cả đều 200, không có 429.`,
      detail:
        'Thiếu rate limit là điều kiện cần để DoS lớp ứng dụng thành công: một client duy nhất cũng đủ làm nghẽn endpoint chậm. Đây chính là "bàn đạp ga" mà bản hardened đã rút ra.',
      fix: 'Token bucket / sliding window theo IP + theo tài khoản; giới hạn đồng thời và body size. Xem src/defense/ratelimiter.js.',
    };
  }
  return {
    id: 'RPS-001',
    title: 'Có rate limiting',
    severity: 'info',
    vulnerable: false,
    evidence: `${limited}/${TOTAL} request bị chặn bằng 429.`,
    detail: 'Server chủ động từ chối khi quá tải — chống DoS lớp ứng dụng hiệu quả.',
    fix: '',
  };
}

async function storedXssProbe(base) {
  const marker = `<svg/onload=alert(7)>`;
  await fetchPage(base + '/guestbook', {
    method: 'POST',
    body: `msg=${ENC(marker)}`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  const page = await fetchPage(base + '/guestbook');
  if (page.ok && page.body.includes(marker)) {
    return {
      id: 'SXSS-001',
      title: 'Stored XSS tại /guestbook (lời nhắn lưu lại và render không escape)',
      severity: 'high',
      vulnerable: true,
      evidence: `Payload ${marker} tồn tại NGUYÊN VĂN trong GET /guestbook sau khi POST.`,
      detail:
        'Stored XSS nguy hiểm hơn reflected: payload NẰM SẴN trên server, tự chạy trong trình duyệt MỌI người xem trang — không cần lừa click link.',
      fix: 'Encode output khi render (esc() ở bản hardened) + CSP. Không bao giờ in dữ liệu user lưu trong DB ra HTML thô.',
    };
  }
  return null;
}

async function cmdiProbe(base) {
  // Marker = username thật của máy — chỉ xuất hiện trong output nếu whoami CHẠY THẬT
  // (lab chỉ chạy trên loopback nên scanner và server cùng một máy).
  const whoami = os.userInfo().username;
  const sep = process.platform === 'win32' ? '&' : ';';
  const res = await fetchPage(`${base}/tools/ping?host=${ENC(`127.0.0.1 ${sep} whoami`)}`);
  if (res.ok && whoami && res.body.toLowerCase().includes(whoami.toLowerCase())) {
    return {
      id: 'CMDI-001',
      title: 'OS Command Injection tại /tools/ping?host=',
      severity: 'high',
      vulnerable: true,
      evidence: `host="127.0.0.1 ${sep} whoami" khiến server chạy whoami — output chứa "${whoami}".`,
      detail:
        'Input được nối chuỗi vào lệnh shell → kẻ tấn công chạy LỆNH TÙY Ý với quyền của tiến trình server: đọc file, lộ biến môi trường, mở reverse shell. Một trong những lỗ hổng nặng nhất.',
      fix: 'Không bao giờ nối input vào shell. Dùng execFile với mảng tham số + whitelist ký tự (bản hardened).',
    };
  }
  return null;
}

async function csrfProbe(base) {
  const login = await fetchPage(base + '/login', {
    method: 'POST',
    body: 'username=alice&password=alice123',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  const sid = (login.headers['set-cookie'] || '').match(/session=([a-f0-9]+)/)?.[1];
  if (!sid) return null;
  const settings = await fetchPage(base + '/settings', { headers: { Cookie: `session=${sid}` } });
  const hasCsrfField = /name="csrf"/.test(settings.body || '');
  const attempt = await fetchPage(base + '/settings/email', {
    method: 'POST',
    body: 'email=csrf-probe@lab.local',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      Cookie: `session=${sid}`,
      Origin: 'https://evil.example',
    },
  });
  if (!hasCsrfField && attempt.ok && attempt.status === 200) {
    return {
      id: 'CSRF-001',
      title: 'CSRF — POST /settings/email chấp nhận request không token, Origin lạ',
      severity: 'high',
      vulnerable: true,
      evidence: 'Đổi email thành công khi gửi Origin: https://evil.example và không có csrf token.',
      detail:
        'Trình duyệt tự đính cookie phiên khi trang khác submit form tới site của bạn. Không có CSRF token → bất kỳ trang nào nạn nhân mở cũng đổi được email/mật khẩu của họ.',
      fix: 'Synchronizer token gắn session (src/defense/csrf.js) + kiểm Origin/Referer + SameSite cookie.',
    };
  }
  return null;
}

async function jwtProbe(base) {
  const tok = await fetchPage(base + '/api/token', {
    method: 'POST',
    body: 'username=alice&password=alice123',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  let token;
  try {
    token = JSON.parse(tok.body || '{}').token;
  } catch {
    /* không phải JSON */
  }
  if (!token) return null;
  // Thử 2 kiểu tấn công kinh điển: alg=none và secret yếu 'secret123'.
  const attacks = [
    { name: 'alg=none (token không chữ ký)', forged: jwtSign({ sub: 'ctfsvc', role: 'svc' }, '', { alg: 'none' }) },
    { name: "secret yếu 'secret123' (crack bằng từ điển)", forged: jwtSign({ sub: 'ctfsvc', role: 'svc' }, 'secret123') },
  ];
  const accepted = [];
  for (const a of attacks) {
    const r = await fetchPage(`${base}/api/profile?token=${ENC(a.forged)}`);
    if (r.ok && r.status === 200 && r.body.includes('"ctfsvc"')) accepted.push(a.name);
  }
  if (accepted.length) {
    return {
      id: 'JWT-001',
      title: `JWT dễ tổn thương — server chấp nhận ${accepted.join(' + ')}`,
      severity: 'high',
      vulnerable: true,
      evidence: `Forge token {"sub":"ctfsvc"} → GET /api/profile trả 200 cho service account không tồn tại.`,
      detail:
        'JWT ký bằng secret yếu → crack offline bằng từ điển. Chấp nhận alg=none → forge không cần khoá. Kết quả: giả mạo danh tính bất kỳ ai.',
      fix: 'Khoá HMAC dài ngẫu nhiên ≥256-bit (hoặc RS256/EdDSA), reject alg=none, kiểm exp/aud/iss. Xem jwtVerify() bản hardened.',
    };
  }
  return null;
}

async function openRedirectProbe(base) {
  const r = await fetchPage(`${base}/redirect?to=${ENC('https://example.com/phish')}`);
  const loc = r.headers?.location || '';
  if (r.ok && (r.status === 301 || r.status === 302) && /example\.com/.test(loc)) {
    return {
      id: 'OREDIR-001',
      title: 'Open Redirect tại /redirect?to=',
      severity: 'medium',
      vulnerable: true,
      evidence: `GET /redirect?to=https://example.com/phish → ${r.status} Location: ${loc}`,
      detail:
        'Redirect không kiểm soát đích → kẻ tấn công dùng domain hợp pháp của bạn làm "cầu" đưa nạn nhân tới trang phishing; bypass cả bộ lọc URL đơn giản.',
      fix: 'Chỉ cho phép path nội bộ (/...) hoặc whitelist domain. Bản hardened trả 400 với URL ngoài.',
    };
  }
  return null;
}

async function uploadProbe(base) {
  const fname = `seclab-poc-${Date.now()}.html`;
  const up = await fetchPage(base + '/upload', {
    method: 'POST',
    body: `name=${ENC(fname)}&content=${ENC('<html><script>alert(1)</script></html>')}`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  if (!up.ok || up.status !== 200) return null;
  const serve = await fetchPage(`${base}/uploads/${fname}`);
  if (serve.ok && serve.status === 200 && (serve.headers['content-type'] || '').includes('text/html')) {
    return {
      id: 'UPLOAD-001',
      title: 'Unrestricted Upload — file .html được phục vụ như trang web (stored XSS)',
      severity: 'high',
      vulnerable: true,
      evidence: `Upload ${fname} chứa <script> → GET /uploads/${fname} trả Content-Type: text/html.`,
      detail:
        'Upload không whitelist đuôi file + phục vụ đúng MIME → attacker đăng "webshell" HTML/SVG chạy script trong origin của bạn; nặng hơn là file thực thi phía server (trên app thật).',
      fix: 'Whitelist extension + kiểm nội dung, đổi tên file, phục vụ qua domain/CDN riêng hoặc ép Content-Type: text/plain (bản hardened).',
    };
  }
  return null;
}

async function xxeProbe(base) {
  const xml =
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///secrets.txt">]><import><item>&xxe;</item></import>';
  const r = await fetchPage(base + '/api/import', {
    method: 'POST',
    body: xml,
    headers: { 'content-type': 'application/xml' },
  });
  if (r.ok && r.status === 200 && /LAB_SECRET|FLAG\{/.test(r.body)) {
    return {
      id: 'XXE-001',
      title: 'XXE — XML external entity đọc file nội bộ tại POST /api/import',
      severity: 'high',
      vulnerable: true,
      evidence: 'Entity file:///secrets.txt được resolve → nội dung file lộ trong response (LAB_SECRET).',
      detail:
        'Parser XML cho phép external entity → kẻ tấn công đọc file hệ thống, quét mạng nội bộ (SSRF qua XML), hoặc DoS bằng billion laughs. Lab mô phỏng trên filesystem ảo.',
      fix: 'Tắt DTD/external entity trong parser (bản hardened trả 400 dtd_prohibited); dùng JSON khi có thể.',
    };
  }
  return null;
}

export const CHECKS = [
  { id: 'HDR', fn: headerProbe },
  { id: 'CKI', fn: cookieProbe },
  { id: 'SQLI', fn: sqliProbe },
  { id: 'XSS', fn: xssProbe },
  { id: 'SXSS', fn: storedXssProbe },
  { id: 'IDOR', fn: idorProbe },
  { id: 'PATH', fn: sensitivePathsProbe },
  { id: 'CMDI', fn: cmdiProbe },
  { id: 'CSRF', fn: csrfProbe },
  { id: 'JWT', fn: jwtProbe },
  { id: 'OREDIR', fn: openRedirectProbe },
  { id: 'UPLOAD', fn: uploadProbe },
  { id: 'XXE', fn: xxeProbe },
  { id: 'RPS', fn: rateLimitProbe },
];

export async function runScan(target, opts = {}) {
  const auth = await assertAuthorizedTarget(target, opts);
  const base = auth.url.origin;
  const findings = [];
  const startedAt = new Date().toISOString();

  for (const check of CHECKS) {
    try {
      const f = await check.fn(base);
      if (f) findings.push(f);
    } catch (e) {
      findings.push({
        id: `ERR-${check.id}`,
        title: `Check ${check.id} gặp lỗi`,
        severity: 'info',
        vulnerable: null,
        evidence: String(e?.message || e),
        detail: '',
        fix: '',
      });
    }
    await sleep(120); // nhẹ nhàng với mục tiêu
  }

  const summary = {
    high: findings.filter((f) => f.vulnerable && f.severity === 'high').length,
    medium: findings.filter((f) => f.vulnerable && f.severity === 'medium').length,
    passed: findings.filter((f) => f.vulnerable === false).length,
  };

  return {
    tool: 'SecLab vulnscan',
    target: auth.url.href,
    scope: auth.scope,
    addresses: auth.addresses,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings,
    summary,
  };
}
