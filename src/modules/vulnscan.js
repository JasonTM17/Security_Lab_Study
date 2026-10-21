// vulnscan.js — Quét lỗ hổng lớp ứng dụng trên mục tiêu ĐÃ ĐƯỢC ỦY QUYỀN.
// Mỗi check trả về một "finding" có: mức độ, bằng chứng, giải thích khái niệm, cách vá.
// Đây là kiểu scanner tương tự OWASP ZAP/Nikto nhưng viết tối giản để bạn ĐỌC CODE.
import { assertAuthorizedTarget } from '../guard.js';
import { fetchPage, sleep } from './http.js';

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

export const CHECKS = [
  { id: 'HDR', fn: headerProbe },
  { id: 'CKI', fn: cookieProbe },
  { id: 'SQLI', fn: sqliProbe },
  { id: 'XSS', fn: xssProbe },
  { id: 'IDOR', fn: idorProbe },
  { id: 'PATH', fn: sensitivePathsProbe },
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
