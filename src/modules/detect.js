// detect.js — Module BLUE-TEAM: phân tích log request của lab để NHẬN DIỆN
// tấn công — mặt "thám sát" mà hầu hết công cụ học bỏ qua.
//
// Dữ liệu vào: mảng log từ GET /_lab/log của lab (mỗi entry {t, method, path, ua}).
// Điều kiện: mục tiêu phải qua assertAuthorizedTarget (lab của bạn) — module
// fetch log qua HTTP nên cũng phải ở cùng phạm vi ủy quyền.
//
// Đầu ra: danh sách phát hiện { type, count, severity, samples, defense } —
// mỗi loại kèm BIỆN PHÁP PHÒNG THỦ tương ứng đã có trong lab (ratelimiter,
// security headers, parameterized query…). Học đúng vòng: tấn công → phát hiện → phòng thủ.
import { assertAuthorizedTarget } from '../guard.js';

const PATTERNS = [
  {
    type: 'sqli',
    label: 'SQL Injection probe',
    severity: 'high',
    test: (p) => /('|%27)\s*(or|and)\s|\bunion\b.*\bselect\b|--(\s|$)|\/\*|sleep\s*\(|benchmark\s*\(/i.test(p),
    defense: 'Parameterized query (đã có ở bản hardened — src/db.js loginSafe/searchUsersSafe); log & alert bất thường; WAF rule chặn mẫu phổ biến.',
  },
  {
    type: 'xss',
    label: 'XSS payload',
    severity: 'high',
    test: (p) => /<script|<svg|onerror\s*=|onload\s*=|javascript:|<img\b[^>]*\bsrc\s*=/i.test(p),
    defense: 'Output encoding (esc() ở bản hardened) + Content-Security-Policy chặn inline script; HttpOnly cookie khiến đánh cắp phiên khó hơn.',
  },
  {
    type: 'traversal',
    label: 'Path traversal',
    severity: 'high',
    test: (p) => /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\//i.test(p) || /etc\/passwd|boot\.ini|win\.ini/i.test(p),
    defense: 'Chuẩn hoá đường dẫn + allowlist prefix (bản hardened từ chối 400); chặn serving file ngoài thư mục gốc.',
  },
  {
    type: 'admin-probe',
    label: 'Dò khu vực quản trị',
    severity: 'medium',
    test: (p) => /\/admin|\/administrator|\/manager|\/wp-admin|\/\.env|\/config\b/i.test(p),
    defense: 'Kiểm tra quyền trên SERVER cho mọi route nhạy cảm (hardened: 403); không lộ existence qua 404 khác biệt.',
  },
  {
    type: 'scanner',
    label: 'Công cụ quét tự động (User-Agent đáng ngờ)',
    severity: 'medium',
    testUA: (ua) => /sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wfuzz|python-requests|curl\/|wget|hydra/i.test(ua),
    defense: 'Rate limiting (token bucket LAB-06) + block UA dựa dấu hiệu; honeypot path. Lưu ý: UA dễ giả mạo — chỉ là tín hiệu, không phải chứng cứ kết luận.',
  },
  {
    type: 'secret-probe',
    label: 'Dò file nhạy cảm',
    severity: 'medium',
    test: (p) => /secrets?\.|\.bak|\.sql|\.git\/|backup|dump|id_rsa/i.test(p),
    defense: 'Không để file nhạy cảm trong webroot; VFS lab đặt cờ ngoài vùng liệt kê — bản hardened chặn traversal nên không đọc được.',
  },
  {
    type: 'cmdinj',
    label: 'Command injection probe',
    severity: 'high',
    test: (p) =>
      /\/tools\/ping/i.test(p) &&
      /(%26|%7[cC]|%3[bB]|%60|%24%28|%24|&amp|; *%20)|whoami|ipconfig|ifconfig|\bset\b|\benv\b|\bcat\b|\bdir\b|\btype\b|\bls\b|\bcurl\b|\bwget\b|\bnc\b/i.test(
        p
      ),
    defense: 'execFile + whitelist input (bản hardened 400); alert khi thấy shell metachar trong query của endpoint chẩn đoán.',
  },
  {
    type: 'open-redir',
    label: 'Open redirect abuse',
    severity: 'medium',
    test: (p) => /\/redirect/i.test(p) && /to=(https?%3a|https?:\/\/|\/\/)/i.test(p),
    defense: 'Whitelist đích chuyển hướng / chỉ cho phép path nội bộ (bản hardened 400); log & cảnh báo domain ngoài.',
  },
  {
    type: 'xxe',
    label: 'XXE probe / entity injection',
    severity: 'high',
    testEntry: (e) => e.method === 'POST' && /\/api\/import/i.test(e.path),
    defense: 'Tắt DTD/external entity ở parser (bản hardened: dtd_prohibited); giám sát endpoint nhận XML.',
  },
  {
    type: 'upload-abuse',
    label: 'Upload đáng ngờ',
    severity: 'medium',
    testEntry: (e) => e.method === 'POST' && /\/upload/i.test(e.path),
    defense: 'Whitelist extension + quét nội dung + phục vụ file qua domain riêng/text-plain (bản hardened 415).',
  },
  {
    type: 'jwt-probe',
    label: 'Thao túng token / dò JWT endpoint',
    severity: 'medium',
    test: (p) => /\/api\/(token|profile)/i.test(p),
    defense: 'Log lượt phát hành/xác minh token; reject alg=none; khoá HMAC mạnh; alert khi một IP thử nhiều token khác nhau.',
  },
  {
    type: 'proto-pollution',
    label: 'Prototype pollution (dấu hiệu gián tiếp)',
    severity: 'medium',
    testEntry: (e) => e.method === 'POST' && /\/api\/config/i.test(e.path),
    // Access log KHÔNG thấy body — __proto__ nằm trong JSON body nên detect chỉ
    // biết "có request POST config", không biết payload. Giới hạn thực của log.
    defense:
      'Access log không thấy body → cần app-level logging hoặc WAF đọc body để nhận __proto__; phòng thủ gốc: lọc key nguy hiểm khi merge (hardened).',
  },
  {
    type: 'mass-assign',
    label: 'Mass assignment — field trái phép trong request',
    severity: 'high',
    testEntry: (e) => e.method === 'POST' && /\/api\/register/i.test(e.path) && /[?&]role=/i.test(e.path),
    defense: 'Whitelist field khi tạo entity; alert khi thấy field quyền (role/admin/is_staff) trong request đăng ký.',
  },
  {
    type: 'blind-sqli',
    label: 'Blind SQLi — thăm dò oracle boolean',
    severity: 'high',
    test: (p) => /\/track/i.test(p) && /('|%27)[^&]*(and|or|select|substr|glob|union)(\s|%20|%2f|$)/i.test(p),
    defense: 'Parameterized query diệt oracle; alert khi endpoint "tra cứu" nhận input chứa cú pháp SQL/substr — đặc trưng rút dữ liệu từng ký tự.',
  },
  {
    type: 'reset-probe',
    label: 'Dò luồng reset mật khẩu',
    severity: 'medium',
    test: (p) => /\/api\/reset\//i.test(p),
    defense: 'Token random ≥128-bit + one-time + expiry; alert khi nhiều reset-request cho nhiều user từ cùng IP (dò account takeover).',
  },
];

// Metadata tĩnh của các rule (không kèm hàm test) — cho dashboard blue-team
// hiển thị "bộ luật hiện có". Cập nhật thủ công khi thêm rule mới vào PATTERNS.
export const RULES_INFO = [
  ...PATTERNS.map((p) => ({ type: p.type, label: p.label, severity: p.severity, defense: p.defense })),
  {
    type: 'brute-force',
    label: 'Brute-force đăng nhập (behavioral — đếm theo IP)',
    severity: 'high',
    defense: 'Rate limit per-IP + khoá tài khoản tạm thời + MFA; alert khi ≥5 lần login thất bại từ cùng IP.',
  },
];

function hits(p) {
  const out = [];
  for (const pat of PATTERNS) {
    const byPath = pat.test ? pat.test(p.path) : false;
    const byUA = pat.testUA ? pat.testUA(p.ua) : false;
    const byEntry = pat.testEntry ? pat.testEntry(p) : false;
    if (byPath || byUA || byEntry) out.push(pat);
  }
  return out;
}

/**
 * Phân tích mảng log (đã fetch từ /_lab/log) → danh sách phát hiện.
 * Hàm thuần — test được trực tiếp.
 */
export function analyzeLog(log) {
  const findings = new Map(); // type -> { type, label, severity, count, samples: [], defense }
  const entries = Array.isArray(log) ? log : [];
  for (const entry of entries) {
    const p = {
      path: String(entry.path || ''),
      ua: String(entry.ua || ''),
      t: entry.t,
      method: String(entry.method || 'GET'),
      ip: String(entry.ip || ''),
    };
    for (const pat of hits(p)) {
      if (!findings.has(pat.type)) {
        findings.set(pat.type, { type: pat.type, label: pat.label, severity: pat.severity, count: 0, samples: [], defense: pat.defense });
      }
      const f = findings.get(pat.type);
      f.count += 1;
      if (f.samples.length < 3) f.samples.push(p.path.slice(0, 160) || `(UA: ${p.ua.slice(0, 60)})`);
    }
  }

  // Brute-force: một IP POST /login ≥5 lần → dò mật khẩu.
  const triesByIp = new Map();
  for (const e of entries) {
    if (String(e.method) === 'POST' && String(e.path || '').startsWith('/login')) {
      const ip = String(e.ip || '?');
      triesByIp.set(ip, (triesByIp.get(ip) || 0) + 1);
    }
  }
  for (const [ip, n] of triesByIp) {
    if (n >= 5) {
      findings.set('brute-force', {
        type: 'brute-force',
        label: 'Brute-force đăng nhập',
        severity: 'high',
        count: n,
        samples: [`POST /login ×${n} từ ${ip}`],
        defense: 'Rate limit per-IP + khoá tài khoản tạm thời + MFA; alert khi ≥5 lần login thất bại từ cùng IP.',
      });
    }
  }

  const list = [...findings.values()].sort((a, b) => {
    const sev = { high: 0, medium: 1, low: 2 };
    return sev[a.severity] - sev[b.severity] || b.count - a.count;
  });
  return {
    totalRequests: Array.isArray(log) ? log.length : 0,
    attacksDetected: list.length,
    findings: list,
  };
}

/**
 * Fetch log từ lab rồi phân tích. Guard 2 lớp như mọi module chủ động.
 */
export async function runDetect(rawUrl, { consent = false, limit = 500 } = {}) {
  const target = await assertAuthorizedTarget(rawUrl, { consent });
  const res = await fetch(target.url.origin + '/_lab/log', {
    headers: { 'User-Agent': 'SecLab-Detect/1.0' },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    throw new Error(`Không đọc được /_lab/log (HTTP ${res.status}) — endpoint có từ lab v1.3 trở lên.`);
  }
  const body = await res.json();
  return { target: target.url.href, scope: target.scope, ...analyzeLog((body.log || []).slice(-limit)) };
}
