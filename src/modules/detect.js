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
];

function hits(p) {
  const out = [];
  for (const pat of PATTERNS) {
    const byPath = pat.test ? pat.test(p.path) : false;
    const byUA = pat.testUA ? pat.testUA(p.ua) : false;
    if (byPath || byUA) out.push(pat);
  }
  return out;
}

/**
 * Phân tích mảng log (đã fetch từ /_lab/log) → danh sách phát hiện.
 * Hàm thuần — test được trực tiếp.
 */
export function analyzeLog(log) {
  const findings = new Map(); // type -> { type, label, severity, count, samples: [], defense }
  for (const entry of Array.isArray(log) ? log : []) {
    const p = { path: String(entry.path || ''), ua: String(entry.ua || ''), t: entry.t };
    for (const pat of hits(p)) {
      if (!findings.has(pat.type)) {
        findings.set(pat.type, { type: pat.type, label: pat.label, severity: pat.severity, count: 0, samples: [], defense: pat.defense });
      }
      const f = findings.get(pat.type);
      f.count += 1;
      if (f.samples.length < 3) f.samples.push(p.path.slice(0, 160) || `(UA: ${p.ua.slice(0, 60)})`);
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
