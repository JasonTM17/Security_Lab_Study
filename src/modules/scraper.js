// scraper.js — Trình thu thập dữ liệu web "lịch sự" (polite scraper) cho học tập.
//
// Đây là module DUY NHẤT của SecLab được phép nhắm vào web công khai — vì
// fetch trang công khai một cách lịch sự (robots.txt + rate limit) là hành vi
// hợp pháp, giống một trình duyệt. Đổi lại, vì nhắm web thật nên ràng buộc
// phải NGHIÊM ngặt hơn cả các module tấn công:
//   1. Chỉ http/https; xác thực host bằng DNS trước khi request;
//      MẶC ĐỊNH TỪ CHỐI loopback/dải riêng (dùng --i-own-this-target khi
//      muốn thực hành cào chính lab cục bộ của mình).
//   2. robots.txt: đọc và TÔN TRỌNG (Disallow/Allow longest-match, Crawl-delay).
//   3. Rate limit: sàn cứng 300ms giữa 2 request (mặc định 800ms).
//   4. Giới hạn cứng: tối đa 200 trang/lần chạy, độ sâu tối đa 5.
//   5. Chỉ theo link cùng-origin (same-origin), KHÔNG gửi cookie/session,
//      KHÔNG vượt qua đăng nhập, KHÔNG retry dồn dập. Redirect KHÔNG được fetch
//      tự theo (redirect:'follow') — mỗi bước chuyển hướng được kiểm duyệt lại,
//      tránh trang public 302 sang origin nội bộ (SSRF pivot); DNS được phân
//      giải lại trước mỗi fetch để thu hẹp cửa sổ DNS rebinding (TOCTOU).
// Mitigation bổ sung: KHÔNG biên dịch RegExp động từ robots.txt (nội dung do
// máy chủ từ xa kiểm soát — nguy cơ ReDoS); so khớp mẫu bằng thuần chuỗi.
// Báo cáo luôn ghi vào <project>/reports/ (hằng số — không nhận đường dẫn CLI).
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { parseTarget, classifyIp, SecurityError } from '../guard.js';
import { c } from '../utils/color.js';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPORTS_DIR = path.join(PROJECT_ROOT, 'reports'); // hằng số — mitigation path-traversal

export const USER_AGENT = 'SecLab-EduScraper/1.0 (educational polite scraper)';
const MIN_DELAY_MS = 300;
const MAX_PAGES_CAP = 200;
const MAX_DEPTH_CAP = 5;
const FETCH_TIMEOUT_MS = 10_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Guard riêng của scraper: NGƯỢC chiều với assertAuthorizedTarget của các module
 * tấn công — cho phép web public (fetch lịch sự là hợp pháp), nhưng từ chối
 * loopback/dải riêng nếu không có cờ xác nhận sở hữu (--i-own-this-target).
 * Mitigation SSRF: chỉ http/https + xác thực host bằng DNS + chặn mạng nội bộ.
 */
export async function assertScrapeTarget(raw, { consent = false } = {}) {
  const url = parseTarget(raw); // chỉ nhận http:// hoặc https://, không scheme nào khác
  const host = url.hostname;
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;

  let addresses;
  if (net.isIP(host)) {
    addresses = [host];
  } else {
    try {
      addresses = (await dns.lookup(host, { all: true })).map((a) => a.address);
    } catch {
      throw new SecurityError(`Không phân giải được tên miền "${host}".`);
    }
  }

  const classes = addresses.map(classifyIp);
  if (classes.includes('loopback') || classes.includes('private')) {
    if (!consent) {
      throw new SecurityError(
        [
          '',
          c.yellow(`  ⚠ Mục tiêu "${host}" phân giải về địa chỉ nội bộ (${addresses.join(', ')}).`),
          '  Scraper mặc định chỉ chạy trên WEB CÔNG KHAI.',
          '  Nếu bạn muốn thực hành cào chính lab cục bộ (bạn sở hữu), chạy lại với:  --i-own-this-target',
          '',
        ].join('\n')
      );
    }
  }

  const scope = classes.includes('public') ? 'public' : classes.includes('loopback') ? 'loopback' : 'private';
  return { url, host, port, addresses, scope };
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

/**
 * So khớp mẫu robots.txt (hỗ trợ '*' và '$' cuối) bằng THUẦN CHUỖI.
 * Không tạo RegExp động — robots.txt là nội dung do máy chủ từ xa kiểm soát,
 * RegExp động từ nó mở nguy cơ ReDoS.
 */
export function globMatch(pattern, text) {
  const anchored = pattern.endsWith('$');
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const segs = body.split('*');
  let pos = 0;
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    if (seg === '') continue;
    if (i === 0) {
      if (!text.startsWith(seg)) return false;
      pos = seg.length;
    } else if (anchored && i === segs.length - 1) {
      const idx = text.lastIndexOf(seg);
      if (idx < pos || idx + seg.length !== text.length) return false;
      pos = text.length;
    } else {
      const idx = text.indexOf(seg, pos);
      if (idx === -1) return false;
      pos = idx + seg.length;
    }
  }
  return true;
}

/**
 * Phân tích nội dung robots.txt — trả về nhóm luật áp dụng cho SecLab
 * (User-agent: * hoặc khớp tên UA của chúng ta) dạng
 * { allow: string[], disallow: string[], crawlDelayMs: number|null }.
 */
export function parseRobots(text, userAgentToken = 'seclab-eduscrawler') {
  const groups = new Map(); // agent.toLowerCase() -> { allow: [], disallow: [], crawlDelayMs }
  let current = null;
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === 'user-agent') {
      const agent = value.toLowerCase();
      if (!groups.has(agent)) groups.set(agent, { allow: [], disallow: [], crawlDelayMs: null });
      current = groups.get(agent);
    } else if (!current) {
      continue;
    } else if (key === 'disallow' && value) {
      current.disallow.push(value);
    } else if (key === 'allow' && value) {
      current.allow.push(value);
    } else if (key === 'crawl-delay') {
      const n = Number(value);
      if (Number.isFinite(n) && n >= 0) current.crawlDelayMs = n * 1000;
    }
  }
  const star = groups.get('*');
  const own = groups.get(userAgentToken);
  const merged = { allow: [], disallow: [], crawlDelayMs: null };
  for (const g of [star, own].filter(Boolean)) {
    merged.allow.push(...g.allow);
    merged.disallow.push(...g.disallow);
    if (g.crawlDelayMs !== null) merged.crawlDelayMs = Math.max(merged.crawlDelayMs ?? 0, g.crawlDelayMs);
  }
  return merged;
}

/** Quy tắc longest-match (mẫu cụ thể nhất thắng; hoà thì Allow thắng) — theo chuẩn robots. */
export function robotsAllows(robots, urlPath) {
  if (!robots) return true;
  let best = null; // { allow: boolean, len: number }
  const consider = (patterns, allow) => {
    for (const p of patterns) {
      if (globMatch(p, urlPath)) {
        const len = p.length;
        if (best === null || len > best.len || (len === best.len && allow)) best = { allow, len };
      }
    }
  };
  consider(robots.allow, true);
  consider(robots.disallow, false);
  return best === null ? true : best.allow;
}

// ---------------------------------------------------------------------------
// Trích xuất HTML (regex LITERAL tĩnh + matchAll, không phụ thuộc ngoài)
// ---------------------------------------------------------------------------

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };
const decodeEntities = (s) => String(s).replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (m) => ENTITIES[m] ?? m);
const stripTags = (s) => String(s).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();

/** Trích title/meta/headings/links/độ dài text/số ảnh từ HTML thô. */
export function extractFromHtml(html, baseUrl) {
  const base = new URL(baseUrl);
  const clean = String(html || '').replace(/<!--[\s\S]*?-->/g, '');
  const out = { title: '', metaDescription: '', headings: [], links: [], textLength: 0, imageCount: 0 };

  let m = clean.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (m) out.title = decodeEntities(m[1]).trim().slice(0, 300);

  m = clean.match(/<meta[^>]+name=["']description["'][^>]*>/i);
  if (m) {
    const cm = m[0].match(/content\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    if (cm) out.metaDescription = decodeEntities(cm[1] ?? cm[2]).trim().slice(0, 300);
  }

  const headRe = /<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi;
  for (const hm of clean.matchAll(headRe)) {
    if (out.headings.length >= 50) break;
    const text = decodeEntities(stripTags(hm[2]));
    if (text) out.headings.push({ level: Number(hm[1]), text: text.slice(0, 200) });
  }

  const linkRe = /<a\s[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  for (const lm of clean.matchAll(linkRe)) {
    const href = lm[1] ?? lm[2] ?? lm[3];
    if (!href || /^(mailto:|javascript:|tel:|data:)/i.test(href)) continue;
    let abs;
    try {
      abs = new URL(href, base);
    } catch {
      continue;
    }
    if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
    abs.hash = '';
    out.links.push({ href: abs.href, sameOrigin: abs.origin === base.origin });
    if (out.links.length >= 500) break;
  }

  const textOnly = clean
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ');
  out.textLength = decodeEntities(stripTags(textOnly)).length;
  out.imageCount = (clean.match(/<img\b/gi) || []).length;
  return out;
}

// ---------------------------------------------------------------------------
// Crawl
// ---------------------------------------------------------------------------

function normalizeUrl(href) {
  try {
    const u = new URL(href);
    u.hash = '';
    return u.href;
  } catch {
    return null;
  }
}

const MAX_REDIRECTS = 3;

/**
 * fetch với redirect:'manual' — mỗi bước chuyển hướng được KIỂM DUYỆT trước khi
 * đi tiếp. Mitigation SSRF: redirect:'follow' cho phép một trang public 302 sang
 * origin nội bộ (loopback/RFC1918) và crawler đi theo, vô hiệu hoá guard DNS của
 * runCrawl (guard chỉ chạy 1 lần ở đầu). `allowRedirect(next)` quyết định bước
 * chuyển hướng nào được phép; vượt MAX_REDIRECTS hoặc bị từ chối → ném lỗi
 * (được tính như lỗi mạng của trang đó, crawl tiếp tục với URL khác).
 */
async function fetchGuarded(url, headers, allowRedirect, redirects = 0) {
  const res = await fetch(url, {
    redirect: 'manual', // KHÔNG tự theo redirect — phải qua allowRedirect bên dưới
    headers,
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
  if (!location) return res;
  await res.arrayBuffer().catch(() => {}); // giải phóng socket của response redirect
  if (redirects >= MAX_REDIRECTS) throw new Error('too_many_redirects');
  const next = new URL(location, url); // location lỗi cú pháp → ném, coi như lỗi mạng
  if (next.protocol !== 'http:' && next.protocol !== 'https:') throw new Error('redirect_scheme_blocked_by_guard');
  if (!allowRedirect(next)) throw new Error('redirect_cross_origin_blocked_by_guard');
  return fetchGuarded(next.href, headers, allowRedirect, redirects + 1);
}

async function fetchPage(url, origin) {
  const started = Date.now();
  const res = await fetchGuarded(
    url,
    { 'User-Agent': USER_AGENT, 'Accept': 'text/html,application/xhtml+xml,text/plain' },
    (next) => next.origin === origin // invariant cùng-origin của crawler áp cho cả redirect
  );
  return { res, ms: Date.now() - started };
}

function crawlSlug(host) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return `crawl-${String(host).toLowerCase().replace(/[^a-z0-9.-]/g, '_')}-${stamp}`;
}

/** Ghi báo cáo crawl (.md + .json) vào reports/ — đường dẫn là hằng số nội bộ. */
export function writeCrawlReport(result) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const base = path.join(REPORTS_DIR, crawlSlug(result.host));
  const mdPath = `${base}.md`;
  const jsonPath = `${base}.json`;
  fs.writeFileSync(mdPath, crawlMarkdown(result), 'utf8');
  fs.writeFileSync(jsonPath, JSON.stringify(result, null, 2), 'utf8');
  return { mdPath, jsonPath };
}

function crawlMarkdown(r) {
  const L = [];
  L.push(`# Báo cáo crawl SecLab`);
  L.push('');
  L.push(`- **Mục tiêu:** ${r.target} (phạm vi: ${r.scope})`);
  L.push(`- **robots.txt:** ${r.robotsFound ? 'có — đã tôn trọng' : 'không có (mặc định cho phép)'}` +
    (r.crawlDelayMs ? ` · crawl-delay áp dụng: ${r.crawlDelayMs}ms` : ''));
  L.push(`- **Kết quả:** ${r.stats.fetched} trang lấy được · ${r.stats.robotsSkipped} URL bị robots chặn · ${r.stats.errors} lỗi mạng`);
  L.push(`- **Latency trung bình:** ${r.stats.avgMs}ms`);
  L.push('');
  L.push(`| # | Trang | HTTP | ms | Tiêu đề | Chars |`);
  L.push(`|---|---|---|---|---|---|`);
  r.pages.forEach((p, i) => {
    L.push(`| ${i + 1} | ${p.url} | ${p.status ?? 'ERR'} | ${p.ms ?? '-'} | ${p.title ?? p.error ?? ''} | ${p.textLength ?? '-'} |`);
  });
  if (r.robotsSkipped.length) {
    L.push('');
    L.push(`## URL bị robots.txt chặn (đã bỏ qua đúng luật)`);
    for (const u of r.robotsSkipped) L.push(`- ${u}`);
  }
  return L.join('\n');
}

/**
 * Crawl lịch sự từ một URL gốc. BFS theo độ sâu, chỉ cùng-origin.
 * @returns {Promise<object>} kết quả crawl (cũng được ghi vào reports/)
 */
export async function runCrawl(rawUrl, opts = {}) {
  const {
    maxPages = 30,
    depth = 2,
    delayMs = 800,
    consent = false,
    onProgress = () => {},
  } = opts;

  const pageCap = Math.min(Number(maxPages) || 30, MAX_PAGES_CAP);
  const depthCap = Math.min(Number(depth) || 2, MAX_DEPTH_CAP);
  const delay = Math.max(MIN_DELAY_MS, Number(delayMs) || 800);

  const target = await assertScrapeTarget(rawUrl, { consent });
  const origin = target.url.origin;

  // robots.txt — lỗi mạng khi đọc robots coi như "không có robots" (mặc định cho phép)
  let robots = null;
  let robotsFound = false;
  try {
    const robotsUrl = new URL('/robots.txt', origin).href;
    // robots.txt gắn với HOST — cho phép chuyển hướng http→https cùng host
    // (rất phổ biến) nhưng không bao giờ sang host khác (mitigation như fetchGuarded).
    const res = await fetchGuarded(robotsUrl, { 'User-Agent': USER_AGENT }, (next) => next.host === new URL(robotsUrl).host);
    if (res.ok) {
      robots = parseRobots(await res.text());
      robotsFound = true;
    }
    await res.arrayBuffer().catch(() => {});
  } catch {
    robots = null;
  }
  const crawlDelayMs = Math.max(delay, robots?.crawlDelayMs ?? 0);

  const queue = [{ href: normalizeUrl(target.url.href), depth: 0 }];
  const seen = new Set(queue[0].href ? [queue[0].href] : []);
  const pages = [];
  const robotsSkipped = [];
  let errors = 0;
  let sumMs = 0;

  while (queue.length && pages.length < pageCap) {
    const item = queue.shift();
    if (!item?.href) continue;
    const u = new URL(item.href);
    const urlPath = u.pathname + u.search;

    if (robotsFound && !robotsAllows(robots, urlPath)) {
      robotsSkipped.push(item.href);
      continue;
    }

    const page = { url: item.href, depth: item.depth, status: null, ms: null };
    try {
      // Mitigation DNS-rebinding (TOCTOU): guard chỉ phân giải DNS MỘT lần ở
      // assertScrapeTarget đầu tiên, còn mọi fetch tự phân giải lại theo hostname.
      // DNS do kẻ xấu điều khiển có thể "rebind" tên miền từ IP public sang
      // loopback/RFC1918 giữa hai lần phân giải. Kiểm tra lại classification
      // TRƯỚC MỖI fetch: phát hiện rebind khi không có consent → SecurityError
      // dừng toàn bộ crawl (ghim IP ở tầng connect cần custom dispatcher — ngoài
      // phạm vi sửa tối thiểu, nên còn lại một cửa sổ hẹp sau lần kiểm tra này).
      await assertScrapeTarget(item.href, { consent });
      const { res, ms } = await fetchPage(item.href, origin);
      page.status = res.status;
      page.ms = ms;
      sumMs += ms;
      const ct = res.headers.get('content-type') || '';
      if (res.ok && ct.includes('html')) {
        const html = await res.text();
        const ex = extractFromHtml(html, res.url || item.href);
        page.title = ex.title;
        page.metaDescription = ex.metaDescription;
        page.headings = ex.headings.slice(0, 10);
        page.textLength = ex.textLength;
        page.imageCount = ex.imageCount;
        for (const l of ex.links) {
          if (!l.sameOrigin) continue; // chỉ cùng-origin — không leo sang domain khác
          const norm = normalizeUrl(l.href);
          if (!norm || seen.has(norm)) continue;
          seen.add(norm);
          if (item.depth + 1 <= depthCap) queue.push({ href: norm, depth: item.depth + 1 });
        }
        if (queue.length > pageCap * 10) queue.length = pageCap * 10; // khoá bộ nhớ
      } else {
        await res.arrayBuffer().catch(() => {});
      }
    } catch (e) {
      if (e instanceof SecurityError) throw e; // rebind bị phát hiện → dừng crawl, KHÔNG nuốt lỗi
      page.error = e.name === 'TimeoutError' ? 'timeout' : String(e.message || e).slice(0, 200);
      errors += 1;
    }
    pages.push(page);
    onProgress({ done: pages.length, queued: queue.length, last: page });

    if (queue.length && pages.length < pageCap) await sleep(crawlDelayMs);
  }

  const result = {
    target: target.url.href,
    host: target.host,
    scope: target.scope,
    startedAt: new Date().toISOString(),
    robotsFound,
    crawlDelayMs,
    stats: {
      fetched: pages.length,
      robotsSkipped: robotsSkipped.length,
      errors,
      avgMs: pages.length ? Math.round(sumMs / pages.length) : 0,
    },
    pages,
    robotsSkipped,
  };
  const reportPaths = writeCrawlReport(result);
  return { ...result, reportPaths };
}
