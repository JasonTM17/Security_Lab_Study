// recon.js — Thu thập thông tin mục tiêu (chỉ mục tiêu đã qua guard).
// Recon là bước 1 của mọi pentest hợp lệ: biết đối phương chạy gì rồi mới kiểm thử.
import net from 'node:net';
import { assertAuthorizedTarget } from '../guard.js';
import { fetchPage } from './http.js';

const COMMON_PORTS = [80, 443, 3000, 3001, 4200, 5000, 8000, 8080, 8081, 8888];

function probePort(host, port, timeoutMs = 500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open ? port : null);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

export async function guessTech(headers) {
  const guesses = [];
  const h = (name) => (headers[name] || '').toLowerCase();
  if (h('server')) guesses.push({ from: 'Server', value: headers.server });
  if (h('x-powered-by')) guesses.push({ from: 'X-Powered-By', value: headers['x-powered-by'] });
  const csp = h('content-security-policy');
  if (csp) guesses.push({ from: 'Content-Security-Policy', value: 'có CSP → ứng dụng quan tâm bảo mật' });
  if (h('x-rate-limit-limit')) guesses.push({ from: 'X-RateLimit-*', value: 'server có rate limiting' });
  if (/set-cookie/i.test(Object.keys(headers).join(','))) {
    guesses.push({ from: 'Set-Cookie', value: headers['set-cookie'] });
  }
  return guesses;
}

export async function runRecon(target, opts = {}) {
  const auth = await assertAuthorizedTarget(target, opts);
  const base = auth.url.origin;
  const [home, robots] = await Promise.all([
    fetchPage(base + '/'),
    fetchPage(base + '/robots.txt'),
  ]);

  const ports =
    auth.scope === 'loopback' || opts.consent
      ? (await Promise.all(COMMON_PORTS.map((p) => probePort(auth.host, p)))).filter(Boolean)
      : [];

  return {
    target: auth.url.href,
    host: auth.host,
    scope: auth.scope,
    addresses: auth.addresses,
    ports,
    status: home.status,
    responseMs: home.ms,
    headers: home.headers,
    tech: await guessTech(home.headers),
    robots: robots.ok && robots.status === 200 ? robots.body : null,
    hasLabMetrics: (await fetchPage(base + '/_lab/metrics')).status === 200,
  };
}
