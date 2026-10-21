// loadtest.js — Mô phỏng tải (traffic generator) CHỈ dành cho lab bạn sở hữu.
//
// Đây là "nửa trong suốt" của vấn đề DoS: công cụ tạo tải bình thường giống
// ab / hey / k6, nhưng bị guard.js khóa chặt vào loopback/mạng riêng.
// Dùng nó để:
//   • đo server chịu bao nhiêu request/giây, p95/p99 latency;
//   • chứng minh: endpoint /slow (3 giây) + không rate limit = nghẽn chỉ với ít luồng;
//   • chứng minh: bản hardened trả 429 ngay → dịch vụ vẫn sống.
import { assertAuthorizedTarget } from '../guard.js';
import { fetchPage, sleep, percentile } from './http.js';

export async function runLoadTest(target, { rps = 100, duration = 10, concurrency, path, onProgress, ...authOpts } = {}) {
  const auth = await assertAuthorizedTarget(target, authOpts);
  let p = path ?? auth.url.pathname;
  if (!p.startsWith('/')) p = '/' + p; // người dùng có thể gõ "slow" thay vì "/slow"
  const url = auth.url.origin + p;

  const workers = Math.max(1, Math.min(concurrency ?? Math.min(Math.max(rps, 1), 64), 256));
  const totalMs = duration * 1000;
  const deadline = performance.now() + totalMs;
  const slotInterval = 1000 / Math.max(1, rps);

  // Bắt đầu: đọc metrics của lab để so sánh số request server thực nhận.
  const metricsBefore = await readLabMetrics(auth.url.origin);

  const latencies = [];
  const statusCounts = {};
  let sent = 0;
  let errors = 0;
  let nextSlot = performance.now();

  const worker = async () => {
    while (performance.now() < deadline) {
      const now = performance.now();
      if (now < nextSlot) await sleep(nextSlot - now);
      nextSlot = Math.max(nextSlot + slotInterval, performance.now());

      const t0 = performance.now();
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
        await res.text();
        const ms = performance.now() - t0;
        latencies.push(ms);
        statusCounts[res.status] = (statusCounts[res.status] || 0) + 1;
      } catch {
        errors += 1;
        statusCounts['network_error'] = (statusCounts['network_error'] || 0) + 1;
      }
      sent += 1;
      if (onProgress && sent % 100 === 0) onProgress({ sent, elapsed: Math.round(performance.now() - (deadline - totalMs)) });
    }
  };

  const t0 = performance.now();
  await Promise.all(Array.from({ length: workers }, worker));
  const wallMs = performance.now() - t0;

  const metricsAfter = await readLabMetrics(auth.url.origin);
  latencies.sort((a, b) => a - b);

  return {
    target: url,
    scope: auth.scope,
    requestedRps: rps,
    actualRps: Math.round((sent / wallMs) * 1000),
    concurrency: workers,
    durationSec: Math.round(wallMs / 100) / 10,
    sent,
    errors,
    statusCounts,
    latency: {
      avg: Math.round(latencies.reduce((a, b) => a + b, 0) / Math.max(1, latencies.length)),
      p50: Math.round(percentile(latencies, 50)),
      p90: Math.round(percentile(latencies, 90)),
      p95: Math.round(percentile(latencies, 95)),
      p99: Math.round(percentile(latencies, 99)),
      max: Math.round(latencies.at(-1) || 0),
    },
    serverReceived: metricsAfter ? metricsAfter.total - (metricsBefore?.total || 0) : null,
  };
}

async function readLabMetrics(origin) {
  const res = await fetchPage(origin + '/_lab/metrics', { timeoutMs: 3000 });
  if (res.ok && res.status === 200) {
    try {
      return JSON.parse(res.body);
    } catch {
      return null;
    }
  }
  return null;
}
