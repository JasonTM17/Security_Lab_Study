// flowload.js — Mô phỏng "luồng người dùng thật": mỗi virtual user chạy một
// CHUỖI BƯỚC (vào trang chủ → tìm kiếm → xem chi tiết…), có think-time giữa
// các bước và ramp-up giữa các user — giống hành vi người dùng thật hơn nhiều
// so với loadtest (bắn 1 endpoint). Đo latency theo TỪNG BƯỚC để thấy bước
// nào đang nghẽn.
//
// Đây vẫn là công cụ TẢI — chỉ dùng được với mục tiêu đã qua assertAuthorizedTarget
// (lab cục bộ / server bạn sở hữu). Nhắm tải vào web công khai không thuộc
// sở hữu là bất hợp pháp (Điều 287 BLHS 2015) và bị guard chặn cứng.
import { assertAuthorizedTarget } from '../guard.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Luồng mặc định đi theo các route có thật của lab SecLab. */
export const DEFAULT_FLOW = [
  { name: 'trang chủ', path: '/' },
  { name: 'tìm kiếm', path: '/search?q=iphone' },
  { name: 'xem chi tiết user', path: '/api/users/1' },
];

/** Tính phân vị từ mảng đã sort (p: 0-100). */
function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(msList) {
  const sorted = [...msList].sort((a, b) => a - b);
  const avg = sorted.length ? Math.round(sorted.reduce((s, v) => s + v, 0) / sorted.length) : 0;
  return { count: sorted.length, avg, p50: percentile(sorted, 50), p95: percentile(sorted, 95), max: sorted.at(-1) ?? 0 };
}

/**
 * Chạy flow test.
 * @param {string} rawUrl gốc lab (vd http://127.0.0.1:3000)
 * @param {object} opts users, iterations, thinkMs, rampUpMs, steps, consent, onProgress
 */
export async function runFlowTest(rawUrl, opts = {}) {
  const {
    users = 5,
    iterations = 10,
    thinkMs = 150,
    rampUpMs = 100,
    steps = DEFAULT_FLOW,
    consent = false,
    onProgress = () => {},
  } = opts;

  // Guard lớp 2 (lớp 1 nằm tại entry của CLI): mục tiêu public bị chặn cứng.
  const target = await assertAuthorizedTarget(rawUrl, { consent });

  const nUsers = Math.max(1, Math.min(Number(users) || 5, 50));
  const nIters = Math.max(1, Math.min(Number(iterations) || 10, 500));
  const think = Math.max(0, Number(thinkMs) || 0);
  const ramp = Math.max(0, Number(rampUpMs) || 0);
  const flow = (Array.isArray(steps) && steps.length ? steps : DEFAULT_FLOW).map((s) => ({
    name: String(s.name || s.path),
    path: String(s.path || '/').startsWith('/') ? String(s.path) : `/${s.path}`,
  }));

  // Bộ đếm theo từng bước
  const perStep = new Map(flow.map((s) => [s.name, { step: s, ms: [], statuses: {}, errors: 0 }]));
  const chainMs = [];
  const startedAt = Date.now();
  let doneIters = 0;

  const userTask = async (userId, startDelay) => {
    await sleep(startDelay); // ramp-up: các user không dâng đồng loạt
    for (let it = 0; it < nIters; it++) {
      const chainStart = Date.now();
      for (const step of flow) {
        const bucket = perStep.get(step.name);
        const t0 = Date.now();
        try {
          const res = await fetch(target.url.origin + step.path, {
            headers: { 'User-Agent': `SecLab-FlowUser/${userId}` },
            signal: AbortSignal.timeout(10_000),
            redirect: 'follow',
          });
          const ms = Date.now() - t0;
          bucket.ms.push(ms);
          bucket.statuses[res.status] = (bucket.statuses[res.status] || 0) + 1;
          await res.arrayBuffer().catch(() => {}); // giải phóng body
        } catch (e) {
          bucket.ms.push(Date.now() - t0);
          bucket.errors += 1;
          bucket.statuses['ERR'] = (bucket.statuses['ERR'] || 0) + 1;
        }
        if (think) await sleep(think);
      }
      chainMs.push(Date.now() - chainStart);
      doneIters += 1;
      onProgress({ user: userId, iteration: it + 1, doneIters, totalIters: nUsers * nIters });
    }
  };

  await Promise.all(
    Array.from({ length: nUsers }, (_, i) => userTask(i + 1, i * ramp))
  );

  const durationSec = Math.round(((Date.now() - startedAt) / 1000) * 10) / 10;
  const statusCounts = {};
  const stepStats = [];
  let sent = 0;
  let errors = 0;
  for (const { step, ms, statuses, errors: stepErrors } of perStep.values()) {
    for (const [k, v] of Object.entries(statuses)) statusCounts[k] = (statusCounts[k] || 0) + v;
    sent += ms.length;
    errors += stepErrors;
    stepStats.push({ name: step.name, path: step.path, ...summarize(ms), statusCounts: statuses, errors: stepErrors });
  }
  const chain = summarize(chainMs);

  return {
    target: target.url.href,
    host: target.host,
    scope: target.scope,
    users: nUsers,
    iterations: nIters,
    thinkMs: think,
    rampUpMs: ramp,
    flow: flow.map((f) => f.name),
    totals: { sent, errors, durationSec, rps: durationSec > 0 ? Math.round((sent / durationSec) * 10) / 10 : 0 },
    statusCounts,
    chainMs: chain,
    steps: stepStats,
  };
}
