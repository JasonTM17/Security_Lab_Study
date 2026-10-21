// HTTP helper dùng chung cho các module chủ động.
export async function fetchPage(url, { timeoutMs = 6000, method = 'GET', body, headers } = {}) {
  const t0 = performance.now();
  try {
    const res = await fetch(url, {
      method,
      body,
      headers,
      redirect: 'manual', // tự quan sát redirect thay vì tự đi theo
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    return {
      ok: true,
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: text,
      ms: Math.round(performance.now() - t0),
    };
  } catch (e) {
    return { ok: false, error: String(e?.cause?.code || e?.message || e), ms: Math.round(performance.now() - t0) };
  }
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}
