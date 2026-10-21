// challenge.js — Client cho CHẾ ĐỘ CTF của lab: xem thử thách, nộp cờ, xem điểm.
//
// Cờ KHÔNG nằm ở đây — phải tự khai thác lỗ hổng của lab vuln bằng tay (browser,
// curl…) mới có cờ; module này chỉ liệt kê gợi ý và NỘP cờ để server xác minh
// (so sánh thời gian hằng, chống timing attack). Bản hardened từ chối nộp cờ —
// vì lỗ hổng đã vá thì không còn đường lấy cờ: đó là bài học của chế độ này.
import { assertAuthorizedTarget } from '../guard.js';

async function api(target, path) {
  const res = await fetch(target.url.origin + path, {
    headers: { 'User-Agent': 'SecLab-CTF/1.0' },
    signal: AbortSignal.timeout(10_000),
  });
  const text = await res.text();
  try {
    return { status: res.status, body: JSON.parse(text) };
  } catch {
    return { status: res.status, body: null, text };
  }
}

/** Danh sách thử thách + điểm hiện tại. */
export async function listChallenges(rawUrl, { consent = false } = {}) {
  const target = await assertAuthorizedTarget(rawUrl, { consent });
  const { status, body } = await api(target, '/_lab/challenges');
  if (status !== 200 || !body) {
    throw new Error(`Không đọc được /_lab/challenges (HTTP ${status}).`);
  }
  return { target: target.url.href, scope: target.scope, ...body };
}

/** Nộp cờ cho một thử thách. Trả về kết quả xác minh của SERVER. */
export async function submitFlag(rawUrl, id, flag, { consent = false } = {}) {
  const target = await assertAuthorizedTarget(rawUrl, { consent });
  const { status, body } = await api(target, `/_lab/verify?id=${encodeURIComponent(id)}&flag=${encodeURIComponent(flag)}`);
  if (status === 403) {
    return { ok: false, disabled: true, message: body?.message || 'CTF bị tắt trên bản này.' };
  }
  if (status !== 200 || !body) {
    throw new Error(`Lỗi khi nộp cờ (HTTP ${status}).`);
  }
  return body;
}
