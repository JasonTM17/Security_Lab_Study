// Token-bucket rate limiter — module PHÒNG THỦ cốt lõi.
// Mỗi "khóa" (thường là IP của client) có một xô chứa tối đa `capacity` token,
// được nạp lại dần với tốc độ `refillPerSec` token/giây. Hết token → 429.
// Đây chính là kỹ thuật mà Cloudflare, nginx (limit_req), API gateway dùng
// để chống DoS lớp ứng dụng.

export function tokenBucketLimiter({
  capacity = 30,
  refillPerSec = 5,
  keyFn = (req) => req.socket?.remoteAddress || 'unknown',
} = {}) {
  const buckets = new Map();

  // Dọn xô của client không hoạt động để không rò rỉ bộ nhớ.
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [key, b] of buckets) {
      if (now - b.last > 120_000) buckets.delete(key);
    }
  }, 60_000);
  if (sweeper.unref) sweeper.unref();

  return function limiter(req, res, next) {
    const key = keyFn(req);
    const now = Date.now();
    let b = buckets.get(key);
    if (!b) {
      b = { tokens: capacity, last: now };
      buckets.set(key, b);
    }
    const elapsed = (now - b.last) / 1000;
    b.tokens = Math.min(capacity, b.tokens + elapsed * refillPerSec);
    b.last = now;

    if (b.tokens >= 1) {
      b.tokens -= 1;
      res.setHeader('X-RateLimit-Limit', String(capacity));
      res.setHeader('X-RateLimit-Remaining', String(Math.floor(b.tokens)));
      next();
      return;
    }

    const retryAfter = Math.max(1, Math.ceil((1 - b.tokens) / refillPerSec));
    res.statusCode = 429;
    res.setHeader('Retry-After', String(retryAfter));
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(
      JSON.stringify({
        error: 'rate_limited',
        message: `Bạn đã gửi quá nhiều yêu cầu. Thử lại sau ${retryAfter}s.`,
        retryAfter,
      })
    );
  };
}
