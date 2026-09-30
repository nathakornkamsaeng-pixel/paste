'use strict';

/**
 * Fixed-window counters, keyed by client IP.
 *
 * Deliberately in-process: this sits behind nginx, which already applies a
 * coarse `limit_req` at the edge, so the second layer only has to stop a
 * single client from hammering the database. Counters are swept lazily on
 * access plus on a timer, so an attacker rotating IPs cannot make memory grow
 * without bound.
 */
class RateLimiter {
  constructor({ windowMs, max, maxKeys = 50_000, now = () => Date.now() }) {
    this.windowMs = windowMs;
    this.max = max;
    this.maxKeys = maxKeys;
    this.now = now;
    this.hits = new Map();
    this.timer = setInterval(() => this.sweep(), Math.min(windowMs, 60_000));
    this.timer.unref?.();
  }

  /** @returns {{allowed: boolean, remaining: number, retryAfterSec: number}} */
  take(key, cost = 1) {
    const t = this.now();
    let entry = this.hits.get(key);
    if (!entry || entry.resetAt <= t) {
      entry = { count: 0, resetAt: t + this.windowMs };
      // Map preserves insertion order, so evicting the first key drops the
      // oldest bucket rather than an arbitrary one.
      if (this.hits.size >= this.maxKeys) this.hits.delete(this.hits.keys().next().value);
      this.hits.set(key, entry);
    }

    entry.count += cost;
    const allowed = entry.count <= this.max;
    const remaining = Math.max(0, this.max - entry.count);
    const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - t) / 1000));
    return { allowed, remaining, retryAfterSec };
  }

  /** Clears a bucket, e.g. after a successful login. */
  reset(key) {
    this.hits.delete(key);
  }

  sweep() {
    const t = this.now();
    for (const [key, entry] of this.hits) {
      if (entry.resetAt <= t) this.hits.delete(key);
    }
  }

  stop() {
    clearInterval(this.timer);
    this.hits.clear();
  }
}

/**
 * Derives the client IP for rate limiting.
 *
 * Behind Cloudflare the vhost rewrites $remote_addr to the real client via
 * `real_ip_header CF-Connecting-IP` restricted to Cloudflare's ranges, then
 * forwards it as X-Real-IP. That header is therefore only trustworthy because
 * nginx overwrites it; the fallbacks exist for direct/local testing.
 */
function clientIp(req) {
  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string') {
    const first = realIp.split(',')[0].trim();
    if (isIpv4(first)) return first;
  }

  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    for (const candidate of forwarded.split(',')) {
      const ip = candidate.trim();
      if (isIpv4(ip)) return ip;
    }
  }

  return req.socket?.remoteAddress || '0.0.0.0';
}

function isIpv4(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

module.exports = { RateLimiter, clientIp };