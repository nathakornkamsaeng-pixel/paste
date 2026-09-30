'use strict';

const path = require('node:path');

const int = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`${name} must be a non-negative integer, got ${JSON.stringify(raw)}`);
  }
  return n;
};

const root = path.resolve(__dirname, '..');

module.exports = {
  root,
  // Bind to loopback only. nginx is the sole public entry point, so the app
  // itself never needs to be reachable from the outside.
  host: process.env.PASTE_HOST || '127.0.0.1',
  port: int('PASTE_PORT', 8790),

  // Absolute origin used when building links that are handed back to clients
  // (API responses, redirects). Pinned rather than derived from the Host
  // header so a spoofed Host cannot steer a user to another domain.
  publicOrigin: (process.env.PASTE_PUBLIC_ORIGIN || 'https://paste.everlyce.com').replace(/\/+$/, ''),

  dbPath: process.env.PASTE_DB || path.join(root, 'data', 'paste.db'),

  publicDir: path.join(root, 'public'),
  hljsDir: path.join(root, 'node_modules', 'highlight.js'),

  // Anonymous ceilings. Accounts get their own, larger set below.
  // 48-byte key backing session secrets and proof-of-work challenge signatures.
  // Shared with the app at boot; see src/app.js makeSecrets.
  serverSecret: null,

  maxPasteBytes: int('PASTE_MAX_BYTES', 1024 * 1024),
  maxFilenameLen: 128,

  // Tier limits. `account` applies once a request carries a valid session.
  tiers: {
    anonymous: {
      // 48-byte key backing session secrets and proof-of-work challenge signatures.
  // Shared with the app at boot; see src/app.js makeSecrets.
  serverSecret: null,

  maxPasteBytes: int('PASTE_MAX_BYTES', 1024 * 1024),
      createPerWindow: int('PASTE_CREATE_MAX', 10),
    },
    account: {
      maxPasteBytes: int('PASTE_MAX_BYTES_ACCOUNT', 4 * 1024 * 1024),
      createPerWindow: int('PASTE_CREATE_MAX_ACCOUNT', 30),
    },
  },
  createWindowMs: int('PASTE_CREATE_WINDOW_MS', 60_000),
  readRate: {
    windowMs: int('PASTE_READ_WINDOW_MS', 60_000),
    max: int('PASTE_READ_MAX', 240),
  },

  // Auth-specific limits. Signup is open to anyone, so it is the most
  // attractive thing to hammer and gets the tightest budget.
  authRate: {
    signup: { windowMs: int('PASTE_SIGNUP_WINDOW_MS', 3600_000), max: int('PASTE_SIGNUP_MAX', 5) },
    login: { windowMs: int('PASTE_LOGIN_WINDOW_MS', 900_000), max: int('PASTE_LOGIN_MAX', 10) },
    // Per-account, so one account cannot be ground down from many IPs.
    loginPerAccount: { windowMs: int('PASTE_LOGIN_ACCOUNT_WINDOW_MS', 900_000), max: int('PASTE_LOGIN_ACCOUNT_MAX', 5) },
  },

  sessionTtlMs: int('PASTE_SESSION_TTL_MS', 30 * 24 * 3600_000),
  // Unlisted pastes never appear in listings, only by direct link.
  defaultVisibility: process.env.PASTE_DEFAULT_VISIBILITY === 'unlisted' ? 'unlisted' : 'public',

  // Burn-after-read has to be claimed by exactly one reader, so the window has
  // to be comfortably longer than the time it takes the body to be delivered.
  burnClaimMs: int('PASTE_BURN_CLAIM_MS', 5_000),

  // Proof-of-work captcha.
  //
  // Cost is 2^bits hashes, and solve time is exponentially distributed, so the
  // *mean* is not what a visitor feels: at 20 bits real attempts ranged from
  // 1M to 3.4M, i.e. roughly 1s to 5s. 18 bits is the compromise chosen here,
  // giving a typical sub-second solve while still costing a scripted client
  // real work per signup. Raise it if signup is being abused; the signup rate
  // limit remains the actual backstop.
  pow: {
    bits: int('PASTE_POW_BITS', 18),
    // A slow device gives up and falls back to the honeypot rather than
    // leaving the visitor staring at a spinner.
    budgetMs: int('PASTE_POW_BUDGET_MS', 25_000),
  },

  // Captcha provider: the built-in proof-of-work by default, Turnstile when a
  // secret is configured, or 'none' to rely on the honeypot and rate limits
  // alone.
  captcha: {
    provider:
      process.env.PASTE_CAPTCHA ||
      (process.env.PASTE_TURNSTILE_SECRET ? 'turnstile' : 'pow'),
    turnstileSecret: process.env.PASTE_TURNSTILE_SECRET || '',
    turnstileSiteKey: process.env.PASTE_TURNSTILE_SITE_KEY || '',
    // Set when a captcha is required but failed, so the form can re-render.
    timeoutMs: int('PASTE_CAPTCHA_TIMEOUT_MS', 5000),
  },

  registrationOpen: process.env.PASTE_REGISTRATION_OPEN !== '0',

  // Comma-separated usernames that are promoted to admin on every boot.
  // Configuration-driven so nobody can self-promote through the signup form.
  admins: (process.env.PASTE_ADMINS || '')
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean),

  // Privileged actions are rare, so they get a tight budget of their own.
  adminRate: {
    windowMs: int('PASTE_ADMIN_WINDOW_MS', 60_000),
    max: int('PASTE_ADMIN_MAX', 60),
  },

  // Expired pastes are swept on this interval and opportunistically on write.
  sweepIntervalMs: int('PASTE_SWEEP_INTERVAL_MS', 60_000),
  recentLimit: 50,
};
