'use strict';

const crypto = require('node:crypto');
const { hashPassword, verifyPassword } = require('./store');

const USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,30}[a-zA-Z0-9]$/;
const MIN_PASSWORD = 10;
const MAX_PASSWORD = 200;

// A short denylist rather than a strength meter. Long passphrases pass, short
// dictionary words do not, and nobody has to guess what "strong" means.
const WEAK_PASSWORDS = new Set([
  'password', 'password1', 'password12', 'password123', 'passw0rd', '12345678',
  '123456789', '1234567890', 'qwertyuiop', 'qwerty12345', 'letmein123',
  'iloveyou12', 'admin12345', 'welcome123', 'abc12345', 'aaaaaaaaaa',
  'asdfghjkl1', 'changeme12', 'secret123', 'trustno123', 'pastery123',
]);

const SESSION_COOKIE = 'paste_session';

/** A real scrypt run performed when no user matched, to flatten login timing. */
const DUMMY_HASH = hashPassword(crypto.randomBytes(24).toString('base64'));

function validateUsername(raw) {
  if (typeof raw !== 'string') return 'Choose a username';
  const username = raw.trim();
  if (username.length < 3 || username.length > 32) {
    return 'Username must be 3 to 32 characters';
  }
  if (!USERNAME_RE.test(username)) {
    return 'Use letters, numbers, dot, dash or underscore, starting and ending with a letter or number';
  }
  return null;
}

function validatePassword(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return 'Choose a password';
  if (raw.length < MIN_PASSWORD) return `Password must be at least ${MIN_PASSWORD} characters`;
  if (raw.length > MAX_PASSWORD) return `Password must be at most ${MAX_PASSWORD} characters`;

  const lowered = raw.toLowerCase();
  if (WEAK_PASSWORDS.has(lowered)) return 'That password is too common';
  if (/^(.)\1+$/.test(raw)) return 'That password is too simple';

  // Reject anything that is not valid UTF-8 text; it cannot be typed reliably.
  if (Buffer.from(raw, 'utf8').toString('utf8') !== raw) return 'That password contains invalid characters';

  return null;
}

function isValidUsername(username) {
  return validateUsername(username) === null;
}

function hash(password) {
  return hashPassword(password);
}

/**
 * Verifies a login attempt.
 *
 * The same generic failure is returned whether the username is unknown or the
 * password is wrong, so the endpoint cannot be used to enumerate accounts. When
 * the user does not exist a dummy scrypt is still performed so the response
 * time does not reveal it either.
 *
 * @returns {{ok: true, user: object} | {ok: false}}
 */
function authenticate(store, username, password) {
  const user = typeof username === 'string' ? store.findUserByUsername(username) : null;

  if (!user) {
    verifyPassword(String(password ?? ''), DUMMY_HASH);
    return { ok: false };
  }
  if (user.disabled) {
    verifyPassword(String(password ?? ''), DUMMY_HASH);
    return { ok: false };
  }
  if (!verifyPassword(String(password ?? ''), user.password_hash)) {
    return { ok: false };
  }
  return { ok: true, user };
}

/** Strongest of two password fields, or null when they do not match. */
function resolvePasswordChange(password, confirm) {
  const problem = validatePassword(password);
  if (problem) return { error: problem };
  if (password !== confirm) return { error: 'The two passwords do not match' };
  return { password };
}

function sessionCookie(token, ttlMs, secure) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    secure ? 'Secure' : '',
    `Max-Age=${Math.floor(ttlMs / 1000)}`,
  ]
    .filter(Boolean)
    .join('; ');
}

function clearSessionCookie(secure) {
  return [
    `${SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    secure ? 'Secure' : '',
    'Max-Age=0',
  ]
    .filter(Boolean)
    .join('; ');
}

function readSessionCookie(cookies) {
  const raw = cookies?.[SESSION_COOKIE];
  return typeof raw === 'string' && raw.length > 0 ? raw : null;
}

function csrfMatches(session, provided) {
  if (!session?.csrfToken || typeof provided !== 'string' || provided.length === 0) return false;
  const a = Buffer.from(crypto.createHash('sha256').update(provided).digest('hex'), 'hex');
  const b = Buffer.from(crypto.createHash('sha256').update(session.csrfToken).digest('hex'), 'hex');
  return crypto.timingSafeEqual(a, b);
}

/**
 * Rejects browser-initiated cross-site writes while still allowing scripts.
 *
 * Browsers always attach Origin to a cross-site POST; curl and server-side
 * clients send no Origin at all. So "an Origin that disagrees with us" is a
 * reliable cross-site signal, and "no Origin" is treated as a non-browser
 * caller rather than as an attack.
 */
/**
 * Reduces a URL or authority to a bare host:port, lowercased, with the default
 * port for the scheme removed so https://x and https://x:443 compare equal.
 */
function normaliseHost(value) {
  if (typeof value !== 'string') return null;
  let host = value.trim().toLowerCase();
  if (!host) return null;

  host = host.replace(/^https?:\/\//, '');
  // Drop any path or trailing slash. Browsers send Origin as scheme+host+port
  // with no path, but a hand-rolled client might not.
  const slash = host.indexOf('/');
  if (slash !== -1) host = host.slice(0, slash);
  if (host.startsWith('[')) {
    // IPv6 literal, optionally with a port after the closing bracket.
    const end = host.indexOf(']');
    if (end !== -1) return host.slice(0, end + 1);
    return host;
  }
  if (host.endsWith(':80') || host.endsWith(':443')) host = host.slice(0, host.lastIndexOf(':'));
  return host;
}

/**
 * Same-origin check for state-changing requests.
 *
 * Three signals, in order of authority:
 *
 *  1. `Sec-Fetch-Site` — set by the browser and not writable by script. When it
 *     says `cross-site`, that is a verdict, not a hint, so it is believed.
 *  2. `Origin` — compared against the Host the request arrived on. `Host` is a
 *     browser-forbidden header, so a victim's browser always supplies the real
 *     one, which is what the CSRF threat model needs. `X-Forwarded-Host` is
 *     never trusted: it is client-supplied, so an attacker could pair their own
 *     Origin with a matching spoofed header.
 *  3. A missing Origin, meaning a non-browser client, which is not the
 *     cross-site case at all.
 *
 * `Origin: null` is an *opaque* origin -- a sandboxed frame, a `file://` or
 * `data:` page, a privacy browser -- which is not the same thing as a foreign
 * origin, and plenty of ordinary visitors land there. It is therefore allowed,
 * because the defences that actually matter are unaffected: every authenticated
 * write requires an unguessable per-session CSRF token, and the session cookie
 * is `SameSite=Lax`. A sandboxed cross-origin frame is still stopped, because
 * browsers send `Sec-Fetch-Site: cross-site` for it, which is checked above.
 */
function originIsSameSite(req, publicOrigin) {
  const fetchSite = req.headers['sec-fetch-site'];

  // Authoritative when the browser provides it.
  if (typeof fetchSite === 'string') {
    if (fetchSite === 'same-origin' || fetchSite === 'none') return true;
    if (fetchSite === 'cross-site' || fetchSite === 'same-site') return false;
    // An unrecognised value: fall through to the Origin comparison.
  }

  const origin = req.headers.origin;
  if (origin === undefined) return true;
  if (Array.isArray(origin)) return false;
  // Opaque origin, discussed above.
  if (origin === 'null') return true;

  const sent = normaliseHost(origin);
  if (!sent) return false;

  const received = normaliseHost(req.headers.host);
  if (received && sent === received) return true;

  // Also accept the configured canonical origin, for deployments behind a proxy
  // that rewrites Host.
  const canonical = normaliseHost(publicOrigin);
  return Boolean(canonical && sent === canonical);
}

/** Explains a refusal, so the cause is obvious instead of guesswork. */
function originMismatch(req, publicOrigin) {
  return (
    'Cross-site request refused: the browser sent Origin ' +
    `${JSON.stringify(req.headers.origin ?? '')} for host ${JSON.stringify(req.headers.host ?? '')}. ` +
    `This site expects ${publicOrigin}. If you are reaching it by IP or another ` +
    'address, use the canonical address for this form.'
  );
}

module.exports = {
  SESSION_COOKIE,
  USERNAME_RE,
  MIN_PASSWORD,
  validateUsername,
  validatePassword,
  isValidUsername,
  hash,
  authenticate,
  resolvePasswordChange,
  sessionCookie,
  clearSessionCookie,
  readSessionCookie,
  csrfMatches,
  originIsSameSite,
  originMismatch,
  normaliseHost,
};