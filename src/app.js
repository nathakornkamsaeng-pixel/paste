'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const config = require('./config');
const { validId, verifyPassword } = require('./store');
const { escapeHtml } = require('./highlight');

const auth = require('./auth');
const captcha = require('./captcha');
const legal = require('./legal');
const { RateLimiter, clientIp } = require('./limits');
const hl = require('./highlight');
const views = require('./views');
const {
  HttpError,
  methodNotAllowed,
  send,
  sendHtml,
  sendJson,
  readBody,
  parseForm,
  newNonce,
  safeFilename,
  contentDisposition,
  parseCookies,
} = require('./http');

/* Reachable while a forced password change is outstanding. */
const FORCED_CHANGE_ALLOWED = new Set([
  '/account/password',
  '/logout',
  '/privacy',
  '/terms',
  '/cookies',
  '/imprint',
  '/healthz',
]);

/**
 * Small Markdown subset for the legal documents: headings, bold, inline code,
 * links, unordered lists, horizontal rules and paragraphs.
 *
 * Deliberately tiny and escaping-first. Admin-authored text still has to be
 * escaped like any other content, because an administrator account can be
 * compromised and these pages are rendered to every visitor.
 */
function renderMarkdown(text) {
  const esc = (value) =>
    String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

  const inline = (value) =>
    esc(value)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" rel="noopener noreferrer">$1</a>');

  const lines = String(text).split('\n');
  const out = [];
  let list = null;
  // Paragraph text is buffered until a blank line, so inline markup may span
  // a line break: **bold** written across two lines would otherwise print its
  // asterisks.
  let paragraph = [];

  const closeList = () => {
    if (list) { out.push(`<${list}>`); list = null; }
  };

  const flushParagraph = () => {
    if (paragraph.length === 0) return;
    out.push(`<p>${inline(paragraph.join(' '))}</p>`);
    paragraph = [];
  };

  for (const raw of lines) {
    const line = raw.trimEnd();

    if (/^#{1,6}\s+/.test(line)) {
      flushParagraph();
      closeList();
      const level = Math.min(6, (/^#+/.exec(line)[0]).length);
      out.push(`<h${level}>${inline(line.replace(/^#+\s+/, ''))}</h${level}>`);
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      flushParagraph();
      if (list !== 'ul') { closeList(); out.push('<ul>'); list = 'ul'; }
      out.push(`<li>${inline(line.replace(/^\s*[-*]\s+/, ''))}</li>`);
      continue;
    }
    if (/^\s*\d+\.\s+/.test(line)) {
      flushParagraph();
      if (list !== 'ol') { closeList(); out.push('<ol>'); list = 'ol'; }
      out.push(`<li>${inline(line.replace(/^\s*\d+\.\s+/, ''))}</li>`);
      continue;
    }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) {
      flushParagraph();
      closeList();
      out.push('<hr>');
      continue;
    }
    if (line.trim() === '') {
      flushParagraph();
      closeList();
      continue;
    }

    paragraph.push(line.trim());
  }
  flushParagraph();
  closeList();
  return out.join('\n');
}

const TTL_MS = {
  '10m': 10 * 60_000,
  '1h': 60 * 60_000,
  '1d': 24 * 60 * 60_000,
  '1w': 7 * 24 * 60 * 60_000,
  '30d': 30 * 24 * 60 * 60_000,
};

function ttlFrom(value) {
  if (value === undefined || value === null || value === '' || value === 'never') return null;
  const known = TTL_MS[String(value)];
  if (known) return known;

  // Also accept an explicit seconds count for scripted use.
  const secs = Number(value);
  if (Number.isFinite(secs) && secs > 0 && secs <= 365 * 24 * 3600) return secs * 1000;
  throw new HttpError(400, 'Unknown expiry value');
}

/** Per-paste secrets derived from a server key, so they survive a restart. */
function makeSecrets() {
  const file = path.join(path.dirname(config.dbPath), 'secret');
  let key;
  try {
    key = fs.readFileSync(file);
    if (key.length < 32) throw new Error('short');
  } catch {
    key = crypto.randomBytes(48);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, key, { mode: 0o600 });
  }

  const derive = (label, id, token) =>
    crypto.createHmac('sha256', key).update(`${label}:${id}:${token}`).digest('base64url');

  const preMac = (ts) => crypto.createHmac('sha256', key).update(`pre:${ts}`).digest('base64url');

  // Proof-of-work challenges are signed with the same key, so the captcha is
  // bound to this deployment's secret and cannot be pre-computed offline.
  config.serverSecret = key;

  return {
    unlock: (id, token) => derive('unlock', id, token),
    remove: (id, token) => derive('remove', id, token),

    /**
     * Self-contained, stateless CSRF token for the signup and login forms.
     *
     * Those forms are used when no session exists yet, so there is no
     * per-session secret to hang a token off. This is an HMAC of a timestamp,
     * which needs no storage and expires on its own. It is a speed bump that
     * stops a casual cross-site replay, not the main defence: the real check
     * for those endpoints is the same-origin Origin test, and every
     * authenticated write uses the much stronger per-session token.
     */
    issuePre() {
      // Read the clock once. Calling it twice would sign a different
      // timestamp than the one embedded in the token, and verification would
      // fail whenever a millisecond happened to tick in between.
      const ts = Date.now();
      return `${ts}.${preMac(ts)}`;
    },

    verifyPre(token, maxAgeMs = 3600_000) {
      const parts = String(token ?? '').split('.');
      if (parts.length !== 2) return false;
      const ts = Number(parts[0]);
      if (!Number.isInteger(ts)) return false;
      if (Math.abs(Date.now() - ts) > maxAgeMs) return false;
      const a = Buffer.from(parts[1]);
      const b = Buffer.from(preMac(ts));
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    },
  };
}

/**
 * Session cookie carries two independent derived secrets, so unlocking a
 * password-protected paste does not also grant delete rights.
 */
function cookieName(id) {
  return `pp_${id}`;
}

function readSession(cookies, id, row, secrets) {
  const raw = cookies[cookieName(id)];
  if (typeof raw !== 'string') return { unlocked: !row.password_hash, deleteToken: null };

  const [unlockToken, removeToken] = raw.split('.');
  const unlocked = !row.password_hash
    ? true
    : typeof unlockToken === 'string' &&
      unlockToken.length > 0 &&
      crypto.timingSafeEqual(
        crypto.createHash('sha256').update(unlockToken).digest(),
        crypto.createHash('sha256').update(secrets.unlock(id, row.edit_token)).digest(),
      );

  const canDelete =
    typeof removeToken === 'string' &&
    removeToken.length > 0 &&
    crypto.timingSafeEqual(
      crypto.createHash('sha256').update(removeToken).digest(),
      crypto.createHash('sha256').update(secrets.remove(id, row.edit_token)).digest(),
    );

  return { unlocked, deleteToken: canDelete ? removeToken : null };
}

/**
 * Session cookie value.
 *
 * The two halves are independently derived, so holding one grants nothing
 * else: unlocking a password-protected paste issues only the unlock half,
 * while creating one issues both, since the creator may want to delete it.
 * `existingDeleteToken` is carried through on re-issue so that unlocking from
 * the same browser that created the paste does not silently drop delete rights.
 */
function sessionValue(id, secrets, editToken, { withDelete, existingDeleteToken = null } = {}) {
  const unlock = secrets.unlock(id, editToken);
  const remove = withDelete ? secrets.remove(id, editToken) : existingDeleteToken;
  return remove ? `${unlock}.${remove}` : unlock;
}

function sessionCookie(id, secrets, editToken, secure, opts) {
  const value = sessionValue(id, secrets, editToken, opts);
  return [
    `${cookieName(id)}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    secure ? 'Secure' : '',
    'Max-Age=86400',
  ]
    .filter(Boolean)
    .join('; ');
}

/**
 * Only same-site absolute paths are honoured as a post-login destination, so
 * ?next=//evil.example or https://evil.example cannot bounce a user away after
 * they authenticate.
 */
function safeNext(value) {
  const raw = typeof value === 'string' ? value : '';
  if (!raw.startsWith('/')) return '/account';
  if (raw.startsWith('//')) return '/account';
  if (/[\r\n]/.test(raw)) return '/account';
  return raw.slice(0, 200);
}

/**
 * Redirect back to /admin with a notice.
 *
 * Built with URLSearchParams so the encoding is consistent rather than
 * hand-rolled, and so a message containing & or = cannot break the query.
 */
function adminRedirect(res, { ok = null, err = null } = {}) {
  const query = new URLSearchParams();
  if (ok) query.set('ok', String(ok).slice(0, 200));
  if (err) query.set('err', String(err).slice(0, 200));
  const location = query.toString() ? `/admin?${query}` : '/admin';
  return send(res.req, res.res, 303, '', { Location: location });
}

/**
 * Admin password reset.
 *
 * There is no mail on this box, so a reset sets the password directly and the
 * admin is responsible for passing the new one on. The plaintext is never
 * logged or stored: only that a reset happened, and never its value.
 */
async function adminResetPassword({ req, res, store, admin, targetId, body, ip }) {
  const target = store.getUserFull(targetId);
  if (!target) throw new HttpError(404, 'No such account');

  const problem = auth.validatePassword(body.password);
  if (problem) {
    store.audit({
      actorId: admin.id, actorName: admin.username, action: 'admin.password.rejected',
      target: target.username, detail: problem, ip,
    });
    return adminRedirect({ req, res }, { err: problem });
  }
  if (body.password !== body.confirm) {
    return adminRedirect({ req, res }, { err: 'The two passwords do not match' });
  }

  store.updatePassword(targetId, auth.hash(body.password));

  // Every existing session is dropped and the account is flagged, so the
  // temporary password is not the password the user ends up keeping.
  const killed = store.requirePasswordChange(targetId);

  store.audit({
    actorId: admin.id, actorName: admin.username, action: 'admin.password.reset',
    target: target.username,
    detail: `sessions_revoked=${killed}, change_required`, ip,
  });

  return adminRedirect({
    req,
    res,
  }, {
    ok:
      `password reset for ${target.username}. They must choose a new one at their next ` +
      `sign-in (${killed} session(s) signed out)`,
  });
}

/** Admin account deletion. */
async function adminDeleteUser({ req, res, store, admin, targetId, body, ip }) {
  const target = store.getUserFull(targetId);
  if (!target) throw new HttpError(404, 'No such account');

  // Two ways to lock yourself out, both refused: deleting yourself, and
  // deleting the last remaining admin.
  if (targetId === admin.id) {
    store.audit({
      actorId: admin.id, actorName: admin.username, action: 'admin.delete.refused',
      target: target.username, detail: 'self-delete', ip,
    });
    return adminRedirect({ req, res }, { err: 'You cannot delete your own account' });
  }
  if (target.is_admin && store.adminCount() <= 1) {
    store.audit({
      actorId: admin.id, actorName: admin.username, action: 'admin.delete.refused',
      target: target.username, detail: 'last-admin', ip,
    });
    return adminRedirect({ req, res }, { err: 'Cannot delete the only admin' });
  }

  const deletePastes = body.pastes === 'delete';
  const result = store.deleteUser(targetId, { deletePastes });
  if (!result.ok) throw new HttpError(404, 'No such account');

  store.audit({
    actorId: admin.id, actorName: admin.username, action: 'admin.user.delete',
    target: target.username,
    detail: `pastes=${deletePastes ? result.removedPastes : `kept(${result.pasteCount})`}`,
    ip,
  });

  return adminRedirect({ req, res }, { ok: `deleted ${target.username}` });
}

// Brand assets are served from a fixed allow-list of names rather than by
  // joining user input onto a directory path, so there is no traversal to get
  // wrong. Anything not listed simply does not exist.
  const BRAND_DIR = path.join(config.publicDir, 'branding');
  const brandTypes = new Map([
    ['favicon.svg', 'image/svg+xml'],
    ['favicon.ico', 'image/x-icon'],
    ['favicon-16.png', 'image/png'],
    ['favicon-32.png', 'image/png'],
    ['favicon-48.png', 'image/png'],
    ['apple-touch-icon.png', 'image/png'],
    ['icon-192.png', 'image/png'],
    ['icon-512.png', 'image/png'],
    ['og.png', 'image/png'],
    ['logo.png', 'image/png'],
    ['site.webmanifest', 'application/manifest+json'],
  ]);
  const brandCache = new Map();

  function serveBrand(req, res, name) {
    const type = brandTypes.get(name);
    if (!type) return false;

    const file = path.join(BRAND_DIR, name);
    // Defence in depth behind the allow-list: the resolved path must still be
    // inside the brand directory.
    if (!path.resolve(file).startsWith(path.resolve(BRAND_DIR) + path.sep)) return false;

    let body = brandCache.get(name);
    if (body === undefined) {
      try {
        body = fs.readFileSync(file);
      } catch {
        return false;
      }
      brandCache.set(name, body);
    }

    const immutable = name.startsWith('favicon-') || name.startsWith('icon-');
    send(req, res, 200, body, {
      'Content-Type': type,
      'Cache-Control': `public, max-age=${immutable ? 604800 : 3600}`,
    });
    return true;
  }

  function createApp({ store, secrets, log = console }) {
  const createLimiters = {
    anonymous: new RateLimiter({ windowMs: config.createWindowMs, max: config.tiers.anonymous.createPerWindow }),
    account: new RateLimiter({ windowMs: config.createWindowMs, max: config.tiers.account.createPerWindow }),
  };
  const readLimiter = new RateLimiter(config.readRate);
  const signupLimiter = new RateLimiter(config.authRate.signup);
  const loginLimiter = new RateLimiter(config.authRate.login);
  const loginAccountLimiter = new RateLimiter(config.authRate.loginPerAccount);
  const adminLimiter = new RateLimiter(config.adminRate);
  let lastSweep = 0;

  /** Resolves the caller into { session, user }, or anonymous. */
  function identify(req) {
    const token = auth.readSessionCookie(req.cookies);
    if (!token) return { session: null, user: null };
    const session = store.resolveSession(token);
    if (!session) return { session: null, user: null };
    return {
      session,
      user: {
        id: session.userId,
        username: session.username,
        isAdmin: session.isAdmin,
        mustChangePassword: session.mustChangePassword,
        csrfToken: session.csrfToken,
      },
    };
  }

  /** Marks a browser as safe to attach CSRF tokens to its forms. */
  function preSessionToken() {
    return secrets.issuePre();
  }

  // Built once: the highlight.js theme is static and reading it per request
  // would mean a disk hit on every page view.
  const stylesheet = `${hljsTheme()}\n${fs.readFileSync(path.join(config.publicDir, 'app.css'), 'utf8')}`;
  const clientJs = fs.readFileSync(path.join(config.publicDir, 'app.js'), 'utf8');
  const powWorkerJs = fs.readFileSync(path.join(config.publicDir, 'pow-worker.js'), 'utf8');

  function hljsTheme() {
    try {
      return hl.stylesheet();
    } catch {
      return '';
    }
  }

  function enforce(limiter, req) {
    const ip = clientIp(req);
    const { allowed, retryAfterSec } = limiter.take(ip);
    if (!allowed) {
      throw new HttpError(429, 'Too many requests, slow down', { 'Retry-After': String(retryAfterSec) });
    }
    return ip;
  }

  /**
   * Guards an authenticated write, or throws.
   *
   * Two independent checks: a same-origin Origin, and the per-session CSRF
   * token. Either alone would do; together a cross-site write has to defeat
   * both to get through.
   */
  function requireSession(req, session, csrf) {
    if (!session) throw new HttpError(401, 'Log in to do that');
    if (!auth.originIsSameSite(req, config.publicOrigin)) {
      throw new HttpError(403, auth.originMismatch(req, config.publicOrigin));
    }
    const provided = csrf ?? req.headers['x-csrf-token'] ?? req.body?.csrf;
    if (!auth.csrfMatches(session, provided)) {
      throw new HttpError(403, 'Your session expired. Reload the page and try again.');
    }
    return session;
  }

  /**
   * Absolute URL of the request currently being served. Used for the copy-link
   * button and the password page's self-reference, where the path really is
   * the paste's own path. It is deliberately NOT used to build links for a
   * newly created paste; see config.publicOrigin for that.
   */
  function currentUrl(req) {
    return `${config.publicOrigin}${req.url.split('?')[0]}`;
  }

  function parseCreateRequest(req, body) {
    const contentType = String(req.headers['content-type'] || '').split(';')[0].trim();

    if (contentType === 'application/json') {
      let data;
      try {
        data = JSON.parse(body || '{}');
      } catch {
        throw new HttpError(400, 'Body is not valid JSON');
      }
      if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        throw new HttpError(400, 'Expected a JSON object');
      }
      return {
        content: data.content ?? data.text,
        filename: data.filename ?? null,
        language: data.language ?? data.lang ?? null,
        ttl: data.ttl ?? data.expires,
        burn: Boolean(data.burn),
        password: data.password ?? null,
        visibility: data.visibility,
      };
    }

    if (contentType === 'text/plain') {
      return {
        content: body,
        filename: req.headers['x-paste-filename'] ?? null,
        language: req.headers['x-paste-language'] ?? null,
        ttl: req.headers['x-paste-ttl'] ?? null,
        burn: String(req.headers['x-paste-burn'] ?? '') === '1',
        password: null,
      };
    }

    const form = parseForm(body);
    return {
      content: form.content ?? form.text,
      filename: form.filename || null,
      language: form.language || null,
      ttl: form.ttl,
      burn: form.burn === '1' || form.burn === 'on' || form.burn === 'true',
      password: form.password || null,
      visibility: form.visibility,
    };
  }

  /**
 * Admin gate.
 *
 * Checked on every /admin route independently rather than once at the top, so
 * a route added later cannot forget it. The flag is re-read from the database
 * instead of being trusted from the session, so revoking admin takes effect on
 * that admin's very next request rather than at their next login.
 *
 * A signed-in non-admin gets a 404 rather than a 403, so the panel's existence
 * is not advertised to every account.
 */
function requireAdmin(store, req, user) {
  if (!user) throw new HttpError(403, 'Not available');
  if (!store.isAdmin(user.id)) throw new HttpError(404, 'Page not found');
  return { session: req.session, user };
}

function tierLimits(tier) {
    return config.tiers[tier] ?? config.tiers.anonymous;
  }

  /** Signed-in callers get the account tier. */
  function tierFor(user) {
    return user ? 'account' : 'anonymous';
  }

  /**
   * @param {object} input parsed create request
   * @param {'anonymous'|'account'} tier
   * @param {object|null} user signed-in account, if any
   */
  function buildPaste(input, tier = 'anonymous', user = null) {
    if (typeof input.content !== 'string' || input.content.length === 0) {
      throw new HttpError(400, 'Paste content is empty');
    }
    const max = tierLimits(tier).maxPasteBytes;
    const bytes = Buffer.byteLength(input.content, 'utf8');
    if (bytes > max) {
      throw new HttpError(413, `Paste is larger than the ${views.formatBytes(max)} limit`);
    }

    const filename = input.filename ? safeFilename(input.filename, null) : null;
    const password = input.password ? String(input.password) : null;
    if (password && password.length > 256) throw new HttpError(400, 'Password is too long');

    // Unlisting is an account feature: an anonymous caller asking for it is
    // silently downgraded to a public paste rather than being trusted.
    const requested = input.visibility === 'unlisted' ? 'unlisted' : 'public';
    const visibility = user ? requested : 'public';

    return {
      content: input.content,
      filename,
      language: hl.normaliseLanguage(input.language, filename),
      ttlMs: ttlFrom(input.ttl),
      burn: Boolean(input.burn),
      password,
      ownerId: user ? user.id : null,
      visibility,
    };
  }

  function servePaste({ req, res, id, asDownload, asRaw }) {
    const peeked = store.peek(id);
    if (!peeked) throw new HttpError(404, 'No such paste, or it has expired');

    const cookies = parseCookies(req.headers.cookie);
    const session = readSession(cookies, id, peeked, secrets);

    if (peeked.password_hash && !session.unlocked) {
      const nonce = newNonce();
      const wantsJson = String(req.headers.accept || '').includes('application/json');
      if (wantsJson) throw new HttpError(401, 'This paste requires a password');
      return sendHtml(
        req,
        res,
        401,
        views.passwordPage({
          nonce,
          user: req.user,
          id,
          selfUrl: currentUrl(req),
          error: req.query?.error ? String(req.query.error).slice(0, 200) : null,
        }),
        { nonce },
      );
    }

    // Only reached once authentication is settled, so a locked burn paste
    // cannot be consumed by a request that has not unlocked it.
    const paste = store.claim(id, { consume: Boolean(peeked.burn) });
    if (!paste) throw new HttpError(404, 'No such paste, or it has expired');

    if (asRaw || asDownload) {
      const filename = safeFilename(paste.filename, `${paste.id}.txt`);
      const headers = asDownload
        ? {
            'Content-Type': 'application/octet-stream; charset=utf-8',
            'Content-Disposition': contentDisposition(filename, 'attachment'),
          }
        : {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': contentDisposition(filename, 'inline'),
          };
      if (paste.burn) headers['Cache-Control'] = 'no-store';
      return send(req, res, 200, paste.content, headers);
    }

    const rendered = hl.render(paste.content, paste.language);
    const nonce = newNonce();
    return sendHtml(
      req,
      res,
      200,
      views.pastePage({
        nonce,
        user: req.user,
        paste: { ...paste, truncated: rendered.truncated },
        rendered,
        selfUrl: currentUrl(req),
        session,
      }),
      { nonce },
    );
  }

  const handler = async (req, res) => {
    const started = process.hrtime.bigint();
    let status = 200;
    let note = '';
    // Declared out here because the error handler renders a page with the nav
    // and needs to know who the caller was even when routing failed.
    let user = null;

    try {
      let url;
      try {
        url = new URL(req.url, 'http://internal.invalid');
      } catch {
        throw new HttpError(400, 'Malformed request URL');
      }
      const pathname = decodeURIComponent(url.pathname).replace(/\/+$/, '') || '/';
      req.query = Object.fromEntries(url.searchParams);

      if (pathname === '/static/app.css') {
        return send(req, res, 200, stylesheet, {
          'Content-Type': 'text/css; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
        });
      }
      if (pathname === '/static/app.js') {
        return send(req, res, 200, clientJs, {
          'Content-Type': 'text/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
        });
      }
      // Served as a real file rather than a blob: URL so the CSP can stay at
      // worker-src 'self' with no blob: exception.
      const brandMatch = /^\/branding\/([A-Za-z0-9._-]+)$/.exec(pathname);
      if (brandMatch) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD']);
        }
        if (serveBrand(req, res, brandMatch[1])) return undefined;
        throw new HttpError(404, 'No such asset');
      }

      if (pathname === '/static/pow-worker.js') {
        return send(req, res, 200, powWorkerJs, {
          'Content-Type': 'text/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
        });
      }
      /* --------------------------------------------------- first-run setup */

      if (pathname === '/setup') {
        // Closed permanently once an administrator exists. 404 rather than 403
        // so the route does not advertise itself later.
        if (!store.setupNeeded()) throw new HttpError(404, 'Page not found');

        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const nonce = newNonce();
          const fields = captcha.fields();
          return sendHtml(req, res, 200, views.setupPage({
            nonce,
            csrfToken: preSessionToken(),
            captchaScript: fields.script,
            captchaWidget: fields.html,
            error: req.query.err ? String(req.query.err).slice(0, 160) : null,
          }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);

        // Same protections as signup: the token is the real gate, these are
        // there so the page cannot be used to grind at anything.
        enforce(signupLimiter, req);
        if (!auth.originIsSameSite(req, config.publicOrigin)) {
          throw new HttpError(403, auth.originMismatch(req, config.publicOrigin));
        }

        const body = parseForm(await readBody(req, 8192));
        if (!secrets.verifyPre(body.csrf)) {
          throw new HttpError(403, 'That form expired. Reload the page and try again.');
        }

        const fail = (message) =>
          send(req, res, 303, '', { Location: `/setup?err=${encodeURIComponent(message)}` });

        const nameProblem = auth.validateUsername(body.username);
        if (nameProblem) return fail(nameProblem);
        const passProblem = auth.validatePassword(body.password);
        if (passProblem) return fail(passProblem);
        if (body.password !== body.confirm) return fail('The two passwords do not match');

        const verdict = await captcha.verify({ form: body, headers: req.headers, remoteip: clientIp(req) });
        if (!verdict.ok) return fail(verdict.reason || 'Could not verify you are human.');

        if (store.findUserByUsername(body.username)) return fail('Choose a different username.');

        const claimed = store.claimSetup(body.username, auth.hash(body.password));
        if (!claimed.ok) throw new HttpError(409, 'Setup has already been completed');

        const session = store.createSession(claimed.user.id, config.sessionTtlMs);
        log.log(`[paste] first administrator created: ${claimed.user.username}`);
        return send(req, res, 303, '', {
          Location: '/account',
          'Set-Cookie': auth.sessionCookie(session.token, config.sessionTtlMs, true),
        });
      }

      if (pathname === '/healthz') {
        return sendJson(req, res, 200, { ok: true, pastes: store.count(), uptime: Math.round(process.uptime()) });
      }

      // Resolved once per request: cookies for identify(), and the caller's
      // account so pages can render the right nav and size limits can be tiered.
      req.cookies = parseCookies(req.headers.cookie);
      const identified = identify(req);
      user = identified.user;
      req.session = identified.session;
      req.user = identified.user;

      /*
       * Forced password change.
       *
       * When an administrator resets someone's password, that account is signed
       * out everywhere and must choose a new one before anything else works.
       * This sits in front of routing so it cannot be forgotten by a route
       * added later. Only the change-password page, static assets, the legal
       * pages and signing out remain reachable.
       */
      if (user?.mustChangePassword && !FORCED_CHANGE_ALLOWED.has(pathname)) {
        return send(req, res, 303, '', { Location: '/account/password' });
      }
      if (pathname === '/favicon.ico') return send(req, res, 204, '');

      if (pathname === '/' || pathname === '/index.html') {
        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const nonce = newNonce();
          const wantsJson = String(req.headers.accept || '').includes('application/json');
          if (wantsJson) {
            return sendJson(req, res, 200, {
              service: 'Everlyce paste',
              max_bytes: config.maxPasteBytes,
              endpoints: {
                create: 'POST /api/paste',
                view: 'GET /{id}',
                raw: 'GET /raw/{id}',
                download: 'GET /dl/{id}',
                recent: 'GET /recent',
              },
            });
          }
          return sendHtml(req, res, 200, views.homePage({ nonce, user }), { nonce });
        }
        if (req.method === 'POST') {
          const tier = tierFor(user);
          enforce(createLimiters[tier], req);
          const body = await readBody(req, tierLimits(tier).maxPasteBytes + 8192);
          const paste = buildPaste(parseCreateRequest(req, body), tier, user);
          const created = store.create(paste);
          const origin = config.publicOrigin;

          const wantsJson = String(req.headers['content-type'] || '').includes('application/json');
          if (wantsJson) {
            return sendJson(
              req,
              res,
              201,
              {
                id: created.id,
                url: `${origin}/${created.id}`,
                raw_url: `${origin}/raw/${created.id}`,
                download_url: `${origin}/dl/${created.id}`,
                expires_at: created.expiresAt ? new Date(created.expiresAt).toISOString() : null,
                burn: Boolean(paste.burn),
                visibility: paste.visibility,
                visibility: paste.visibility,
              },
              { Location: `${origin}/${created.id}`, 'Set-Cookie': // withDelete is false for signed-in creators on purpose: an owned paste is
              // deleted from /account while signed in, so no standing delete
              // capability is left lying in this browser's cookies.
              sessionCookie(created.id, secrets, created.editToken, true, { withDelete: !user }) },
            );
          }

          return sendHtml(req, res, 303, '', {
            headers: {
              Location: `${origin}/${created.id}`,
              'Set-Cookie': sessionCookie(created.id, secrets, created.editToken, true, { withDelete: !user }),
            },
          });
        }
        throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);
      }

      if (pathname === '/api/paste') {
        // GET is documentation, not an error: the UI links here, and a link
        // that answers 405 is just a bug that looks like one to a visitor.
        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const docs = {
            service: 'Everlyce paste',
            create: {
              method: 'POST',
              path: '/api/paste',
              content_type: ['application/json', 'text/plain', 'application/x-www-form-urlencoded'],
              fields: {
                content: 'string, required. The paste body.',
                filename: 'string, optional. Shown as the title; sanitised.',
                language: 'string, optional. highlight.js name or file extension.',
                ttl: 'string|number, optional. never | 10m | 1h | 1d | 1w | 30d, or seconds.',
                burn: 'boolean, optional. Delete the paste once it has been read.',
                password: 'string, optional. Require a password to view.',
              },
              headers_for_text_plain: {
                'X-Paste-Filename': 'filename',
                'X-Paste-Language': 'language',
                'X-Paste-TTL': 'ttl',
                'X-Paste-Burn': '1 to enable',
              },
            },
            responses: {
              '201': '{ id, url, raw_url, download_url, expires_at, burn }',
              '400': 'empty or malformed body',
              '413': `paste exceeds ${config.maxPasteBytes} bytes`,
              '429': 'rate limit exceeded',
            },
            routes: {
              'GET /{id}': 'view a paste',
              'GET /raw/{id}': 'the body as text/plain',
              'GET /dl/{id}': 'download as an attachment',
              'GET /recent': 'recent public pastes',
              'GET /healthz': 'status',
            },
            limits: { max_paste_bytes: config.maxPasteBytes },
          };

          if (String(req.headers.accept || '').includes('application/json')) {
            return sendJson(req, res, 200, docs);
          }
          const nonce = newNonce();
          return sendHtml(req, res, 200, views.apiPage({ nonce, user, docs }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);
        const tier = tierFor(user);
        enforce(createLimiters[tier], req);
        const body = await readBody(req, tierLimits(tier).maxPasteBytes + 8192);
        const paste = buildPaste(parseCreateRequest(req, body), tier, user);
        const created = store.create(paste);
        const origin = config.publicOrigin;
        return sendJson(
          req,
          res,
          201,
          {
            id: created.id,
            url: `${origin}/${created.id}`,
            raw_url: `${origin}/raw/${created.id}`,
            download_url: `${origin}/dl/${created.id}`,
            expires_at: created.expiresAt ? new Date(created.expiresAt).toISOString() : null,
            burn: Boolean(paste.burn),
            visibility: paste.visibility,
          },
          { Location: `${origin}/${created.id}`, 'Set-Cookie': sessionCookie(created.id, secrets, created.editToken, true, { withDelete: !user }) },
        );
      }

      if (pathname === '/admin') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD', 'OPTIONS']);
        }
        const { session, user: admin } = requireAdmin(store, req, user);
        enforce(readLimiter, req);
        const nonce = newNonce();
        const query = String(req.query.q || '').slice(0, 64);
        return sendHtml(req, res, 200, views.adminPage({
          nonce,
          user: admin,
          accounts: store.listUsers({ query }),
          query,
          audit: store.recentAudit(40),
          stats: {
            users: store.userCount(),
            admins: store.adminCount(),
            pastes: store.count(),
            actions: store.auditCount(),
          },
          csrfToken: session.csrfToken,
          flash: req.query.ok ? String(req.query.ok).slice(0, 120) : null,
          error: req.query.err ? String(req.query.err).slice(0, 120) : null,
        }), { nonce });
      }

      if (pathname === '/admin/settings') {
        const { session, user: admin } = requireAdmin(store, req, user);

        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const nonce = newNonce();
          return sendHtml(req, res, 200, views.settingsPage({
            nonce,
            user: admin,
            settings: store.getSettings(),
            outstanding: legal.requiredTokens(store.getSettings()),
            csrfToken: session.csrfToken,
            flash: req.query.ok ? 'Saved.' : null,
          }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);

        enforce(adminLimiter, req);
        const raw = await readBody(req, 512 * 1024);
        const body = parseForm(raw);
        requireSession(req, session, body.csrf);

        // Only the keys the form declares are accepted, so a crafted post
        // cannot write arbitrary settings rows.
        const allowed = new Set([
          'operator_name', 'operator_country', 'privacy_contact', 'effective_date',
          'retention_pastes', 'retention_backups', 'liability_cap', 'legal_version',
          'doc_privacy', 'doc_terms', 'doc_cookies', 'doc_imprint',
        ]);
        const updates = {};
        for (const [key, value] of Object.entries(body)) {
          if (allowed.has(key)) updates[key] = value;
        }
        store.setSettings(updates);
        store.audit({
          actorId: admin.id, actorName: admin.username, action: 'admin.settings.update',
          detail: `keys=${Object.keys(updates).sort().join(',')}`, ip: clientIp(req),
        });
        return send(req, res, 303, '', { Location: '/admin/settings?ok=1' });
      }

      const adminPwMatch = /^\/admin\/users\/(\d+)\/password$/.exec(pathname);
      if (adminPwMatch) {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        const { session, user: admin } = requireAdmin(store, req, user);
        enforce(adminLimiter, req);
        const body = parseForm(await readBody(req, 8192));
        requireSession(req, session, body.csrf);
        return adminResetPassword({ req, res, store, admin, targetId: Number(adminPwMatch[1]), body, ip: clientIp(req) });
      }

      const adminDelMatch = /^\/admin\/users\/(\d+)\/delete$/.exec(pathname);
      if (adminDelMatch) {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        const { session, user: admin } = requireAdmin(store, req, user);
        enforce(adminLimiter, req);
        const body = parseForm(await readBody(req, 8192));
        requireSession(req, session, body.csrf);
        return adminDeleteUser({ req, res, store, admin, targetId: Number(adminDelMatch[1]), body, ip: clientIp(req) });
      }

      if (pathname === '/recent') {
        enforce(readLimiter, req);
        const nonce = newNonce();
        const limit = Number(req.query.limit) || config.recentLimit;
        return sendHtml(req, res, 200, views.recentPage({ nonce, user, rows: store.recent(limit) }), { nonce });
      }

      /* ------------------------------------------------------------ accounts */

      if (pathname === '/signup') {
        const { user: signedIn } = identify(req);
        if (signedIn) return send(req, res, 303, '', { Location: '/account' });

        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const nonce = newNonce();
          const captchaFields = captcha.fields();
          return sendHtml(req, res, 200, views.signupPage({
            nonce,
            csrfToken: preSessionToken(),
            captchaScript: captchaFields.script,
            captchaWidget: captchaFields.html,
          }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);

        if (!config.registrationOpen) {
          throw new HttpError(403, 'Registration is closed');
        }

        const ip = enforce(signupLimiter, req);
        if (!auth.originIsSameSite(req, config.publicOrigin)) {
          throw new HttpError(403, auth.originMismatch(req, config.publicOrigin));
        }

        const body = parseForm(await readBody(req, 8192));
        if (!secrets.verifyPre(body.csrf)) {
          throw new HttpError(403, 'That form expired. Reload the page and try again.');
        }

        const renderError = (message, values) => {
          const nonce = newNonce();
          // A fresh challenge on every re-render, so a failed attempt is not
          // stuck retrying a spent one.
          const captchaFields = captcha.fields();
          return sendHtml(req, res, 400, views.signupPage({
            nonce,
            error: message,
            values,
            csrfToken: preSessionToken(),
            captchaScript: captchaFields.script,
            captchaWidget: captchaFields.html,
          }), { nonce });
        };

        // The captcha runs before the username is looked at, so a bot cannot
        // use the response to probe which names are taken.
        const verdict = await captcha.verify({
          form: body,
          query: req.query,
          headers: req.headers,
          remoteip: ip,
        });
        if (!verdict.ok) return renderError(verdict.reason || 'Could not verify you are human.', {});

        const username = String(body.username ?? '').trim();
        const nameProblem = auth.validateUsername(username);
        if (nameProblem) return renderError(nameProblem, { username });

        const passProblem = auth.validatePassword(body.password);
        if (passProblem) return renderError(passProblem, { username });

        if (body.password !== body.confirm) {
          return renderError('The two passwords do not match', { username });
        }

        if (store.findUserByUsername(username)) {
          // Deliberately vague: confirming which names exist would let anyone
          // enumerate accounts.
          return renderError('Could not create that account. Try a different username.', { username });
        }

        let created;
        try {
          created = store.createUser(username, auth.hash(body.password));
        } catch (err) {
          if (String(err?.message || '').includes('UNIQUE constraint failed')) {
            return renderError('Could not create that account. Try a different username.', { username });
          }
          throw err;
        }

        const session = store.createSession(created.id, config.sessionTtlMs);
        log.log(`[paste] signup user=${created.username} id=${created.id} ip=${ip}`);
        return send(req, res, 303, '', {
          Location: '/account',
          'Set-Cookie': auth.sessionCookie(session.token, config.sessionTtlMs, true),
        });
      }

      if (pathname === '/login') {
        const { user: signedIn } = identify(req);
        if (signedIn) return send(req, res, 303, '', { Location: '/account' });

        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const nonce = newNonce();
          // Only same-site relative paths are honoured, so ?next= cannot be
          // used to bounce a freshly logged-in user off to another domain.
          const next = safeNext(req.query.next);
          return sendHtml(req, res, 200, views.loginPage({ nonce, csrfToken: preSessionToken(), next }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);

        const ip = enforce(loginLimiter, req);
        if (!auth.originIsSameSite(req, config.publicOrigin)) {
          throw new HttpError(403, auth.originMismatch(req, config.publicOrigin));
        }

        const body = parseForm(await readBody(req, 8192));
        if (!secrets.verifyPre(body.csrf)) {
          throw new HttpError(403, 'That form expired. Reload the page and try again.');
        }
        if (captcha.isHoneypotFilled(body)) {
          throw new HttpError(403, 'That sign-in attempt could not be completed. This is not a password problem.');
        }

        const username = String(body.username ?? '').trim();

        // Per-account budget, so one account cannot be ground down from many IPs.
        const accountKey = `acct:${username.toLowerCase()}`;
        const accountVerdict = loginAccountLimiter.take(accountKey);
        if (!accountVerdict.allowed) {
          throw new HttpError(429, 'Too many login attempts. Wait and try again.', {
            'Retry-After': String(accountVerdict.retryAfterSec),
          });
        }

        const result = auth.authenticate(store, username, body.password);
        if (!result.ok) {
          log.log(`[paste] login failed user=${username} ip=${ip}`);
          const nonce = newNonce();
          // One message for both "no such user" and "wrong password".
          return sendHtml(req, res, 401, views.loginPage({
            nonce,
            error: 'Wrong username or password.',
            values: { username },
            csrfToken: preSessionToken(),
          }), { nonce });
        }

        loginAccountLimiter.reset(accountKey);
        const session = store.createSession(result.user.id, config.sessionTtlMs);
        log.log(`[paste] login user=${result.user.username} id=${result.user.id} ip=${ip}`);
        return send(req, res, 303, '', {
          Location: safeNext(body.next),
          'Set-Cookie': auth.sessionCookie(session.token, config.sessionTtlMs, true),
        });
      }

      if (pathname === '/logout') {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        const { session } = identify(req);
        const body = parseForm(await readBody(req, 8192));
        if (session) {
          // The body has to be read first: that is where the CSRF token lives.
          requireSession(req, session, body.csrf);
          store.destroySession(auth.readSessionCookie(req.cookies));
        }
        return send(req, res, 303, '', {
          Location: '/',
          'Set-Cookie': auth.clearSessionCookie(true),
        });
      }

      if (pathname === '/account/password') {
        const { session } = identify(req);

        if (req.method === 'GET' || req.method === 'HEAD') {
          if (!session) return send(req, res, 303, '', { Location: '/login?next=%2Faccount%2Fpassword' });
          const nonce = newNonce();
          const banner = user?.mustChangePassword
            ? '<p class="notice error" role="alert">Your password was reset by an administrator. Choose a new one to continue.</p>'
            : '';
          return sendHtml(req, res, 200, views.passwordChangePage({
            nonce,
            user,
            banner,
            csrfToken: session.csrfToken,
            forced: Boolean(user?.mustChangePassword),
          }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);

        const body = parseForm(await readBody(req, 8192));
        // Only an already-signed-in session may change a password; the login
        // form must not be able to reach here.
        requireSession(req, session, body.csrf);

        const resolved = auth.resolvePasswordChange(body.password, body.confirm);
        if (resolved.error) {
          const nonce = newNonce();
          return sendHtml(req, res, 400, views.passwordChangePage({
            nonce,
            user,
            banner: `<p class="notice error" role="alert">${escapeHtml(resolved.error)}</p>`,
            csrfToken: session.csrfToken,
            forced: Boolean(user?.mustChangePassword),
          }), { nonce });
        }

        store.updatePassword(session.userId, auth.hash(resolved.password));
        store.clearPasswordChange(session.userId);

        // Drop every existing session first, then issue the replacement. Doing
        // it the other way round would delete the session just created and log
        // the user straight back out.
        //
        // If the reset was in response to a compromise, the old sessions must
        // not survive the fix.
        store.deleteSessionsForUser(session.userId);
        const kept = store.createSession(session.userId, config.sessionTtlMs);
        store.audit({
          actorId: session.userId,
          actorName: session.username,
          action: 'account.password.changed',
          target: session.username,
        });

        return sendHtml(req, res, 303, '', {
          headers: {
            Location: '/account?ok=' + encodeURIComponent('password changed'),
            'Set-Cookie': auth.sessionCookie(kept.token, config.sessionTtlMs, true),
          },
        });
      }

      if (pathname === '/account/export') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD', 'OPTIONS']);
        }
        const { session, user: self_ } = identify(req);
        if (!session) return send(req, res, 303, '', { Location: '/login' });

        const data = store.exportUserData(session.userId);
        if (!data) throw new HttpError(404, 'Account not found');
        store.audit({
          actorId: session.userId, actorName: session.username,
          action: 'account.export', target: session.username,
        });

        return send(req, res, 200, JSON.stringify(data, null, 2), {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': contentDisposition(`${session.username}-paste-export.json`, 'attachment'),
          'Cache-Control': 'no-store',
        });
      }

      if (pathname === '/account/delete') {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        const { session } = identify(req);
        if (!session) throw new HttpError(401, 'Log in to do that');
        const body = parseForm(await readBody(req, 8192));
        requireSession(req, session, body.csrf);

        // Erasure is irreversible, so it takes the password again. This is not
        // a security control against an attacker who already has a session --
        // nothing would stop them -- it is a deliberate speed bump so a
        // mis-click or a CSRF post cannot destroy an account.
        if (!auth.authenticate(store, session.username, body.password).ok) {
          const nonce = newNonce();
          return sendHtml(req, res, 403, views.accountPage({
            nonce,
            user,
            pastes: store.listByOwner(session.userId),
            stats: {
              total: store.count(),
              accountMax: config.tiers.account.maxPasteBytes,
              anonymousMax: config.tiers.anonymous.maxPasteBytes,
            },
            csrfToken: session.csrfToken,
            error: 'That password is not correct, so nothing was deleted.',
          }), { nonce });
        }

        const result = store.deleteAccount(session.userId);
        if (!result.ok) {
          const nonce = newNonce();
          return sendHtml(req, res, 409, views.accountPage({
            nonce,
            user,
            pastes: store.listByOwner(session.userId),
            stats: {
              total: store.count(),
              accountMax: config.tiers.account.maxPasteBytes,
              anonymousMax: config.tiers.anonymous.maxPasteBytes,
            },
            csrfToken: session.csrfToken,
            error:
              result.reason === 'last_admin'
                ? 'This is the only administrator account, so it cannot be deleted.'
                : 'Could not delete that account.',
          }), { nonce });
        }

        store.audit({ actorName: session.username, action: 'account.delete', target: session.username });
        return send(req, res, 303, '', {
          Location: '/',
          'Set-Cookie': auth.clearSessionCookie(true),
        });
      }

      /* ------------------------------------------------------------ legal */

      if (pathname === '/privacy' || pathname === '/terms' || pathname === '/cookies' || pathname === '/imprint') {
        enforce(readLimiter, req);
        const nonce = newNonce();
        const settings = store.getSettings();
        return sendHtml(req, res, 200, views.legalPage({
          nonce,
          user,
          kind: pathname.slice(1),
          bodyHtml: renderMarkdown(legal.render(settings[`doc_${pathname.slice(1)}`] ?? '', settings)),
          outstanding: legal.requiredTokens(settings),
          settings,
        }), { nonce });
      }

      if (pathname === '/account') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD', 'OPTIONS']);
        }
        const { session, user: signedIn } = identify(req);
        if (!session) return send(req, res, 303, '', { Location: '/login?next=%2Faccount' });

        enforce(readLimiter, req);
        const nonce = newNonce();
        const account = store.getUser(session.userId);
        return sendHtml(req, res, 200, views.accountPage({
          nonce,
          user: { ...account, csrfToken: session.csrfToken, isAdmin: Boolean(account.is_admin) },
          pastes: store.listByOwner(session.userId),
          stats: {
            total: store.count(),
            accountMax: config.tiers.account.maxPasteBytes,
            anonymousMax: config.tiers.anonymous.maxPasteBytes,
          },
          csrfToken: session.csrfToken,
          flash: req.query.ok ? 'Saved.' : null,
        }), { nonce });
      }

      const visMatch = /^\/account\/pastes\/([^/]+)\/visibility$/.exec(pathname);
      if (visMatch) {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        const { session } = identify(req);
        const body = parseForm(await readBody(req, 8192));
        requireSession(req, session, body.csrf);
        const changed = store.setVisibility(visMatch[1], session.userId, body.visibility);
        if (!changed) throw new HttpError(404, 'No such paste of yours');
        return send(req, res, 303, '', { Location: '/account?ok=1' });
      }

      const ownerDeleteMatch = /^\/account\/pastes\/([^/]+)\/delete$/.exec(pathname);
      if (ownerDeleteMatch) {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        const { session } = identify(req);
        const body = parseForm(await readBody(req, 8192));
        requireSession(req, session, body.csrf);
        const ok = store.deleteOwned(ownerDeleteMatch[1], session.userId);
        if (!ok) throw new HttpError(404, 'No such paste of yours');
        return send(req, res, 303, '', { Location: '/account?ok=1' });
      }

      const editMatch = /^\/([^/]+)\/edit$/.exec(pathname);
      if (editMatch) {
        const { session, user: signedIn } = identify(req);
        if (!session) return send(req, res, 303, '', { Location: `/login?next=${encodeURIComponent(pathname)}` });

        const id = editMatch[1];
        if (!validId(id)) throw new HttpError(404, 'No such paste');

        if (req.method === 'GET' || req.method === 'HEAD') {
          enforce(readLimiter, req);
          const meta = store.ownedMeta(id, session.userId);
          if (!meta) throw new HttpError(404, 'No such paste of yours');
          if (meta.burn) throw new HttpError(409, 'A burn-after-read paste cannot be edited');

          const current = store.claim(id, { consume: false });
          const nonce = newNonce();
          return sendHtml(req, res, 200, views.editPastePage({
            nonce,
            user: signedIn,
            paste: meta,
            content: current?.content ?? '',
            csrfToken: session.csrfToken,
          }), { nonce });
        }

        if (req.method !== 'POST') throw methodNotAllowed(['GET', 'HEAD', 'POST', 'OPTIONS']);

        const body = parseForm(await readBody(req, config.tiers.account.maxPasteBytes + 8192));
        requireSession(req, session, body.csrf);
        const meta = store.ownedMeta(id, session.userId);
        if (!meta) throw new HttpError(404, 'No such paste of yours');

        const content = String(body.content ?? '');
        if (content.length === 0) throw new HttpError(400, 'Paste content is empty');
        if (Buffer.byteLength(content, 'utf8') > config.tiers.account.maxPasteBytes) {
          throw new HttpError(413, `Paste is larger than the ${views.formatBytes(config.tiers.account.maxPasteBytes)} limit`);
        }

        const filename = body.filename ? safeFilename(body.filename, null) : null;
        const changed = store.updateOwned(id, session.userId, {
          content,
          filename,
          language: hl.normaliseLanguage(body.language, filename),
          ttlMs: ttlFrom(body.ttl),
        });
        if (!changed) throw new HttpError(409, 'That paste can no longer be edited');

        return send(req, res, 303, '', { Location: `/${id}` });
      }

      const rawMatch = /^\/raw\/([^/]+)$/.exec(pathname);
      if (rawMatch) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD', 'OPTIONS']);
        }
        enforce(readLimiter, req);
        return servePaste({ req, res, id: rawMatch[1], asRaw: true });
      }

      const dlMatch = /^\/dl\/([^/]+)$/.exec(pathname);
      if (dlMatch) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD', 'OPTIONS']);
        }
        enforce(readLimiter, req);
        return servePaste({ req, res, id: dlMatch[1], asDownload: true });
      }

      const deleteMatch = /^\/([^/]+)\/delete$/.exec(pathname);
      if (deleteMatch) {
        if (req.method !== 'POST') throw methodNotAllowed(['POST', 'OPTIONS']);
        enforce(createLimiters[tierFor(user)], req);
        const id = deleteMatch[1];
        const peeked = store.peek(id);
        if (!peeked) throw new HttpError(404, 'No such paste, or it has expired');

        // A paste that belongs to an account is only ever deletable by that
        // account while signed in. The cookie token exists so someone can
        // remove an *anonymous* paste from the browser that made it; it is not
        // a second, weaker door into an owned one.
        if (peeked.owner_id) {
          throw new HttpError(
            403,
            'This paste belongs to an account. Sign in as that account and delete it from /account.',
          );
        }

        const body = parseForm(await readBody(req, 8192));
        const token = body.token ?? '';
        const expected = secrets.remove(id, peeked.edit_token);
        const ok =
          typeof token === 'string' &&
          token.length > 0 &&
          crypto.timingSafeEqual(
            crypto.createHash('sha256').update(token).digest(),
            crypto.createHash('sha256').update(expected).digest(),
          );

        if (!ok) throw new HttpError(403, 'That delete token is not valid for this paste');
        store.deleteWithToken(id, peeked.edit_token);

        const nonce = newNonce();
        return sendHtml(req, res, 200, views.errorPage({
          nonce,
          status: 'deleted',
          title: 'deleted',
          message: 'That paste has been deleted.',
        }), { nonce, headers: { 'Set-Cookie': `${cookieName(id)}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` } });
      }

      // POST /{id} is the password unlock. Checked before the GET handler for
      // the same shape, otherwise /{id} would answer 405 for every unlock.
      const unlockMatch = /^\/([^/]+)$/.exec(pathname);
      if (unlockMatch && req.method === 'POST') {
        enforce(createLimiters[tierFor(user)], req);
        const id = unlockMatch[1];
        if (!validId(id)) throw new HttpError(404, 'No such paste');
        const peeked = store.peek(id);
        if (!peeked) throw new HttpError(404, 'No such paste, or it has expired');

        const body = parseForm(await readBody(req, 8192));
        if (!peeked.password_hash) return send(req, res, 303, '', { Location: `/${id}` });

        if (!verifyPassword(String(body.password ?? ''), peeked.password_hash)) {
          const nonce = newNonce();
          return sendHtml(req, res, 401, views.passwordPage({
            nonce,
            id,
            error: 'That password is not correct',
            selfUrl: currentUrl(req),
          }), { nonce });
        }

        // Unlock issues only the unlock half of the cookie, so knowing a paste's
        // password never confers the right to delete it. An existing, still
        // valid delete half from this browser is carried over.
        const prior = readSession(parseCookies(req.headers.cookie), id, peeked, secrets);
        return sendHtml(req, res, 303, '', {
          headers: {
            Location: `/${id}`,
            'Set-Cookie': sessionCookie(id, secrets, peeked.edit_token, true, {
              withDelete: false,
              existingDeleteToken: prior.deleteToken,
            }),
          },
        });
      }

      const viewMatch = /^\/([^/]+)$/.exec(pathname);
      if (viewMatch) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          throw methodNotAllowed(['GET', 'HEAD', 'OPTIONS']);
        }
        enforce(readLimiter, req);
        const id = viewMatch[1];
        if (!validId(id)) throw new HttpError(404, 'No such paste');
        return servePaste({ req, res, id });
      }

      throw new HttpError(404, 'Page not found');
    } catch (err) {
      status = err instanceof HttpError ? err.status : 500;
      note = err instanceof HttpError ? err.message : 'internal error';
      if (status === 500) {
        // Message only; the underlying error may carry paths or SQL.
        log.error(`[paste] unhandled ${req.method} ${req.url}:`, err && err.stack ? err.stack : err);
      }

      // A preflight is a question, not a mistake, so answer it with 204 and
      // the Allow list the router already worked out. No CORS headers are
      // added: this API is deliberately not callable from other origins, which
      // stops a random site from spending a visitor's rate-limit budget.
      if (req.method === 'OPTIONS' && status === 405) {
        note = 'preflight';
        return send(req, res, 204, '', { Allow: err.headers?.Allow || 'GET, HEAD, OPTIONS' });
      }

      const wantsJson = String(req.headers.accept || '').includes('application/json');
      const extraHeaders = err instanceof HttpError ? err.headers : {};
      if (wantsJson) {
        sendJson(req, res, status, { error: note }, extraHeaders);
      } else {
        const nonce = newNonce();
        sendHtml(
          req,
          res,
          status,
          views.errorPage({ nonce, user, status: String(status), title: String(status), message: note }),
          { nonce, headers: extraHeaders },
        );
      }
    } finally {
      // Log what was actually sent, not the optimistic default: successful
      // creates are 201/303 and errors overwrite `status`.
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      const logged = res.statusCode || status;
      log.log(`[paste] ${req.method} ${req.url.split('?')[0]} ${logged} ${ms.toFixed(1)}ms${note ? ` (${note})` : ''}`);

      // Opportunistic expiry sweep, throttled so the common case costs a
      // timestamp comparison instead of a write on every request.
      const now = Date.now();
      if (now - lastSweep > config.sweepIntervalMs) {
        lastSweep = now;
        try {
          store.sweep(now);
        } catch (err) {
          log.error('[paste] sweep failed:', err);
        }
      }
    }
  };

  captcha.warnAtBoot(log);

  return { handler, createLimiters, readLimiter, signupLimiter, loginLimiter, adminLimiter };
}

module.exports = { createApp, ttlFrom, makeSecrets };