'use strict';

const crypto = require('node:crypto');

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), interest-cohort=()',
};

class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} message
   * @param {object} headers
   * @param {string[]} [allow] methods valid for this path; RFC 7231 requires
   *   an Allow header on every 405, so it is carried here rather than left to
   *   each call site to remember.
   */
  constructor(status, message, headers = {}, allow = null) {
    super(message);
    this.status = status;
    this.headers = headers;
    this.allow = allow;
  }
}

/** Builds a 405 that advertises the methods which actually work here. */
function methodNotAllowed(allow) {
  return new HttpError(405, 'Method not allowed', { Allow: allow.join(', ') }, allow);
}

function send(req, res, status, body, headers = {}) {
  if (res.writableEnded) return;
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body ?? '', 'utf8');
  // A body that was rejected for being oversized was never fully read, so the
  // connection cannot be reused; say so rather than leaving the client to
  // discover it as a truncated stream.
  const close = req.bodyLimitExceeded ? { Connection: 'close' } : {};
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    ...close,
    'Content-Length': payload.length,
    ...headers,
  });
  if (req.method === 'HEAD') res.end();
  else res.end(payload);
}

function sendHtml(req, res, status, html, options = {}) {
  // Guard against passing raw headers here instead of { nonce, headers }. Doing
  // so used to drop Location/Set-Cookie silently, which is a nasty class of bug.
  const known = new Set(['nonce', 'headers']);
  const unknown = Object.keys(options).filter((key) => !known.has(key));
  if (unknown.length > 0) {
    throw new Error(`sendHtml options must be { nonce, headers }; unexpected: ${unknown.join(', ')}`);
  }

  const { nonce, headers = {} } = options;

  // `default-src 'none'` plus a per-response nonce means no injected markup and
  // no injected script can execute, even if escaping were to fail somewhere.
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'self'",
    "img-src 'self' data:",
    // The proof-of-work solver runs in a same-origin Worker file, so no blob:
    // exception is needed.
    "worker-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join('; ');

  send(req, res, status, html, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': csp,
    'Cache-Control': 'no-store',
    ...headers,
  });
}

function sendJson(req, res, status, value, headers = {}) {
  send(req, res, status, JSON.stringify(value, null, 2), {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
}

/**
 * Reads a request body with a hard byte ceiling.
 *
 * The limit is enforced while streaming rather than from Content-Length, so an
 * oversized or lying request is cut off instead of being buffered into memory.
 *
 * On overflow the request is *not* destroyed: doing that before the 413 has
 * been written makes the client see a connection reset instead of the error it
 * needs. Instead reading stops and the response is sent with `Connection:
 * close`, so the socket is torn down after the client has the message.
 */
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;

    const fail = (err, fatal = true) => {
      if (done) return;
      done = true;
      if (fatal) {
        req.off('data', onData);
        req.pause();
        req.bodyLimitExceeded = true;
      }
      reject(err);
    };

    function onData(chunk) {
      if (done) return;
      size += chunk.length;
      if (size > maxBytes) {
        fail(new HttpError(413, `Payload too large (limit ${maxBytes} bytes)`), false);
        return;
      }
      chunks.push(chunk);
    }

    req.on('data', onData);

    req.on('end', () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', () => fail(new HttpError(400, 'Request aborted')));
    req.on('aborted', () => fail(new HttpError(400, 'Request aborted')));
  });
}

/** Minimal `application/x-www-form-urlencoded` parser. */
function parseForm(body) {
  const out = Object.create(null);
  const params = new URLSearchParams(body);
  for (const [key, value] of params) {
    // Last value wins for repeated keys, matching browser form submission for
    // the checkbox patterns used here.
    out[key] = value;
  }
  return out;
}

function newNonce() {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * Builds a safe download filename.
 *
 * Any path separator, control character or quote is removed, so the value can
 * be interpolated into a Content-Disposition header without letting a caller
 * inject extra parameters or traverse to another path.
 */
function safeFilename(input, fallback = 'paste.txt') {
  if (typeof input !== 'string') return fallback;
  const cleaned = input
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[/\\]/g, '_')
    .replace(/["']/g, '')
    // Collapse dot runs so no ".." survives; it carries no meaning in a
    // download name and only invites questions about path traversal.
    .replace(/\.{2,}/g, '.')
    .replace(/^[.\s]+/, '')
    .trim()
    .slice(0, 128);
  return cleaned.length > 0 ? cleaned : fallback;
}

/** RFC 5987 form, so non-ASCII filenames survive the download header. */
function contentDisposition(filename, type = 'attachment') {
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `${type}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

function parseCookies(header) {
  const out = Object.create(null);
  if (typeof header !== 'string') return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[key] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

module.exports = {
  HttpError,
  methodNotAllowed,
  SECURITY_HEADERS,
  send,
  sendHtml,
  sendJson,
  readBody,
  parseForm,
  newNonce,
  safeFilename,
  contentDisposition,
  parseCookies,
};