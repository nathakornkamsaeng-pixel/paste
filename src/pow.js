'use strict';

const crypto = require('node:crypto');

/*
 * Server side of the proof-of-work captcha.
 *
 * Stateless by design: a challenge carries everything needed to verify it, so
 * no table of outstanding challenges has to be kept and nothing has to expire
 * out of a cache. The difficulty lives *inside* the signed payload, so a client
 * cannot ask for an easier one.
 *
 * Wire format, base64url of:
 *   12 bytes random
 *    4 bytes unix seconds, big endian
 *    1 byte  difficulty in leading zero bits
 * followed by ':' and the nonce that the client found.
 *
 * The signature is an HMAC over the challenge bytes. Verifying it first proves
 * the server issued this challenge and pins the fields, so the difficulty and
 * timestamp cannot be tampered with.
 */

const MAGIC = Buffer.from('pow1', 'ascii');
const RANDOM_BYTES = 12;
const TS_BYTES = 4;
const BITS_BYTE = 1;
const PAYLOAD_BYTES = RANDOM_BYTES + TS_BYTES + BITS_BYTE;

const DEFAULT_MAX_AGE_MS = 15 * 60_000;

/** Kept short: the browser packs challenge + ':' + nonce into one 64-byte block. */
function base64url(buf) {
  return buf.toString('base64url');
}

/**
 * @param {Buffer} key the server secret
 * @param {number} bits difficulty in leading zero bits
 */
function issue(key, bits) {
  const payload = Buffer.alloc(PAYLOAD_BYTES);
  crypto.randomBytes(RANDOM_BYTES).copy(payload, 0);
  payload.writeUInt32BE(Math.floor(Date.now() / 1000) >>> 0, RANDOM_BYTES);
  payload.writeUInt8(bits, RANDOM_BYTES + TS_BYTES);

  const challenge = base64url(payload);
  return { challenge, sig: sign(key, challenge), bits };
}

function sign(key, challenge) {
  return crypto.createHmac('sha256', key).update(`pow:${challenge}`).digest('base64url');
}

function parseChallenge(challenge) {
  if (typeof challenge !== 'string' || challenge.length > 64) return null;
  let payload;
  try {
    payload = Buffer.from(challenge, 'base64url');
  } catch {
    return null;
  }
  if (payload.length !== PAYLOAD_BYTES) return null;

  const bits = payload.readUInt8(RANDOM_BYTES + TS_BYTES);
  const ts = payload.readUInt32BE(RANDOM_BYTES) * 1000;
  if (bits < 8 || bits > 32) return null;
  return { bits, ts };
}

/** Counts leading zero bits, matching the client's definition exactly. */
function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function hasLeadingZeroBits(digest, bits) {
  const full = bits >> 3;
  for (let i = 0; i < full; i += 1) {
    if (digest[i] !== 0) return false;
  }
  const rem = bits & 7;
  if (rem === 0) return true;
  return (digest[full] >>> (8 - rem)) === 0;
}

/**
 * Verifies a submitted solution.
 *
 * @returns {{ok: true, bits: number} | {ok: false, reason: string}}
 */
function verify(key, { challenge, sig, nonce }, { maxAgeMs = DEFAULT_MAX_AGE_MS } = {}) {
  if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 20 || !/^[0-9]+$/.test(nonce)) {
    return { ok: false, reason: 'missing or malformed proof' };
  }
  if (typeof challenge !== 'string' || typeof sig !== 'string') {
    return { ok: false, reason: 'missing proof' };
  }

  const parsed = parseChallenge(challenge);
  if (!parsed) return { ok: false, reason: 'unreadable challenge' };

  // Signature before anything else: it proves the payload is ours, so the
  // timestamp and difficulty below can be trusted.
  const expected = sign(key, challenge);
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'challenge was not issued by this server' };
  }

  const age = Math.abs(Date.now() - parsed.ts);
  if (age > maxAgeMs) {
    return { ok: false, reason: 'challenge expired, reload the page' };
  }

  const digest = crypto.createHash('sha256').update(`${challenge}:${nonce}`, 'utf8').digest();
  if (!hasLeadingZeroBits(digest, parsed.bits)) {
    return { ok: false, reason: 'proof of work did not check out' };
  }

  return { ok: true, bits: parsed.bits };
}

module.exports = {
  issue,
  verify,
  parseChallenge,
  hasLeadingZeroBits,
  leadingZeroBits,
  sign,
  base64url,
  PAYLOAD_BYTES,
  MAGIC,
};