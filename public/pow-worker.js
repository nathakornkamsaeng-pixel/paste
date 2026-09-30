'use strict';

/*
 * Proof-of-work solver for the signup form.
 *
 * The server hands out a signed challenge; this finds a nonce such that
 * SHA-256(challenge + ':' + nonce) starts with N zero *bits*. Work is measured
 * in leading zero bits, so difficulty 20 means about a million hashes.
 *
 * It runs in a Worker so the page stays responsive and so a solve cannot be
 * faked by blocking the main thread. SHA-256 is implemented inline rather than
 * pulled from a CDN: the whole point is that verification is auditable and the
 * form works with no third-party script.
 *
 * The hot loop keeps the SHA-256 state for everything up to the nonce in
 * registers and re-runs only the final compression, so each attempt costs one
 * block hash instead of a full re-hash.
 */

(function () {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  const H0 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  const W = new Uint32Array(64);

  /**
   * In-place SHA-256 compression over one 64-byte block.
   * `state` is mutated; `block` is the padded block.
   */
  function compress(state, block, offset) {
    for (let i = 0; i < 16; i += 1) {
      const j = offset + i * 4;
      W[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3];
    }
    for (let i = 16; i < 64; i += 1) {
      const x = W[i - 15];
      const y = W[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }

    let a = state[0], b = state[1], c = state[2], d = state[3];
    let e = state[4], f = state[5], g = state[6], h = state[7];

    for (let i = 0; i < 64; i += 1) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;

      h = g; g = f; f = e;
      e = (d + t1) | 0;
      d = c; c = b; b = a;
      a = (t1 + t2) | 0;
    }

    state[0] = (state[0] + a) | 0;
    state[1] = (state[1] + b) | 0;
    state[2] = (state[2] + c) | 0;
    state[3] = (state[3] + d) | 0;
    state[4] = (state[4] + e) | 0;
    state[5] = (state[5] + f) | 0;
    state[6] = (state[6] + g) | 0;
    state[7] = (state[7] + h) | 0;
  }

  const encoder = new TextEncoder();

  /** Full SHA-256 of a byte array, returned as 32 bytes. */
  function sha256Bytes(bytes) {
    const state = H0.slice();
    const bitLen = bytes.length * 8;
    const blocks = Math.ceil((bytes.length + 9) / 64);
    const total = blocks * 64;

    const padded = new Uint8Array(total);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    // Length is a 64-bit big-endian bit count. Inputs here are far below 2^32
    // bits, so the high word is always zero.
    padded[total - 4] = (bitLen >>> 24) & 0xff;
    padded[total - 3] = (bitLen >>> 16) & 0xff;
    padded[total - 2] = (bitLen >>> 8) & 0xff;
    padded[total - 1] = bitLen & 0xff;

    for (let i = 0; i < total; i += 64) compress(state, padded, i);

    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i += 1) {
      out[i * 4] = (state[i] >>> 24) & 0xff;
      out[i * 4 + 1] = (state[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (state[i] >>> 8) & 0xff;
      out[i * 4 + 3] = state[i] & 0xff;
    }
    return out;
  }

  /** True when the digest starts with at least `bits` zero bits. */
  function meets(digest, bits) {
    const fullBytes = bits >> 3;
    for (let i = 0; i < fullBytes; i += 1) if (digest[i] !== 0) return false;
    const rem = bits & 7;
    if (rem === 0) return true;
    return (digest[fullBytes] >>> (8 - rem)) === 0;
  }

  /**
   * Searches for a nonce such that SHA-256(challenge + ':' + nonce) has `bits`
   * leading zero bits.
   *
   * The message is short enough to fit in one 64-byte block, so everything
   * before the final compression is reused across attempts: the challenge is
   * written once and only the nonce, the padding marker and the length field
   * change. That makes each attempt a single compression rather than a full
   * hash, which is worth roughly an order of magnitude in throughput.
   *
   * Reports progress so a slow device does not look like a hang, and honours a
   * time budget so it cannot spin forever.
   */
  function solve(challenge, bits, budgetMs, onProgress) {
    const prefix = encoder.encode(`${challenge}:`);
    // prefix + nonce digits + the 0x80 marker must all fit before byte 56.
    if (prefix.length > 40) throw new Error('challenge too long');

    const block = new Uint8Array(64);
    block.set(prefix);

    const state = H0.slice();
    const digest = new Uint8Array(32);
    const started = Date.now();

    let nonce = 0;
    let attempts = 0;
    // Tracks where the 0x80 marker currently sits so a stale one is cleared
    // when the nonce gains a digit.
    let markerAt = -1;

    for (;;) {
      const text = String(nonce);
      const digitsAt = prefix.length;
      const end = digitsAt + text.length;
      if (end > 55) throw new Error('nonce exhausted the block');

      // Clear the previous marker, then lay down this attempt's bytes.
      if (markerAt >= 0) block[markerAt] = 0;
      for (let i = 0; i < text.length; i += 1) {
        block[digitsAt + i] = text.charCodeAt(i);
      }
      block[end] = 0x80;
      markerAt = end;

      // SHA-256 appends the bit length as a 64-bit big-endian value across the
      // last 8 bytes of the block, right-aligned. A message this short is far
      // under 2^32 bits, so the high word is zero and the low word holds it.
      const bitLen = end * 8;
      block[56] = 0;
      block[57] = 0;
      block[58] = 0;
      block[59] = 0;
      block[60] = (bitLen >>> 24) & 0xff;
      block[61] = (bitLen >>> 16) & 0xff;
      block[62] = (bitLen >>> 8) & 0xff;
      block[63] = bitLen & 0xff;

      for (let i = 0; i < 8; i += 1) state[i] = H0[i];
      compress(state, block, 0);
      attempts += 1;

      for (let i = 0; i < 8; i += 1) {
        digest[i * 4] = (state[i] >>> 24) & 0xff;
        digest[i * 4 + 1] = (state[i] >>> 16) & 0xff;
        digest[i * 4 + 2] = (state[i] >>> 8) & 0xff;
        digest[i * 4 + 3] = state[i] & 0xff;
      }

      if (meets(digest, bits)) {
        return { nonce: text, attempts, ms: Date.now() - started };
      }

      nonce += 1;

      if ((attempts & 0x3ff) === 0) {
        const elapsed = Date.now() - started;
        if (onProgress) onProgress({ attempts, elapsed });
        if (budgetMs > 0 && elapsed > budgetMs) {
          return { nonce: null, attempts, ms: elapsed, timedOut: true };
        }
      }
    }
  }

  // Exposed for the Node test harness, which checks this implementation against
  // node:crypto rather than trusting it.
  const api = { sha256Bytes, meets, solve, compress, H0, K };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
    return;
  }

  self.onmessage = (event) => {
    const { challenge, bits, budgetMs, id } = event.data || {};
    try {
      const result = solve(challenge, bits, budgetMs, (progress) => {
        self.postMessage({ type: 'progress', id, ...progress });
      });
      self.postMessage({ type: 'done', id, ...result });
    } catch (err) {
      self.postMessage({ type: 'error', id, message: String(err && err.message ? err.message : err) });
    }
  };

  self.postMessage({ type: 'ready' });
})();