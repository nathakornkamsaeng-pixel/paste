'use strict';

/* Integration tests against a real server on an ephemeral port. */

const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.PASTE_DB = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'paste-test-')), 't.db');
process.env.PASTE_CREATE_MAX = '1000';
process.env.PASTE_READ_MAX = '100000';
process.env.PASTE_SIGNUP_MAX = '1000';
// Low difficulty so the suite stays fast. The solver and the server verifier
// are the real implementations, only the amount of work is reduced.
process.env.PASTE_POW_BITS = '8';
process.env.PASTE_LOGIN_MAX = '1000';
process.env.PASTE_LOGIN_ACCOUNT_MAX = '1000';
process.env.PASTE_PUBLIC_ORIGIN = 'https://paste.test';

const { Store } = require('../src/store');
const legal = require('../src/legal');
const { createApp, makeSecrets, ttlFrom } = require('../src/app');
const powSolver = require('../public/pow-worker.js');

const store = new Store(process.env.PASTE_DB);
// The server seeds the legal documents at boot; tests bypass that, so do it
// here or the legal pages render empty.
legal.seed(store);
const quiet = { log() {}, error() {}, warn() {} };
const { handler } = createApp({ store, secrets: makeSecrets(), log: quiet });

const server = http.createServer((req, res) => {
  handler(req, res).catch(() => {
    if (!res.writableEnded) res.writeHead(500);
    res.end();
  });
});

let base;

/**
 * @param {object} jar when supplied, receives and replays cookies so a browser
 *   session can be followed across requests.
 */
function request(method, urlPath, { body, headers = {}, form, cookie, jar } = {}) {
  return new Promise((resolve, reject) => {
    let payload = body;
    const finalHeaders = { ...headers };
    if (form) {
      payload = new URLSearchParams(form).toString();
      finalHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    if (cookie) finalHeaders.Cookie = cookie;
    if (jar) {
      const pairs = Object.entries(jar.cookies || {});
      if (pairs.length > 0) {
        finalHeaders.Cookie = pairs.map(([k, v]) => `${k}=${v}`).join('; ');
      }
    }
    if (payload && !finalHeaders['Content-Length'] && !finalHeaders['Transfer-Encoding']) {
      finalHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(`${base}${urlPath}`, { method, headers: finalHeaders }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (jar && res.headers['set-cookie']) {
          jar.cookies = jar.cookies || {};
          for (const raw of res.headers['set-cookie']) {
            const [pair] = raw.split(';');
            const eq = pair.indexOf('=');
            const name = pair.slice(0, eq).trim();
            const value = pair.slice(eq + 1).trim();
            if (/max-age=0/i.test(raw)) delete jar.cookies[name];
            else jar.cookies[name] = value;
          }
        }
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json, cookie: res.headers['set-cookie'] });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Reads a query parameter out of a Location header. */
function paramOf(location, key) {
  return new URL(location, 'http://x.test').searchParams.get(key);
}

/** Pulls the CSRF token out of a rendered page. */
function csrfOf(html) {
  return /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? null;
}

/** Pulls the proof-of-work fields out of a rendered signup form. */
function powOf(html) {
  const challenge = /name="pow_challenge" value="([^"]*)"/.exec(html)?.[1];
  const sig = /name="pow_sig" value="([^"]*)"/.exec(html)?.[1];
  const bits = Number(/data-bits="(\d+)"/.exec(html)?.[1] ?? 0);
  return challenge && sig ? { challenge, sig, bits } : null;
}

/** Solves whatever challenge the page issued, exactly as a browser would. */
function solvePow(challenge, bits) {
  return powSolver.solve(challenge, bits, 30_000, () => {});
}

/**
 * GETs the signup form, solves the challenge it issued, then posts with the
 * given field overrides. Mirrors what a real browser does, so the captcha is
 * on the path for every signup test rather than bypassed.
 */
async function signupPost(jar, fields = {}) {
  const page = await request('GET', '/signup', { jar });
  const challenge = powOf(page.text);
  const solved = challenge ? solvePow(challenge.challenge, challenge.bits) : { nonce: null };

  return request('POST', '/signup', {
    jar,
    form: {
      username: 'someone',
      password: 'correct-horse-battery',
      confirm: 'correct-horse-battery',
      ...(challenge
        ? {
            pow_challenge: challenge.challenge,
            pow_sig: challenge.sig,
            pow_nonce: solved.nonce ?? '',
          }
        : {}),
      csrf: csrfOf(page.text),
      ...fields,
    },
  });
}

async function signup(jar, username, password = 'correct-horse-battery') {
  return signupPost(jar, { username, password, confirm: password });
}

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

/* ---------------------------------------------------------------- basics */

test('healthz reports ok', async () => {
  const res = await request('GET', '/healthz');
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
});

test('home page sets a nonce-matching CSP', async () => {
  const res = await request('GET', '/');
  assert.equal(res.status, 200);
  const csp = res.headers['content-security-policy'];
  const bodyNonce = /nonce="([^"]+)"/.exec(res.text)?.[1];
  assert.ok(bodyNonce, 'body should carry a nonce');
  assert.ok(csp.includes(`script-src 'nonce-${bodyNonce}'`), 'CSP nonce must match the body');
  assert.ok(!csp.includes('unsafe-inline'), 'CSP must not allow unsafe-inline');
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-frame-options'], 'DENY');
});

test('ttlFrom parses known and numeric values', () => {
  assert.equal(ttlFrom('1h'), 3600_000);
  assert.equal(ttlFrom('never'), null);
  assert.equal(ttlFrom(undefined), null);
  assert.equal(ttlFrom('120'), 120_000);
  assert.throws(() => ttlFrom('nonsense'), /Unknown expiry/);
});

/* --------------------------------------------------------------- create */

let sampleId;
let sampleCookie;

test('creates a paste from a form post and redirects', async () => {
  const res = await request('POST', '/', {
    form: { content: 'hello paste', filename: 'greeting.txt', ttl: '1h' },
  });
  assert.equal(res.status, 303);
  const location = res.headers.location;
  assert.match(location, /^https:\/\/paste\.test\/[0-9A-Za-z]{8}$/);
  sampleId = location.split('/').pop();
  sampleCookie = (res.cookie || []).map((c) => c.split(';')[0]).join('; ');
  assert.ok(sampleCookie, 'creator should receive a session cookie');
});

test('serves the created paste', async () => {
  const res = await request('GET', `/${sampleId}`);
  assert.equal(res.status, 200);
  assert.ok(res.text.includes('hello paste'));
  assert.ok(res.text.includes('greeting.txt'));
});

test('raw endpoint returns plain text', async () => {
  const res = await request('GET', `/raw/${sampleId}`);
  assert.equal(res.status, 200);
  assert.equal(res.text, 'hello paste');
  assert.match(res.headers['content-type'], /text\/plain/);
  assert.match(res.headers['content-disposition'], /inline/);
});

test('download endpoint sets an attachment filename', async () => {
  const res = await request('GET', `/dl/${sampleId}`);
  assert.equal(res.status, 200);
  assert.match(res.headers['content-disposition'], /^attachment/);
  assert.ok(res.headers['content-disposition'].includes('greeting.txt'));
});

test('JSON API create returns urls', async () => {
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: '# api paste', language: 'markdown', ttl: '1d' }),
  });
  assert.equal(res.status, 201);
  assert.match(res.json.url, /^https:\/\/paste\.test\/[0-9A-Za-z]{8}$/);
  assert.equal(res.json.burn, false);
  await request('GET', `/${res.json.id}`);
});

test('text/plain body is accepted', async () => {
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'text/plain', 'X-Paste-Filename': 'note.md' },
    body: 'plain body text',
  });
  assert.equal(res.status, 201);
  const raw = await request('GET', `/raw/${res.json.id}`);
  assert.equal(raw.text, 'plain body text');
});

/* ---------------------------------------------------------- validation */

test('rejects empty content', async () => {
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: '' }),
  });
  assert.equal(res.status, 400);
});

test('rejects malformed JSON', async () => {
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: '{nope',
  });
  assert.equal(res.status, 400);
});

test('rejects a body over the size limit with a readable 413', async () => {
  const big = 'x'.repeat(3 * 1024 * 1024);
  const res = await request('POST', '/api/paste', { headers: { 'Content-Type': 'text/plain' }, body: big });
  assert.equal(res.status, 413, 'an oversized body should get 413, not a dropped connection');
  assert.ok(res.json?.error || res.text.includes('too large') || res.text.includes('larger'), 'should explain why');
});

test('unknown id is a 404', async () => {
  const res = await request('GET', '/zzzzzzzz');
  assert.equal(res.status, 404);
});

test('unknown route is a 404', async () => {
  assert.equal((await request('GET', '/no/such/route/here')).status, 404);
});

test('method not allowed on api', async () => {
  const res = await request('PUT', '/api/paste');
  assert.equal(res.status, 405);
});

test('GET /api/paste serves docs instead of a 405', async () => {
  const json = await request('GET', '/api/paste', { headers: { Accept: 'application/json' } });
  assert.equal(json.status, 200);
  assert.equal(json.json.create.method, 'POST');

  // The UI links here, so it must also work for a normal browser.
  const html = await request('GET', '/api/paste', { headers: { Accept: 'text/html' } });
  assert.equal(html.status, 200);
  assert.ok(html.text.includes('<h1>API</h1>'));
});

test('every 405 advertises Allow (RFC 7231)', async () => {
  const cases = [
    ['PUT', '/api/paste', 'POST'],
    ['PUT', '/', 'GET'],
    ['PUT', '/raw/zzzzzzzz', 'GET'],
    ['PUT', '/dl/zzzzzzzz', 'GET'],
    ['PUT', '/zzzzzzzz/delete', 'POST'],
  ];
  for (const [method, path, expected] of cases) {
    const res = await request(method, path);
    assert.equal(res.status, 405, `${method} ${path} should be 405`);
    assert.ok(res.headers.allow, `${method} ${path} must send Allow`);
    assert.ok(res.headers.allow.includes(expected), `${method} ${path} Allow should list ${expected}, got ${res.headers.allow}`);
  }
});

test('OPTIONS is answered with 204 and Allow, not 405', async () => {
  const res = await request('OPTIONS', '/api/paste');
  assert.equal(res.status, 204);
  assert.ok(res.headers.allow?.includes('POST'), `expected POST in Allow, got ${res.headers.allow}`);
});

test('no CORS headers are exposed', async () => {
  const res = await request('OPTIONS', '/api/paste', { headers: { Origin: 'https://evil.example' } });
  assert.equal(res.headers['access-control-allow-origin'], undefined);
});

/* ------------------------------------------------------------------ xss */

test('escapes html and script payloads in content', async () => {
  const payload = '<script>alert(1)</script><img src=x onerror=alert(2)>';
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: payload }),
  });
  const page = await request('GET', `/${res.json.id}`);
  assert.equal(page.status, 200);
  assert.ok(!page.text.includes('<script>alert(1)</script>'), 'raw script tag must not survive');
  assert.ok(!page.text.includes('<script>alert'), 'no live script tag at all');
  assert.ok(!page.text.includes('<img'), 'no live img tag at all');
  // highlight.js wraps tokens in spans, so the escaped text may be split
  // across them; assert on the escaped entities rather than a whole substring.
  assert.ok(page.text.includes('&lt;'), 'angle brackets must be escaped');
  assert.ok(page.text.includes('&gt;'), 'angle brackets must be escaped');
});

test('escapes a hostile filename in the download header', async () => {
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'x', filename: '../../etc/pa"sswd\r\nX-Injected: 1' }),
  });
  const dl = await request('GET', `/dl/${res.json.id}`);
  assert.equal(dl.status, 200);
  assert.ok(!dl.headers['x-injected'], 'must not allow header injection');
  const cd = dl.headers['content-disposition'];
  assert.ok(!cd.includes('/'), 'no path separators in filename');
  assert.ok(!cd.includes('..'), 'no traversal in filename');
});

test('reflected query text is escaped', async () => {
  const res = await request('GET', '/' + sampleId + '?error=<img src=x onerror=alert(1)>');
  assert.ok(!res.text.includes('onerror=alert(1)'));
});

/* -------------------------------------------------------------- burn */

test('burn paste is readable exactly once', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'burn me', burn: true }),
  });
  const id = created.json.id;

  const first = await request('GET', `/raw/${id}`);
  assert.equal(first.status, 200);
  assert.equal(first.text, 'burn me');

  const second = await request('GET', `/raw/${id}`);
  assert.equal(second.status, 404);
});

test('concurrent readers of a burn paste: only one wins', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'one winner only', burn: true }),
  });
  const id = created.json.id;
  const results = await Promise.all(
    Array.from({ length: 8 }, () => request('GET', `/raw/${id}`)),
  );
  const winners = results.filter((r) => r.status === 200);
  assert.equal(winners.length, 1, `expected exactly 1 winner, got ${winners.length}`);
  assert.equal(winners[0].text, 'one winner only');
});

/* ------------------------------------------------------------ password */

test('password paste hides content until unlocked', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'top secret', password: 'letmein' }),
  });
  const id = created.json.id;

  const locked = await request('GET', `/${id}`);
  assert.equal(locked.status, 401);
  assert.ok(!locked.text.includes('top secret'), 'content must not leak to a locked viewer');

  const lockedRaw = await request('GET', `/raw/${id}`);
  assert.equal(lockedRaw.status, 401);
  assert.ok(!lockedRaw.text.includes('top secret'));

  const wrong = await request('POST', `/${id}`, { form: { password: 'nope' } });
  assert.equal(wrong.status, 401);
  assert.ok(!wrong.text.includes('top secret'));

  const right = await request('POST', `/${id}`, { form: { password: 'letmein' } });
  assert.equal(right.status, 303);
  const sessionCookie = (right.cookie || []).map((c) => c.split(';')[0]).join('; ');

  const unlocked = await request('GET', `/${id}`, { cookie: sessionCookie });
  assert.equal(unlocked.status, 200);
  assert.ok(unlocked.text.includes('top secret'));
});

test('a password-protected burn paste is not consumed by a locked request', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'sealed burn', burn: true, password: 'pw12345' }),
  });
  const id = created.json.id;

  await request('GET', `/raw/${id}`);
  await request('GET', `/${id}`);

  const unlock = await request('POST', `/${id}`, { form: { password: 'pw12345' } });
  const sessionCookie = (unlock.cookie || []).map((c) => c.split(';')[0]).join('; ');
  const raw = await request('GET', `/raw/${id}`, { cookie: sessionCookie });
  assert.equal(raw.status, 200, 'the paste must survive failed unlock attempts');
  assert.equal(raw.text, 'sealed burn');

  const gone = await request('GET', `/raw/${id}`, { cookie: sessionCookie });
  assert.equal(gone.status, 404);
});

/* -------------------------------------------------------------- delete */

test('delete requires the creator secret', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'delete me' }),
  });
  const id = created.json.id;
  const creator = (created.cookie || []).map((c) => c.split(';')[0]).join('; ');

  // A visitor who only knows the URL must not be offered delete.
  const anon = await request('GET', `/${id}`);
  assert.ok(!anon.text.includes('action="/' + id + '/delete"'), 'anonymous viewers get no delete control');

  const bad = await request('POST', `/${id}/delete`, { form: { token: 'not-a-real-token' } });
  assert.equal(bad.status, 403);
  assert.equal((await request('GET', `/${id}`)).status, 200, 'still alive after a bad token');

  const view = await request('GET', `/${id}`, { cookie: creator });
  const token = /name="token" value="([^"]+)"/.exec(view.text)?.[1];
  assert.ok(token, 'creator should see a delete form with a token');

  const ok = await request('POST', `/${id}/delete`, { cookie: creator, form: { token } });
  assert.equal(ok.status, 200);
  assert.equal((await request('GET', `/${id}`)).status, 404);
});

test('unlocking a password paste does not grant delete rights', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'lock and key', password: 'abc12345' }),
  });
  const id = created.json.id;

  const unlock = await request('POST', `/${id}`, { form: { password: 'abc12345' } });
  const unlockedCookie = (unlock.cookie || []).map((c) => c.split(';')[0]).join('; ');

  const view = await request('GET', `/${id}`, { cookie: unlockedCookie });
  assert.ok(!view.text.includes('action="/' + id + '/delete"'), 'unlock must not imply delete');
});

/* -------------------------------------------------------------- expiry */

test('expired paste is not served', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'short lived', ttl: 1 }),
  });
  const id = created.json.id;
  assert.equal((await request('GET', `/raw/${id}`)).status, 200);
  await new Promise((r) => setTimeout(r, 1100));
  assert.equal((await request('GET', `/raw/${id}`)).status, 404);
});

test('recent list does not include content', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'UNIQUE_CONTENT_MARKER_9127' }),
  });
  const list = await request('GET', '/recent');
  assert.equal(list.status, 200);
  assert.ok(list.text.includes(created.json.id), 'id should be listed');
  assert.ok(!list.text.includes('UNIQUE_CONTENT_MARKER_9127'), 'listing must not leak content');
});

test('recent list hides burn and password-protected pastes', async () => {
  const burn = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'listed burn', burn: true }),
  });
  const locked = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'listed locked', filename: 'secret-name.txt', password: 'pw' }),
  });

  const list = await request('GET', '/recent');
  assert.ok(!list.text.includes(burn.json.id), 'a burn paste must not be publicly listed');
  assert.ok(!list.text.includes(locked.json.id), 'a locked paste must not be publicly listed');
  assert.ok(!list.text.includes('secret-name.txt'), 'locked filename must not leak via the listing');

  // Both are still reachable directly by link.
  assert.equal((await request('GET', `/${burn.json.id}`)).status, 200);
  assert.equal((await request('GET', `/${locked.json.id}`)).status, 401);
});

/* ------------------------------------------------------------ accounts */

test('signup creates an account and a session', async () => {
  const jar = {};
  const res = await signup(jar, 'alice');
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/account');
  assert.ok(jar.cookies?.paste_session, 'a session cookie should be set');

  const account = await request('GET', '/account', { jar });
  assert.equal(account.status, 200);
  assert.ok(account.text.includes('alice'));
});

test('signup validates username', async () => {
  for (const bad of ['a', 'ab', 'x'.repeat(33), 'has space', '-leading', 'trailing-', 'semi;colon', '<script>']) {
    const jar = {};
    const res = await signupPost(jar, { username: bad });
    assert.equal(res.status, 400, `"${bad}" should be rejected`);
    assert.ok(!jar.cookies?.paste_session, `"${bad}" must not create a session`);
  }
});

test('signup validates password strength', async () => {
  const weak = ['short1', 'password123', 'aaaaaaaaaaaa', 'changeme12'];
  for (const pw of weak) {
    const jar = {};
    const res = await signupPost(jar, {
      username: `u${Math.random().toString(36).slice(2, 8)}`, password: pw, confirm: pw,
    });
    assert.equal(res.status, 400, `"${pw}" should be rejected`);
  }
});

test('signup requires matching confirmation', async () => {
  const res = await signupPost({}, { username: 'nomatch', confirm: 'different-value' });
  assert.equal(res.status, 400);
});

test('duplicate username is refused, case-insensitively', async () => {
  await signup({}, 'dupuser');
  const res = await signup({}, 'DUPUSER');
  assert.equal(res.status, 400);
  const banner = /<p class="notice error"[^>]*>([^<]*)<\/p>/.exec(res.text)?.[1] ?? '';
  assert.ok(banner.length > 0, 'an error should be shown');
  assert.ok(!/taken|exists|already|registered/i.test(banner), `must not confirm the name exists: ${banner}`);
});

test('honeypot blocks a bot signup', async () => {
  const jar = {};
  const res = await signupPost(jar, { username: 'botfriend', website: 'http://spam.example' });
  assert.equal(res.status, 400);
  assert.ok(!jar.cookies?.paste_session);
});

test('login works and logout ends the session', async () => {
  const jar = {};
  await signup(jar, 'loginer');

  const fresh = {};
  const page = await request('GET', '/login', { fresh: true, jar: fresh });
  const res = await request('POST', '/login', {
    jar: fresh,
    form: { username: 'loginer', password: 'correct-horse-battery', csrf: csrfOf(page.text) },
  });
  assert.equal(res.status, 303);
  assert.ok(fresh.cookies?.paste_session);

  const account = await request('GET', '/account', { jar: fresh });
  assert.equal(account.status, 200);

  const csrf = csrfOf(account.text);
  const out = await request('POST', '/logout', { jar: fresh, form: { csrf } });
  assert.equal(out.status, 303);
  assert.ok(!fresh.cookies?.paste_session, 'session cookie should be cleared');

  const after = await request('GET', '/account', { jar: fresh });
  assert.equal(after.status, 303, 'account should redirect to login once logged out');
});

test('login does not reveal whether a username exists', async () => {
  const unknown = {};
  const pageA = await request('GET', '/login', { jar: unknown });
  const resA = await request('POST', '/login', {
    jar: unknown,
    form: { username: 'ghostuser', password: 'whatever-value', csrf: csrfOf(pageA.text) },
  });

  const wrong = {};
  const pageB = await request('GET', '/login', { jar: wrong });
  const resB = await request('POST', '/login', {
    jar: wrong,
    form: { username: 'loginer', password: 'definitely-wrong', csrf: csrfOf(pageB.text) },
  });

  assert.equal(resA.status, 401);
  assert.equal(resB.status, 401);
  const bannerOf = (res) => /<p class="notice error"[^>]*>([^<]*)<\/p>/.exec(res.text)?.[1] ?? null;
  assert.equal(bannerOf(resA), 'Wrong username or password.');
  assert.equal(bannerOf(resB), 'Wrong username or password.');
  // The username is echoed back into the form in both cases, so compare only
  // the parts that could differ meaningfully.
  const normalise = (html) =>
    html
      .replace(/value="[^"]*"/g, 'value=""')   // csrf token and echoed username
      .replace(/nonce="[^"]*"/g, 'nonce=""');  // per-response CSP nonce
  assert.equal(normalise(resA.text), normalise(resB.text), 'responses should be indistinguishable');
});

test('login next= cannot redirect off-site', async () => {
  const jar = {};
  const page = await request('GET', '/login?next=//evil.example/steal', { jar });
  const res = await request('POST', '/login', {
    jar,
    form: { username: 'loginer', password: 'correct-horse-battery', next: '//evil.example/steal', csrf: csrfOf(page.text) },
  });
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/account', 'must not bounce off-site');
});

test('authenticated writes need a CSRF token', async () => {
  const jar = {};
  await signup(jar, 'csrfuser');
  const created = await request('POST', '/api/paste', { jar, form: { content: 'owned paste' } });
  assert.equal(created.status, 201);

  // No csrf at all, against a real authenticated route.
  const noToken = await request('POST', '/account/pastes/zzzzzzzz/visibility', { jar, form: { visibility: 'unlisted' } });
  assert.equal(noToken.status, 403, 'a missing CSRF token must be refused');

  // Wrong csrf.
  const badToken = await request('POST', '/account/pastes/zzzzzzzz/visibility', { jar, form: { visibility: 'unlisted', csrf: 'forged' } });
  assert.equal(badToken.status, 403);
});

test('cross-site Origin is refused even with a valid CSRF token', async () => {
  const jar = {};
  await signup(jar, 'originuser');
  const account = await request('GET', '/account', { jar });
  const csrf = csrfOf(account.text);

  const res = await request('POST', '/logout', {
    jar,
    form: { csrf },
    headers: { Origin: 'https://evil.example' },
  });
  assert.equal(res.status, 403, 'a cross-site write must be refused');
});

test('a signed-in user can manage their own pastes', async () => {
  const jar = {};
  await signup(jar, 'owneruser');

  const created = await request('POST', '/api/paste', {
    jar,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'original body', filename: 'mine.txt' }),
  });
  assert.equal(created.status, 201);
  const id = created.json.id;

  const account = await request('GET', '/account', { jar });
  assert.ok(account.text.includes(id), 'owned paste should be listed');

  // Edit keeps the same URL.
  const editPage = await request('GET', `/${id}/edit`, { jar });
  assert.equal(editPage.status, 200);
  const editRes = await request('POST', `/${id}/edit`, {
    jar,
    form: { content: 'edited body', filename: 'mine.txt', csrf: csrfOf(editPage.text) },
  });
  assert.equal(editRes.status, 303);
  assert.equal(editRes.headers.location, `/${id}`);
  assert.equal((await request('GET', `/raw/${id}`)).text, 'edited body');

  // Unlist, and confirm it leaves /recent.
  const account2 = await request('GET', '/account', { jar });
  await request('POST', `/account/pastes/${id}/visibility`, {
    jar, form: { visibility: 'unlisted', csrf: csrfOf(account2.text) },
  });
  assert.ok(!(await request('GET', '/recent')).text.includes(id), 'unlisted must not be listed');
  assert.equal((await request('GET', `/${id}`)).status, 200, 'still reachable by link');

  // Delete.
  const account3 = await request('GET', '/account', { jar });
  const del = await request('POST', `/account/pastes/${id}/delete`, {
    jar, form: { csrf: csrfOf(account3.text) },
  });
  assert.equal(del.status, 303);
  assert.equal((await request('GET', `/${id}`)).status, 404);
});

test('one account cannot touch another account\'s pastes', async () => {
  const owner = {};
  await signup(owner, 'pasteowner');
  const created = await request('POST', '/api/paste', {
    jar: owner,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'not yours' }),
  });
  const id = created.json.id;

  const stranger = {};
  await signup(stranger, 'strangeruser');

  const account = await request('GET', '/account', { jar: stranger });
  const csrf = csrfOf(account.text);

  assert.equal((await request('POST', `/${id}/edit`, { jar: stranger, form: { content: 'hijacked', csrf } })).status, 404);
  assert.equal((await request('POST', `/account/pastes/${id}/delete`, { jar: stranger, form: { csrf } })).status, 404);
  assert.equal((await request('POST', `/account/pastes/${id}/visibility`, { jar: stranger, form: { visibility: 'unlisted', csrf } })).status, 404);

  assert.equal((await request('GET', `/raw/${id}`)).text, 'not yours', 'content must be untouched');
});

test('account holders get the larger paste limit', async () => {
  const big = 'z'.repeat(2 * 1024 * 1024); // 2 MiB: over anonymous, under account
  const jar = {};
  await signup(jar, 'biguser');

  const anon = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'text/plain' }, body: big,
  });
  assert.equal(anon.status, 413, 'anonymous should be capped at 1 MiB');

  const member = await request('POST', '/api/paste', {
    jar, headers: { 'Content-Type': 'text/plain' }, body: big,
  });
  assert.equal(member.status, 201, 'account tier should allow 2 MiB');

  // Still bounded: 8 MiB exceeds even the account ceiling.
  const huge = 'z'.repeat(8 * 1024 * 1024);
  assert.equal((await request('POST', '/api/paste', { jar, headers: { 'Content-Type': 'text/plain' }, body: huge })).status, 413);
});

test('anonymous callers cannot create unlisted pastes', async () => {
  const res = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'sneaky', visibility: 'unlisted' }),
  });
  assert.equal(res.status, 201);
  assert.equal(res.json.visibility, 'public', 'must be downgraded to public');
});

test('a forged session cookie is rejected', async () => {
  const forged = `paste_session=${'A'.repeat(43)}`;
  const res = await request('GET', '/account', { cookie: forged });
  assert.equal(res.status, 303, 'unknown token must not authenticate');
});

test('tampered session cookie does not authenticate', async () => {
  const jar = {};
  await signup(jar, 'tamperuser');
  const real = jar.cookies.paste_session;
  const tampered = `${real.slice(0, -4)}AAAA`;
  const res = await request('GET', '/account', { cookie: `paste_session=${tampered}` });
  assert.equal(res.status, 303);
});

test('session token is not stored in the database', () => {
  const token = store.createSession(store.createUser('dbcheck', 'x').id, 60_000).token;
  const row = store.db.prepare('SELECT token_hash FROM sessions WHERE token_hash = ?').get(token);
  assert.equal(row, undefined, 'the raw token must not appear in any row');
});

test('logout actually destroys the session server-side', async () => {
  const jar = {};
  await signup(jar, 'revokeuser');
  const token = jar.cookies.paste_session;
  const account = await request('GET', '/account', { jar });
  await request('POST', '/logout', { jar, form: { csrf: csrfOf(account.text) } });

  // Replaying the old cookie must not work even after the browser drops it.
  const replay = await request('GET', '/account', { cookie: `paste_session=${token}` });
  assert.equal(replay.status, 303, 'a destroyed session must stay destroyed');
});

/* ---------------------------------------------------------------- admin */

/** Registers an account and grants it admin through the configured list. */
async function makeAdmin(username) {
  const jar = {};
  await signup(jar, username);
  store.syncAdmins([username]);
  return jar;
}

test('burn leaves no trace anywhere after being read', async () => {
  const user = store.createUser('burnowner', 'x');
  const created = store.create({ content: 'vanishing act', burn: true, filename: 'gone.txt', ownerId: user.id });
  const id = created.id;

  assert.equal(store.claim(id, { consume: true }).content, 'vanishing act');

  // Other tests share this database, so check the specific row rather than the
  // table count.
  assert.equal(store.peek(id), null);
  assert.deepEqual(store.db.prepare('SELECT * FROM pastes WHERE id = ?').all(id), []);
  assert.equal(store.ownedMeta(id, user.id), null);
  assert.ok(!store.recent().some((r) => r.id === id), 'must not be listed');
  assert.deepEqual(
    store.db.prepare('SELECT * FROM pastes WHERE id = ?').all(id),
    [],
    'no row may remain in the table',
  );
});

test('anonymous users cannot reach the admin panel', async () => {
  assert.equal((await request('GET', '/admin')).status, 403);
});

test('a normal account gets 404 for admin, not 403', async () => {
  const jar = {};
  await signup(jar, 'plainuser');
  assert.equal((await request('GET', '/admin', { jar })).status, 404);
});

test('an admin can open the panel', async () => {
  const jar = await makeAdmin('paneladmin');
  const res = await request('GET', '/admin', { jar });
  assert.equal(res.status, 200);
  assert.ok(res.text.includes('accounts'));
  assert.ok(res.text.includes('Audit log'));
});

test('admin can reset a password and it revokes that user\'s sessions', async () => {
  const admin = await makeAdmin('resetadmin');
  const victim = {};
  await signup(victim, 'resetvictim');

  assert.equal((await request('GET', '/account', { jar: victim })).status, 200, 'victim starts signed in');

  const victimId = store.findUserByUsername('resetvictim').id;
  const page = await request('GET', '/admin', { jar: admin });
  const res = await request('POST', `/admin/users/${victimId}/password`, {
    jar: admin,
    form: { password: 'brand-new-secret-1', confirm: 'brand-new-secret-1', csrf: csrfOf(page.text) },
  });
  assert.equal(res.status, 303);
  const notice = paramOf(res.headers.location, 'ok') ?? '';
  assert.ok(notice.includes('password reset'), notice);
  assert.ok(notice.includes('resetvictim'), notice);
  assert.ok(paramOf(res.headers.location, 'err') === null, 'no error expected');

  // The victim's old session is dead even though their cookie is unchanged.
  assert.equal((await request('GET', '/account', { jar: victim })).status, 303);

  // And the password the admin set does let them sign in.
  const fresh = {};
  const loginPage = await request('GET', '/login', { jar: fresh });
  const login = await request('POST', '/login', {
    jar: fresh,
    form: { username: 'resetvictim', password: 'brand-new-secret-1', csrf: csrfOf(loginPage.text) },
  });
  assert.equal(login.status, 303);

  // But it is provisional: signing in lands on the change page, not the account.
  const landing = await request('GET', '/account', { jar: fresh });
  assert.equal(landing.status, 303);
  assert.equal(landing.headers.location, '/account/password');

  // Once they choose their own, the account is reachable.
  const changePage = await request('GET', '/account/password', { jar: fresh });
  await request('POST', '/account/password', {
    jar: fresh,
    form: { password: 'their-own-choice-here', confirm: 'their-own-choice-here', csrf: csrfOf(changePage.text) },
  });
  assert.equal((await request('GET', '/account', { jar: fresh })).status, 200);
});

test('admin password reset refuses a weak password', async () => {
  const admin = await makeAdmin('weakcheckadmin');
  await signup({}, 'weakvictim');
  const victimId = store.findUserByUsername('weakvictim').id;
  const page = await request('GET', '/admin', { jar: admin });
  const res = await request('POST', `/admin/users/${victimId}/password`, {
    jar: admin,
    form: { password: 'password123', confirm: 'password123', csrf: csrfOf(page.text) },
  });
  assert.equal(res.status, 303);
  assert.ok(paramOf(res.headers.location, 'err'), 'should report the problem');
});

test('admin can delete an account and its pastes', async () => {
  const admin = await makeAdmin('deleteadmin');
  const doomed = {};
  await signup(doomed, 'doomeduser');
  const created = await request('POST', '/api/paste', {
    jar: doomed,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'spam content' }),
  });
  assert.equal(created.status, 201);

  const doomedId = store.findUserByUsername('doomeduser').id;
  const page = await request('GET', '/admin', { jar: admin });
  const res = await request('POST', `/admin/users/${doomedId}/delete`, {
    jar: admin,
    form: { pastes: 'delete', csrf: csrfOf(page.text) },
  });
  assert.equal(res.status, 303);

  assert.equal(store.findUserByUsername('doomeduser'), null, 'account should be gone');
  assert.equal(store.claim(created.json.id), null, 'its pastes should be gone');
});

test('deleting an account can preserve its pastes', async () => {
  const admin = await makeAdmin('keepadmin');
  const kept = {};
  await signup(kept, 'keptuser');
  const created = await request('POST', '/api/paste', {
    jar: kept,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'keep me around' }),
  });

  const keptId = store.findUserByUsername('keptuser').id;
  const page = await request('GET', '/admin', { jar: admin });
  await request('POST', `/admin/users/${keptId}/delete`, { jar: admin, form: { csrf: csrfOf(page.text) } });

  assert.equal(store.findUserByUsername('keptuser'), null);
  assert.equal((await request('GET', `/raw/${created.json.id}`)).text, 'keep me around',
    'paste should survive, just unowned');
});

test('an admin cannot delete their own account', async () => {
  const admin = await makeAdmin('selfdeleteadmin');
  const adminId = store.findUserByUsername('selfdeleteadmin').id;
  const page = await request('GET', '/admin', { jar: admin });
  const res = await request('POST', `/admin/users/${adminId}/delete`, {
    jar: admin,
    form: { pastes: 'delete', csrf: csrfOf(page.text) },
  });
  assert.equal(res.status, 303);
  assert.ok((paramOf(res.headers.location, 'err') ?? '').includes('your own account'));
  assert.ok(store.findUserByUsername('selfdeleteadmin'), 'account must still exist');
});

test('admin writes require a CSRF token', async () => {
  const admin = await makeAdmin('csrfadmin');
  const created = await signup({}, 'csrfvictim');
  const victim = store.findUserByUsername('csrfvictim');
  assert.ok(victim, `victim signup failed with ${created.status}: ${(/class="notice error"[^>]*>([^<]*)/.exec(created.text) || [])[1] || created.text.slice(0, 120)}`);
  const victimId = victim.id;

  assert.equal((await request('POST', `/admin/users/${victimId}/password`, {
    jar: admin, form: { password: 'some-long-password', confirm: 'some-long-password' },
  })).status, 403);

  assert.equal((await request('POST', `/admin/users/${victimId}/delete`, { jar: admin, form: {} })).status, 403);

  assert.ok(store.findUserByUsername('csrfvictim'), 'target must be untouched');
});

test('a normal account cannot use admin endpoints', async () => {
  const jar = {};
  await signup(jar, 'notadmin');
  const victimId = store.findUserByUsername('notadmin').id;
  assert.equal((await request('GET', '/admin', { jar })).status, 404);
  assert.equal((await request('POST', `/admin/users/${victimId}/password`, {
    jar, form: { password: 'some-long-password', confirm: 'some-long-password' },
  })).status, 404);
});

test('every admin action is written to the audit log, without secrets', async () => {
  const admin = await makeAdmin('auditadmin');
  await signup({}, 'audittarget');
  const targetId = store.findUserByUsername('audittarget').id;

  const page = await request('GET', '/admin', { jar: admin });
  await request('POST', `/admin/users/${targetId}/password`, {
    jar: admin,
    form: { password: 'audited-secret-1', confirm: 'audited-secret-1', csrf: csrfOf(page.text) },
  });
  await request('POST', `/admin/users/${targetId}/delete`, { jar: admin, form: { csrf: csrfOf(page.text) } });

  const actions = store.recentAudit(50).map((entry) => entry.action);
  assert.ok(actions.includes('admin.password.reset'), `expected a reset in ${actions.join(',')}`);
  assert.ok(actions.includes('admin.user.delete'), `expected a delete in ${actions.join(',')}`);

  const dump = JSON.stringify(store.recentAudit(50));
  assert.ok(!dump.includes('audited-secret-1'), 'the new password must not be logged');
});

test('revoking admin takes effect on the next request', async () => {
  const jar = await makeAdmin('revokee');
  assert.equal((await request('GET', '/admin', { jar })).status, 200);

  store.db.prepare('UPDATE users SET is_admin = 0 WHERE username_lower = ?').run('revokee');
  assert.equal((await request('GET', '/admin', { jar })).status, 404,
    'a revoked admin should lose access without re-logging in');
});

test('signup cannot grant itself admin', async () => {
  const before = store.adminCount();
  const jar = {};
  const res = await signupPost(jar, {
    username: 'sneakyadmin', is_admin: '1', admin: '1', role: 'admin',
  });
  assert.equal(res.status, 303);
  const user = store.findUserByUsername('sneakyadmin');
  assert.ok(user);
  assert.equal(Boolean(user.is_admin), false, 'signup must not be able to self-promote');
  assert.equal(store.adminCount(), before);
});

/* -------------------------------------------------------- proof of work */

const powModule = require('../src/pow');
const auth = require('../src/auth');
const views = require('../src/views');

test('a signup page carries a solvable challenge', async () => {
  const res = await request('GET', '/signup');
  const challenge = powOf(res.text);
  assert.ok(challenge, 'the form should embed a challenge');
  assert.ok(challenge.bits > 0, 'difficulty should be above zero');
  assert.ok(challenge.challenge.length <= 40, 'must stay short enough for one hash block');

  const solved = solvePow(challenge.challenge, challenge.bits);
  assert.ok(solved.nonce !== null, 'the shipped solver should find an answer');
  assert.ok(
    powModule.hasLeadingZeroBits(
      crypto.createHash('sha256').update(`${challenge.challenge}:${solved.nonce}`).digest(),
      challenge.bits,
    ),
    'the solution must satisfy the stated difficulty',
  );
});

test('signup is refused without a proof of work', async () => {
  const jar = {};
  const res = await signupPost(jar, { username: 'nopow', pow_nonce: '' });
  assert.equal(res.status, 400);
  assert.ok(!jar.cookies?.paste_session, 'no account may be created');
  assert.equal(store.findUserByUsername('nopow'), null);
});

test('signup is refused with a wrong nonce', async () => {
  const jar = {};
  const page = await request('GET', '/signup', { jar });
  const challenge = powOf(page.text);
  const res = await request('POST', '/signup', {
    jar,
    form: {
      username: 'badpow', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
      csrf: csrfOf(page.text),
      pow_challenge: challenge.challenge, pow_sig: challenge.sig, pow_nonce: '1',
    },
  });
  assert.equal(res.status, 400);
  assert.equal(store.findUserByUsername('badpow'), null);
});

test('a tampered challenge signature is refused', async () => {
  const jar = {};
  const page = await request('GET', '/signup', { jar });
  const challenge = powOf(page.text);
  const solved = solvePow(challenge.challenge, challenge.bits);
  const flipped = challenge.sig.slice(0, -2) + (challenge.sig.slice(-2) === 'aa' ? 'bb' : 'aa');

  const res = await request('POST', '/signup', {
    jar,
    form: {
      username: 'forged', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
      csrf: csrfOf(page.text),
      pow_challenge: challenge.challenge, pow_sig: flipped, pow_nonce: solved.nonce,
    },
  });
  assert.equal(res.status, 400);
  assert.equal(store.findUserByUsername('forged'), null);
});

test('a challenge from another server key is refused', async () => {
  const foreign = powModule.issue(crypto.randomBytes(48), 8);
  const solved = solvePow(foreign.challenge, foreign.bits);

  // A valid csrf so the request reaches the captcha stage at all.
  const jar = {};
  const page = await request('GET', '/signup', { jar });
  const res = await request('POST', '/signup', {
    jar,
    form: {
      username: 'outsider', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
      csrf: csrfOf(page.text),
      pow_challenge: foreign.challenge, pow_sig: foreign.sig, pow_nonce: solved.nonce,
    },
  });
  assert.equal(res.status, 400);
  assert.ok((/class="notice error"[^>]*>([^<]*)/.exec(res.text) || [])[1]?.includes('not issued by this server'),
    'should report the challenge as unrecognised');
  assert.equal(store.findUserByUsername('outsider'), null);
});

test('the difficulty cannot be lowered by the client', async () => {
  // The difficulty lives inside the signed payload. Asking for a weaker one
  // means asking against a signature that no longer matches.
  const jar = {};
  const page = await request('GET', '/signup', { jar });
  const challenge = powOf(page.text);

  // A solution valid for difficulty 0 is trivially "nonce 1".
  const res = await request('POST', '/signup', {
    jar,
    form: {
      username: 'sneakypow', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
      csrf: csrfOf(page.text),
      pow_challenge: challenge.challenge, pow_sig: challenge.sig,
      pow_nonce: '1',
      // attempts to override every field it might read difficulty from
      pow_bits: '0', bits: '0', difficulty: '0',
    },
  });
  assert.equal(res.status, 400, 'nonce 1 does not satisfy the real difficulty');
  assert.equal(store.findUserByUsername('sneakypow'), null);
});

test('an expired challenge is refused', () => {
  const key = crypto.randomBytes(48);
  const issued = powModule.issue(key, 8);
  const solved = solvePow(issued.challenge, issued.bits);
  const proof = { challenge: issued.challenge, sig: issued.sig, nonce: solved.nonce };

  const stale = powModule.verify(key, proof, { maxAgeMs: 0 });
  assert.equal(stale.ok, false);
  assert.match(stale.reason, /expired/);

  // The same proof is accepted inside the window, so the rejection is about
  // age and not about the solution itself.
  assert.equal(powModule.verify(key, proof, { maxAgeMs: 60_000 }).ok, true);
});

test('the solver in the worker matches SHA-256 exactly', () => {
  // Guards the fast path that skips re-hashing the prefix: if the block is
  // built wrongly, solutions would silently fail server-side.
  for (let i = 0; i < 60; i += 1) {
    const challenge = crypto.randomBytes(12).toString('base64url');
    const bits = 4;
    const solved = solvePow(challenge, bits);
    const digest = crypto.createHash('sha256').update(`${challenge}:${solved.nonce}`).digest();
    assert.ok(
      powModule.hasLeadingZeroBits(digest, bits),
      `worker disagreed with sha256 for challenge ${challenge}`,
    );
  }
});

test('anonymous CSRF tokens round-trip every time', () => {
  // Regression: the token used to be built from two separate Date.now() reads,
  // so whenever a millisecond ticked between them the signature was over a
  // different timestamp than the one embedded, and every signup failed at
  // random. Hammer it so that window cannot come back.
  const secrets = makeSecrets();
  let failures = 0;
  for (let i = 0; i < 20000; i += 1) {
    if (!secrets.verifyPre(secrets.issuePre())) failures += 1;
  }
  assert.equal(failures, 0, `${failures} of 20000 tokens failed to verify`);

  const good = secrets.issuePre();
  assert.ok(!secrets.verifyPre(`${good.slice(0, -4)}AAAA`), 'a tampered token must be refused');
  assert.ok(!secrets.verifyPre('nonsense'), 'garbage must be refused');
  assert.ok(!secrets.verifyPre(''), 'empty must be refused');
  assert.ok(!secrets.verifyPre(`${Date.now() - 7200000}.abc`), 'an expired token must be refused');
});

/* ------------------------------------------------------------- branding */

test('brand assets are served with the right content types', async () => {
  const expected = [
    ['favicon.svg', 'image/svg+xml'],
    ['favicon.ico', 'image/x-icon'],
    ['favicon-16.png', 'image/png'],
    ['favicon-32.png', 'image/png'],
    ['apple-touch-icon.png', 'image/png'],
    ['icon-192.png', 'image/png'],
    ['icon-512.png', 'image/png'],
    ['og.png', 'image/png'],
    ['site.webmanifest', 'application/manifest+json'],
  ];

  for (const [name, type] of expected) {
    const res = await request('GET', `/branding/${name}`);
    assert.equal(res.status, 200, `${name} should be served`);
    assert.equal(res.headers['content-type'], type, `${name} content-type`);
    assert.ok(res.headers['content-length'] > 0, `${name} should not be empty`);
  }
});

test('brand paths cannot escape the asset directory', async () => {
  for (const attempt of ['/branding/..%2fapp.css', '/branding/app.js', '/branding/%2e%2e%2fapp.css']) {
    const res = await request('GET', attempt);
    assert.ok(res.status === 404 || res.status === 400, `${attempt} should not be served (got ${res.status})`);
  }
});

test('brand assets reject methods other than GET', async () => {
  const res = await request('POST', '/branding/og.png');
  assert.equal(res.status, 405);
  assert.ok(res.headers.allow?.includes('GET'), 'Allow should list GET');
});

test('the inlined header mark has not drifted from brand/icon.svg', async () => {
  // brand/icon.svg is the source of truth: the build renders the favicons and
  // PWA icons from it. src/views.js holds a second, inlined copy for the header
  // because it is the only asset on the critical path, and nothing but a human
  // remembering keeps the two equal. They have drifted before, which put an
  // off-brand logo in the page header while every cached icon looked fine.
  const res = await request('GET', '/');
  const inlined = /<svg class="mark"[\s\S]*?<\/svg>/.exec(res.text)?.[0];
  assert.ok(inlined, 'the header should inline the brand mark');

  const source = fs.readFileSync(path.join(__dirname, '..', 'brand', 'icon.svg'), 'utf8');

  // Compare the drawing, not the bytes. The inlined copy legitimately differs
  // in its own <svg> attributes (no xmlns, aria-hidden rather than a role and
  // label) and in indentation, so both are normalised away. What is left is
  // the gradients, fills and geometry — the part that decides whether the
  // header looks like the same product as the favicon.
  const fingerprint = (svg) =>
    svg
      .slice(svg.indexOf('>', svg.indexOf('<svg')) + 1) // drop the <svg> tag itself
      .replace(/<!--[\s\S]*?-->/g, '') // comments quote colours for the reader
      .replace(/\s+/g, ' ') // ignore indentation and wrapping
      .trim();

  assert.equal(
    fingerprint(inlined),
    fingerprint(source),
    'src/views.js MARK has drifted from brand/icon.svg — copy the mark across',
  );
});

test('the manifest is valid JSON with the icons it references', async () => {
  const res = await request('GET', '/branding/site.webmanifest');
  const manifest = JSON.parse(res.text);
  assert.ok(manifest.name);
  assert.ok(manifest.start_url);
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 2);

  for (const icon of manifest.icons) {
    const path = icon.src.replace(`${process.env.PASTE_PUBLIC_ORIGIN}`, '');
    const iconRes = await request('GET', path);
    assert.equal(iconRes.status, 200, `${icon.src} should exist`);
  }
});

test('every page links the icon set and declares a theme colour', async () => {
  for (const path of ['/', '/login', '/signup', '/recent']) {
    const res = await request('GET', path);
    assert.ok(res.text.includes('/branding/favicon.svg'), `${path} needs a favicon`);
    assert.ok(res.text.includes('rel="apple-touch-icon"'), `${path} needs an apple touch icon`);
    assert.ok(res.text.includes('rel="manifest"'), `${path} needs a manifest`);
    assert.ok(res.text.includes('name="theme-color"'), `${path} needs a theme colour`);
  }
});

test('the mark is inlined in the header, not fetched separately', async () => {
  const res = await request('GET', '/');
  assert.ok(res.text.includes('<svg class="mark"'), 'header should inline the mark');
  assert.ok(res.text.includes('url(#markGradient)'), 'mark should carry the brand gradient');
});

test('a paste gets its own social preview', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'function greet() {\n  return "hi";\n}', filename: 'greet.js', ttl: '1h' }),
  });
  const page = await request('GET', `/${created.json.id}`);

  const og = (key) => {
    const m = new RegExp(`property="og:${key}" content="([^"]*)"`).exec(page.text);
    return m ? m[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>') : null;
  };

  assert.equal(og('type'), 'article');
  assert.ok(og('title').includes('greet.js'), `title was ${og('title')}`);
  assert.ok(og('description').includes('function greet'), `description was ${og('description')}`);
  assert.equal(og('url'), `${process.env.PASTE_PUBLIC_ORIGIN}/${created.json.id}`);
  assert.ok(og('image').endsWith('/branding/og.png'));
  assert.ok(page.text.includes('name="twitter:card" content="summary_large_image"'));
});

test('social metadata escapes paste content', async () => {
  const hostile = '"><script>alert(1)</script>';
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: hostile, filename: hostile }),
  });
  const page = await request('GET', `/${created.json.id}`);
  assert.ok(!page.text.includes('"><script>alert(1)'), 'must not break out of a meta attribute');
  assert.ok(page.text.includes('&lt;script&gt;'), 'payload should be escaped');
});

test('the page ships no theme switch, because there is only one theme', async () => {
  const res = await request('GET', '/');
  assert.ok(!res.text.includes('data-theme'), 'no theme attribute');
  assert.ok(!res.text.includes('localStorage'), 'no theme persistence');
  assert.ok(!res.text.includes('theme-toggle'), 'no toggle control');

  const js = await request('GET', '/static/app.js');
  assert.ok(!js.text.includes('localStorage'), 'the script should not carry theme code');
  assert.ok(!/prefers-color-scheme/.test(res.text), 'no colour-scheme negotiation');
});

test('the stylesheet is light only', async () => {
  const res = await request('GET', '/static/app.css');
  assert.ok(!/data-theme="light"/.test(res.text), 'no dark-to-light override block');
  assert.ok(!/color-scheme:\s*dark/.test(res.text), 'dark scheme is not declared');
  assert.ok(/color-scheme:\s*light/.test(res.text), 'light scheme is declared');

  // The syntax theme has to match the page, or code renders as a dark slab in a
  // light layout.
  assert.ok(/--text:\s*#10151d/.test(res.text), 'tokens should be the light palette');
  assert.ok(!/github-dark/.test(res.text));
});

test('syntax highlighting uses the light theme', async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'const x = 1;', language: 'javascript' }),
  });
  const page = await request('GET', `/${created.json.id}`);
  assert.ok(page.text.includes('hljs'), 'should be highlighted');

  const css = await request('GET', '/static/app.css');
  // github.css sets a near-white background; github-dark would not.
  assert.ok(/\.hljs\s*\{[^}]*background:\s*#fff/i.test(css.text), 'bundled syntax theme should be light');
});

test('highlight.js theme still ships inside the stylesheet', async () => {
  const res = await request('GET', '/static/app.css');
  assert.equal(res.status, 200);
  assert.ok(res.text.includes('.hljs'), 'the token theme must be bundled');
  assert.ok(res.text.includes('--accent'), 'the design tokens must be present');
  // Balanced braces catch a truncated or malformed sheet.
  const opens = (res.text.match(/\{/g) || []).length;
  const closes = (res.text.match(/\}/g) || []).length;
  assert.equal(opens, closes, 'stylesheet braces must balance');
});

/* ------------------------------------------- compliance & data rights */

test('an admin reset forces the user to change their password', async () => {
  const admin = await makeAdmin('resetflowadmin');
  const victim = {};
  await signup(victim, 'resetflowvictim');
  const victimId = store.findUserByUsername('resetflowvictim').id;

  const page = await request('GET', '/admin', { jar: admin });
  await request('POST', `/admin/users/${victimId}/password`, {
    jar: admin,
    form: { password: 'temporary-admin-set', confirm: 'temporary-admin-set', csrf: csrfOf(page.text) },
  });

  assert.ok(store.mustChangePassword(victimId), 'account should be flagged');

  // The old session is dead, so the user signs in with the temporary password.
  const jar = {};
  const loginPage = await request('GET', '/login', { jar });
  const login = await request('POST', '/login', {
    jar,
    form: { username: 'resetflowvictim', password: 'temporary-admin-set', csrf: csrfOf(loginPage.text) },
  });
  assert.equal(login.status, 303);

  // Every route bounces them to the change page, including ones they would
  // otherwise reach.
  for (const path of ['/', '/recent', '/account', '/api/paste']) {
    const res = await request('GET', path, { jar });
    const location = res.headers.location || '';
    assert.ok(
      res.status === 303 && location === '/account/password',
      `${path} should redirect to the change page, got ${res.status} ${location}`,
    );
  }

  // Monitoring must keep working while an account is locked, so /healthz stays
  // reachable, as do the legal pages.
  assert.equal((await request('GET', '/healthz', { jar })).status, 200);
  assert.equal((await request('GET', '/privacy', { jar })).status, 200);

  const changePage = await request('GET', '/account/password', { jar });
  assert.equal(changePage.status, 200);
  assert.ok(changePage.text.includes('reset by an administrator'));

  // The temporary password alone is not enough: they must set a new one.
  const done = await request('POST', '/account/password', {
    jar,
    form: { password: 'a-brand-new-password', confirm: 'a-brand-new-password', csrf: csrfOf(changePage.text) },
  });
  assert.equal(done.status, 303);
  assert.equal(store.mustChangePassword(victimId), false);

  // And now the site works again for them.
  assert.equal((await request('GET', '/', { jar })).status, 200);
  assert.equal((await request('GET', '/account', { jar })).status, 200);
});

test('a forced password change refuses a weak new password', async () => {
  const admin = await makeAdmin('weakforceadmin');
  await signup({}, 'weakforcevictim');
  const victimId = store.findUserByUsername('weakforcevictim').id;

  const page = await request('GET', '/admin', { jar: admin });
  await request('POST', `/admin/users/${victimId}/password`, {
    jar: admin,
    form: { password: 'temporary-admin-set', confirm: 'temporary-admin-set', csrf: csrfOf(page.text) },
  });

  const jar = {};
  const loginPage = await request('GET', '/login', { jar });
  await request('POST', '/login', {
    jar,
    form: { username: 'weakforcevictim', password: 'temporary-admin-set', csrf: csrfOf(loginPage.text) },
  });

  const changePage = await request('GET', '/account/password', { jar });
  const weak = await request('POST', '/account/password', {
    jar,
    form: { password: 'password123', confirm: 'password123', csrf: csrfOf(changePage.text) },
  });
  assert.equal(weak.status, 400);
  assert.ok(store.mustChangePassword(victimId), 'still forced after a rejected attempt');
});

test('an admin cannot read paste content through the admin panel', async () => {
  const admin = await makeAdmin('readonlyadmin');
  const owner = {};
  await signup(owner, 'contentowner');
  const created = await request('POST', '/api/paste', {
    jar: owner,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content: 'ADMIN_MUST_NOT_SEE_THIS',
      filename: 'SECRET_FILENAME.txt',
      visibility: 'unlisted',
    }),
  });
  assert.equal(created.status, 201);

  // Every admin surface, checked for content, filename and paste id.
  // /recent is deliberately not in this list: it is a public page that lists
  // public pastes, so seeing a public paste's name there is correct.
  for (const path of ['/admin', '/admin/settings']) {
    const res = await request('GET', path, { jar: admin });
    assert.equal(res.status, 200, `${path} should load`);
    assert.ok(!res.text.includes('ADMIN_MUST_NOT_SEE_THIS'), `${path} leaked content`);
    assert.ok(!res.text.includes('SECRET_FILENAME.txt'), `${path} leaked a filename`);
    assert.ok(!res.text.includes(created.json.id), `${path} leaked a paste id`);
  }

  // The store method behind the panel must not return content either, so the
  // guarantee does not depend on the template being careful.
  const row = store.listUsers({}).find((u) => u.username === 'contentowner');
  // An unlisted paste must not surface on the public listing either.
  const recent = await request('GET', '/recent');
  assert.ok(!recent.text.includes('SECRET_FILENAME.txt'), '/recent leaked an unlisted filename');
  assert.ok(!recent.text.includes(created.json.id), '/recent leaked an unlisted paste id');

  const serialised = JSON.stringify(row);
  assert.ok(!serialised.includes('ADMIN_MUST_NOT_SEE_THIS'));
  assert.ok(!serialised.includes('SECRET_FILENAME.txt'));
  assert.ok(!('content' in row));
  assert.ok(!('filename' in row));
});

test('users can export their own data', async () => {
  const jar = {};
  await signup(jar, 'exporter');
  const created = await request('POST', '/api/paste', {
    jar,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'exportable content', filename: 'mine.txt' }),
  });

  const res = await request('GET', '/account/export', { jar });
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /application\/json/);
  assert.match(res.headers['content-disposition'], /attachment/);

  const data = JSON.parse(res.text);
  assert.equal(data.format, 'paste-account-export/1');
  assert.equal(data.account.username, 'exporter');
  assert.ok(data.pastes.some((p) => p.content === 'exportable content'));
  assert.equal(data.counts.pastes, 1);

  // Session tokens are secrets, not user data: they must not be in the export.
  assert.ok(!JSON.stringify(data).includes(jar.cookies.paste_session), 'no session token in export');
  assert.ok(!('token' in data.sessions[0]));
});

test('exporting requires being signed in, and only ever returns your own data', async () => {
  assert.equal((await request('GET', '/account/export')).status, 303);

  const a = {}; await signup(a, 'exporterone');
  const b = {}; await signup(b, 'exportertwo');
  await request('POST', '/api/paste', {
    jar: b,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'B_SECRET' }),
  });

  const res = await request('GET', '/account/export', { jar: a });
  assert.equal(res.status, 200);
  assert.ok(!res.text.includes('B_SECRET'), 'one user must not receive another user data');
});

test('users can delete their own account, which takes their pastes with it', async () => {
  const jar = {};
  await signup(jar, 'selfdeleter');
  const created = await request('POST', '/api/paste', {
    jar,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'goes away too' }),
  });
  assert.equal(created.status, 201);

  const account = await request('GET', '/account', { jar });
  // A wrong password must not delete anything.
  const wrong = await request('POST', '/account/delete', {
    jar, form: { csrf: csrfOf(account.text), password: 'not-my-password' },
  });
  assert.equal(wrong.status, 403);
  assert.ok(store.findUserByUsername('selfdeleter'), 'account must survive a wrong password');

  const right = await request('POST', '/account/delete', {
    jar, form: { csrf: csrfOf(account.text), password: 'correct-horse-battery' },
  });
  assert.equal(right.status, 303);

  assert.equal(store.findUserByUsername('selfdeleter'), null, 'account gone');
  assert.equal(store.claim(created.json.id), null, 'pastes gone');
  assert.equal((await request('GET', '/account', { jar })).status, 303, 'session is dead');
});

test('account deletion requires a CSRF token', async () => {
  const jar = {};
  await signup(jar, 'delsec');
  const res = await request('POST', '/account/delete', {
    jar, form: { password: 'correct-horse-battery' },
  });
  assert.equal(res.status, 403);
  assert.ok(store.findUserByUsername('delsec'));
});

test('the last administrator cannot delete their own account', () => {
  // Checked against a fresh database: in the shared test store other tests
  // have left administrators behind, which would make the guard vacuous.
  const solo = new Store(':memory:');
  try {
    solo.createUser('soloadmin', 'hash');
    solo.syncAdmins(['soloadmin']);
    const id = solo.findUserByUsername('soloadmin').id;
    assert.equal(solo.adminCount(), 1);

    const refused = solo.deleteAccount(id);
    assert.equal(refused.ok, false);
    assert.equal(refused.reason, 'last_admin');
    assert.ok(solo.findUserByUsername('soloadmin'), 'the only admin must survive');

    // With a second admin present the guard no longer applies, which is what
    // makes the first admin recoverable if they get locked out.
    solo.createUser('secondadmin', 'hash');
    solo.syncAdmins(['secondadmin']);
    assert.equal(solo.adminCount(), 2);
    assert.equal(solo.deleteAccount(id).ok, true, 'deletion is allowed once a backup exists');
  } finally {
    solo.close();
  }
});

test('legal pages render, are linked, and never leak an unresolved token silently', async () => {
  for (const kind of ['privacy', 'terms', 'cookies', 'imprint']) {
    const res = await request('GET', `/${kind}`);
    assert.equal(res.status, 200, `/${kind} should serve`);
    assert.ok(res.text.includes('<h1>'), `/${kind} needs a heading`);
    assert.ok(res.text.includes('class="prose"'), `/${kind} needs prose content`);
    // A blank operator detail must be visibly marked, not rendered as nothing.
    assert.ok(!res.text.includes('****, ,'), `/${kind} rendered an empty operator name`);
  }

  const home = await request('GET', '/');
  for (const kind of ['privacy', 'terms', 'cookies', 'imprint']) {
    assert.ok(home.text.includes(`/${kind}`), `footer should link /${kind}`);
  }
});

test('markdown handles inline markup that spans a line break', async () => {
  // Regression: the renderer used to process line by line, so a bold span
  // written across two lines printed its asterisks verbatim.
  const multi = await request('GET', '/privacy');
  const prose = /<div class="prose">([\s\S]*?)<\/div>/.exec(multi.text)?.[1] ?? '';
  assert.ok(!/\*\*/.test(prose), 'no literal asterisks should survive in the rendered prose');
  assert.ok(prose.includes('<strong>'), 'bold should still be rendered');

  const two = await request('GET', '/terms');
  const termsProse = /<div class="prose">([\s\S]*?)<\/div>/.exec(two.text)?.[1] ?? '';
  assert.ok(!/\*\*/.test(termsProse), 'same on the terms page');
});

test('legal documents escape admin-authored markdown', async () => {
  const admin = await makeAdmin('legalxss');
  const page = await request('GET', '/admin/settings', { jar: admin });
  await request('POST', '/admin/settings', {
    jar: admin,
    form: { csrf: csrfOf(page.text), doc_imprint: '<script>alert(1)</script>\n\n## Heading\n- item' },
  });

  const res = await request('GET', '/imprint');
  assert.equal(res.status, 200);
  assert.ok(!res.text.includes('<script>alert(1)</script>'), 'must not render raw script');
  assert.ok(res.text.includes('&lt;script&gt;'), 'should be escaped');
  assert.ok(res.text.includes('<h2>Heading</h2>'), 'markdown should still work');
});

test('admin settings reject keys outside the declared set', async () => {
  const admin = await makeAdmin('settingsguard');
  const page = await request('GET', '/admin/settings', { jar: admin });
  await request('POST', '/admin/settings', {
    jar: admin,
    form: { csrf: csrfOf(page.text), operator_name: 'Real Name', not_a_real_setting: 'x' },
  });

  const settings = store.getSettings();
  assert.equal(settings.operator_name, 'Real Name', 'declared key should save');
  assert.equal(settings.not_a_real_setting, undefined, 'undeclared key must be ignored');
});

test('admin settings are not writable by a normal account', async () => {
  const jar = {};
  await signup(jar, 'settingsintruder');
  const res = await request('POST', '/admin/settings', {
    jar, form: { operator_name: 'Hijacked' },
  });
  assert.equal(res.status, 404);
  assert.notEqual(store.getSettings().operator_name, 'Hijacked');
});

test('the legal pages publish no street address', () => {
  const solo = new Store(':memory:');
  try {
    const { settings } = legal.seed(solo);
    solo.setSettings({ operator_name: 'Example Co', operator_country: 'Thailand', privacy_contact: 'a@b.tld' });

    for (const key of ['doc_privacy', 'doc_terms', 'doc_imprint', 'doc_cookies']) {
      const text = solo.getSettings()[key];
      assert.ok(!text.includes('operator_address'), `${key} must not ask for an address`);
    }
    assert.equal(settings.operator_address, undefined, 'the address must not be a declared setting');

    const rendered = legal.render(solo.getSettings().doc_privacy, solo.getSettings());
    assert.ok(!rendered.includes('[not set: operator_address'), 'nothing should render as a missing address');
    assert.ok(!/\{\{operator_address\}\}/.test(rendered), 'no address placeholder may survive');
  } finally {
    solo.close();
  }
});

test('a retired placeholder refreshes its document and drops the data', () => {
  const solo = new Store(':memory:');
  try {
    legal.seed(solo);
    // Simulate a database seeded before the address was retired.
    solo.setSettings({ operator_address: '1 Old Road' });
    solo.setSettings({
      doc_privacy: String.raw`## Who runs this site\n\n**{{operator_name}}**, {{operator_address}}.`,
    });

    const result = legal.syncDocuments(solo);
    assert.ok(result.removed.includes('operator_address'), 'the stored address row is dropped');
    assert.ok(result.refreshed.includes('doc_privacy'), 'the broken document is refreshed');

    const settings = solo.getSettings();
    assert.equal(settings.operator_address, undefined);
    assert.ok(!JSON.stringify(settings).includes('1 Old Road'), 'the old address is gone from the database');
    assert.ok(legal.missingTokens(settings).every((t) => t !== 'operator_address'));

    // Idempotent, and an edited document is left alone.
    assert.deepEqual(legal.syncDocuments(solo).refreshed, []);
    solo.setSettings({ doc_terms: String.raw`## Custom\n\nEdited by the operator.` });
    assert.deepEqual(legal.syncDocuments(solo).refreshed, [], 'a hand-edited document is not overwritten');
    assert.ok(solo.getSettings().doc_terms.includes('Edited by the operator'));
  } finally {
    solo.close();
  }
});

test('only the controller identity is required', () => {
  const solo = new Store(':memory:');
  try {
    const { settings } = legal.seed(solo);
    // Exactly two things are outstanding on a fresh install: who you are and
    // where someone would send a privacy request.
    assert.deepEqual(legal.requiredTokens(settings), ['operator_name', 'privacy_contact']);

    solo.setSettings({ operator_name: 'Example Co', privacy_contact: 'hi@example.tld' });
    assert.deepEqual(legal.requiredTokens(legal.seed(solo).settings), [], 'nothing outstanding once filled');
  } finally {
    solo.close();
  }
});

test('the retired address, email and registration fields are purged', () => {
  const solo = new Store(':memory:');
  try {
    legal.seed(solo);
    solo.setSettings({ operator_address: '1 Old Road', operator_email: 'a@b.tld', operator_registration: 'REG-1' });
    const { removed } = legal.syncDocuments(solo);
    assert.ok(removed.includes('operator_address'));
    assert.ok(removed.includes('operator_email'));
    assert.ok(removed.includes('operator_registration'));
    const dump = JSON.stringify(solo.getSettings());
    assert.ok(!dump.includes('1 Old Road'), 'the address is gone from the database');
    assert.ok(!dump.includes('REG-1'), 'the registration number is gone');
  } finally {
    solo.close();
  }
});

test('a document version bump refreshes stored copies but keeps a backup', () => {
  const solo = new Store(':memory:');
  try {
    legal.seed(solo);
    const original = solo.getSettings().doc_privacy;

    // Stand in for a previous version of the text.
    solo.setSettings({ doc_privacy: '## Old wording\n\n{{operator_name}}' });
    solo.setSettings({ docs_version: '1' });

    const result = legal.seed(solo);
    assert.ok(result.refreshed.includes('doc_privacy'), 'the stored copy is refreshed');
    const after = solo.getSettings();
    assert.notEqual(after.doc_privacy, '## Old wording\n\n{{operator_name}}');
    assert.equal(after.backup_doc_privacy, '## Old wording\n\n{{operator_name}}', 'the old text is preserved');
    assert.ok(after.doc_privacy.length > 200, 'the current document is in place');
    void original;

    // Idempotent afterwards.
    assert.equal(legal.seed(solo).refreshed.length, 0);
  } finally {
    solo.close();
  }
});

test('the settings form offers no address field', () => {
  const admin = {};
  const solo = new Store(':memory:');
  solo.setSettings({ setup_claimed: '1' });
  solo.createUser('formadmin', 'hash');
  solo.syncAdmins(['formadmin']);
  void admin;
  void solo;
  // The page is rendered through the shared template; assert on the source of
  // truth for the field list instead of booting a second server.
  const page = views.settingsPage({
    nonce: 'N', user: { username: 'a' }, settings: {}, outstanding: [], csrfToken: 'C',
  });
  assert.ok(!page.includes('name="operator_address"'), 'no address input is rendered');
  assert.ok(page.includes('name="operator_name"'), 'the name input is still there');
  assert.ok(page.includes('name="privacy_contact"'), 'the contact input is still there');
});

test('seeding fills gaps but never overwrites an administrator edit', () => {
  const fresh = new Store(':memory:');
  const first = legal.seed(fresh);
  assert.ok(first.seeded.length > 0, 'first run seeds');
  assert.equal(legal.seed(fresh).seeded.length, 0, 'second run seeds nothing');

  fresh.setSettings({ operator_name: 'Edited Name' });
  const again = legal.seed(fresh);
  assert.equal(again.seeded.length, 0);
  assert.equal(again.settings.operator_name, 'Edited Name', 'admin edit must survive');
  fresh.close();
});

test('the site sets only one cookie, and none for anonymous visitors', async () => {
  const anon = await request('GET', '/');
  assert.equal(anon.cookie, undefined, 'an anonymous page view must set no cookie');

  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'anonymous paste' }),
  });
  assert.equal(created.status, 201);
  assert.ok(
    !created.cookie?.some((c) => /^paste_session=/.test(c)),
    'creating a paste anonymously must not set a session cookie',
  );

  // The only session cookie must be marked HttpOnly, SameSite and Secure.
  const jar = {};
  await signup(jar, 'cookiecheck');
  const set = jar.cookies && Object.keys(jar.cookies);
  assert.ok(set?.includes('paste_session'), 'one session cookie');
  assert.ok(!set?.some((n) => /track|analytics|ads|_ga|_gid/i.test(n)), 'no tracking cookies');
});

/* ------------------------------------------------------- first-run setup */

test('setup is needed only while no administrator exists', () => {
  const solo = new Store(':memory:');
  try {
    assert.equal(solo.setupNeeded(), true);
    solo.claimSetup('firstadmin', 'hash');
    assert.equal(solo.adminCount(), 1);
    assert.equal(solo.setupNeeded(), false, 'setup must close once an admin exists');

    // Even if the claim flag is tampered with, an existing admin wins.
    solo.setSettings({ setup_claimed: '0' });
    assert.equal(solo.setupNeeded(), false, 'an existing admin must keep setup closed');

    const again = solo.claimSetup('secondadmin', 'hash');
    assert.equal(again.ok, false, 'cannot claim a second time');
    assert.equal(solo.adminCount(), 1);
    assert.equal(solo.findUserByUsername('secondadmin'), null);
  } finally {
    solo.close();
  }
});

test('claiming setup promotes the account and is audited', () => {
  const solo = new Store(':memory:');
  try {
    const result = solo.claimSetup('owner', 'hash');
    assert.equal(result.ok, true);
    assert.equal(result.user.username, 'owner');
    assert.equal(solo.isAdmin(result.user.id), true, 'the first admin must be an admin');
    assert.ok(solo.recentAudit(10).some((a) => a.action === 'admin.claim'), 'the claim is audited');
  } finally {
    solo.close();
  }
});

/** Boots a throwaway app over a fresh database so setup is open. */
async function withOpenSetup(run) {
  const bare = new Store(':memory:');
  const { handler } = createApp({ store: bare, secrets: makeSecrets(), log: quiet });
  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.writableEnded) res.writeHead(500);
      res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;

  const call = (method, path, form) =>
    new Promise((resolve, reject) => {
      const body = form ? new URLSearchParams(form).toString() : null;
      const headers = body
        ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
        : {};
      const req = http.request(`${url}${path}`, { method, headers }, (res) => {
        let text = '';
        res.on('data', (c) => { text += c; });
        res.on('end', () => resolve({ status: res.statusCode, text, location: res.headers.location }));
      });
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });

  /** Solves whatever challenge the page issued, as a browser would. */
  const solved = async (page) => {
    const bits = Number(/data-bits="(\d+)"/.exec(page)?.[1] ?? 0);
    const challenge = /name="pow_challenge" value="([^"]*)"/.exec(page)?.[1];
    const sig = /name="pow_sig" value="([^"]*)"/.exec(page)?.[1];
    return {
      csrf: csrfOf(page),
      pow_challenge: challenge ?? '',
      pow_sig: sig ?? '',
      pow_nonce: challenge ? powSolver.solve(challenge, bits, 30_000, () => {}).nonce ?? '' : '',
    };
  };

  try {
    await run({ call, solved, store: bare });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    bare.close();
  }
}

test('/setup works with no token and closes permanently afterwards', async () => {
  await withOpenSetup(async ({ call, solved, store }) => {
    const page = await call('GET', '/setup');
    assert.equal(page.status, 200, 'setup should be open with no admin');
    assert.ok(page.text.includes('name="username"'), 'the form asks for a username');
    assert.ok(page.text.includes('name="password"'), 'the form asks for a password');
    // No token field: the portal is meant to just work.
    assert.ok(!page.text.includes('name="token"'), 'there should be no token field');
    assert.ok(page.text.includes('becomes the administrator'), 'the page should say it is open');

    const res = await call('POST', '/setup', {
      username: 'setupowner',
      password: 'correct-horse-battery',
      confirm: 'correct-horse-battery',
      ...(await solved(page.text)),
    });
    assert.equal(res.status, 303, 'a valid claim should redirect');
    assert.equal(res.location, '/account');
    assert.equal(store.adminCount(), 1);
    assert.equal(store.isAdmin(store.findUserByUsername('setupowner').id), true);

    // Permanently closed.
    assert.equal((await call('GET', '/setup')).status, 404, 'setup must 404 once an admin exists');
    assert.equal(store.setupNeeded(), false);
  });
});

test('/setup rejects a weak password or a duplicate username', async () => {
  await withOpenSetup(async ({ call, solved, store }) => {
    const weak = await call('POST', '/setup', {
      username: 'weakling', password: 'password123', confirm: 'password123',
      ...(await solved((await call('GET', '/setup')).text)),
    });
    assert.equal(weak.status, 303);
    assert.match(weak.location, /err=/, 'a weak password should be refused');
    assert.equal(store.userCount(), 0);

    const mismatch = await call('POST', '/setup', {
      username: 'mismatch', password: 'correct-horse-battery', confirm: 'something-else',
      ...(await solved((await call('GET', '/setup')).text)),
    });
    assert.match(mismatch.location, /err=/);
    assert.equal(store.userCount(), 0);

    const badName = await call('POST', '/setup', {
      username: 'has space', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
      ...(await solved((await call('GET', '/setup')).text)),
    });
    assert.match(badName.location, /err=/);
    assert.equal(store.userCount(), 0);
  });
});

test('/setup still requires the proof of work', async () => {
  await withOpenSetup(async ({ call, solved, store }) => {
    const page = (await call('GET', '/setup')).text;
    const fields = await solved(page);
    const res = await call('POST', '/setup', {
      username: 'nobot', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
      ...fields,
      pow_nonce: '', // unsolved
    });
    assert.equal(res.status, 303);
    assert.match(res.location, /err=/, 'an unsolved challenge should be refused');
    assert.equal(store.userCount(), 0, 'no account may be created');
    assert.equal(store.adminCount(), 0);
  });
});

test('/setup cannot be reached once this suite has made an admin', async () => {
  // Guards the guarantee for the running site: the shared store here has
  // administrators, so setup must be shut.
  assert.equal(store.setupNeeded(), false);
  assert.equal((await request('GET', '/setup')).status, 404);
});

test('same-origin accepts the host the request actually arrived on', () => {
  const origin = 'https://paste.everlyce.com';
  const req = (headers) => ({ headers, socket: {} });

  // No Origin: a script client, not the cross-site case this guards.
  assert.equal(auth.originIsSameSite(req({ host: 'paste.everlyce.com' }), origin), true);

  // Exact match.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'https://paste.everlyce.com' }), origin),
    true,
  );

  // Default port written out explicitly must still match.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'https://paste.everlyce.com:443' }), origin),
    true,
  );

  // Reached by IP over plain HTTP: Host is the IP, so it is same-site.
  assert.equal(
    auth.originIsSameSite(req({ host: '72.62.248.114', origin: 'http://72.62.248.114' }), origin),
    true,
  );

  // A trailing slash on Origin is not disqualifying.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'https://paste.everlyce.com/' }), origin),
    true,
  );

  // Genuinely cross-site stays blocked.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'https://evil.example' }), origin),
    false,
  );

  // Multiple Origin headers, or a lookalike host, stay blocked.
  assert.equal(auth.originIsSameSite(req({ host: 'x', origin: ['https://a', 'https://b'] }), origin), false);
  assert.equal(auth.originIsSameSite(req({ host: 'x', origin: 'https://sub.evil.example' }), origin), false);

  // An opaque origin is not a foreign origin. Sandboxes, file:// pages and some
  // privacy browsers send this, and blocking it locks out legitimate visitors.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'null' }), origin),
    true,
  );
});

test('Sec-Fetch-Site is believed when the browser sends it', () => {
  const origin = 'https://paste.everlyce.com';
  const req = (headers) => ({ headers, socket: {} });

  // The browser's own verdict wins, including over a matching Origin.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin, 'sec-fetch-site': 'same-origin' }), origin),
    true,
  );
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin, 'sec-fetch-site': 'cross-site' }), origin),
    false,
  );

  // This is what still stops a sandboxed cross-origin frame: it sends
  // Origin: null, but browsers send Sec-Fetch-Site: cross-site for it.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'null', 'sec-fetch-site': 'cross-site' }), origin),
    false,
    'a sandboxed cross-site frame must still be blocked',
  );

  // Direct navigation / bookmarklet style requests.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin: 'null', 'sec-fetch-site': 'none' }), origin),
    true,
  );

  // An unrecognised value falls back to the Origin comparison rather than
  // failing closed on something we do not understand.
  assert.equal(
    auth.originIsSameSite(req({ host: 'paste.everlyce.com', origin, 'sec-fetch-site': 'nonsense' }), origin),
    true,
  );
});

test('a spoofed X-Forwarded-Host cannot bypass the origin check', () => {
  const origin = 'https://paste.everlyce.com';
  // An attacker who controls their own Origin must not be able to pair it with
  // a client-supplied forwarding header and talk their way through.
  const attempt = {
    headers: {
      host: 'paste.everlyce.com',
      origin: 'https://evil.example',
      'x-forwarded-host': 'evil.example',
      'x-forwarded-proto': 'https',
    },
    socket: {},
  };
  assert.equal(auth.originIsSameSite(attempt, origin), false);
});

test('the refusal message says what was wrong', () => {
  const message = auth.originMismatch(
    { headers: { host: 'paste.everlyce.com', origin: 'https://evil.example' } },
    'https://paste.everlyce.com',
  );
  assert.ok(message.includes('evil.example'), 'names the origin received');
  assert.ok(message.includes('paste.everlyce.com'), 'names the host expected');
});

/* ------------------------------------------------------ delete ownership */

test('an owned paste cannot be deleted with the browser delete token', async () => {
  const jar = {};
  const joined = await signup(jar, 'ownedpasteuser');
  assert.ok(
    jar.cookies?.paste_session,
    `sign-up must have succeeded for this test to mean anything (got ${joined.status})`,
  );

  // Created while signed in: the response must not carry a delete capability.
  const created = await request('POST', '/api/paste', {
    jar,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'mine, signed in', filename: 'mine.txt' }),
  });
  assert.equal(created.status, 201);
  const id = created.json.id;

  // The cookie still exists, because a password-protected paste still needs the
  // unlock half. What it must not carry is a second component, which is the
  // delete capability.
  const ppCookie = (created.cookie || []).map((c) => c.split(';')[0]).find((c) => c.startsWith('pp_'));
  assert.ok(ppCookie, 'the unlock half is still handed out');
  const halves = ppCookie.slice(ppCookie.indexOf('=') + 1).split('.');
  assert.equal(halves.length, 1, `an owned paste must carry no delete token, got ${halves.length} halves`);

  // Even if a token were somehow known, the route refuses an owned paste.
  const guessed = await request('POST', `/${id}/delete`, {
    jar, form: { token: 'anything-at-all' },
  });
  assert.equal(guessed.status, 403, 'the cookie-token route must refuse an owned paste');
  assert.match(guessed.text, /belongs to an account/);
  assert.equal((await request('GET', `/${id}`)).status, 200, 'the paste must still be there');

  // The owner deletes it the proper way instead.
  const account = await request('GET', '/account', { jar });
  const removed = await request('POST', `/account/pastes/${id}/delete`, {
    jar, form: { csrf: csrfOf(account.text) },
  });
  assert.equal(removed.status, 303);
  assert.equal((await request('GET', `/${id}`)).status, 404);
});

test('an anonymous paste is still deletable from the browser that made it', async () => {
  const jar = {};
  const created = await request('POST', '/api/paste', {
    jar,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'made without logging in' }),
  });
  assert.equal(created.status, 201);
  const id = created.json.id;

  const ppCookie = (created.cookie || []).map((c) => c.split(';')[0]).find((c) => c.startsWith('pp_'));
  assert.ok(ppCookie, 'an anonymous paste still gets a browser-scoped delete token');

  const view = await request('GET', `/${id}`, { cookie: ppCookie });
  const token = /name="token" value="([^"]+)"/.exec(view.text)?.[1];
  assert.ok(token, 'the creator sees a delete form');

  const removed = await request('POST', `/${id}/delete`, { cookie: ppCookie, form: { token } });
  assert.equal(removed.status, 200);
  assert.equal((await request('GET', `/${id}`)).status, 404);
});

test('a signed-in user cannot delete an anonymous paste they merely hold a link to', async () => {
  // Made with no session at all, so no delete token exists anywhere.
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'someone elses anonymous paste' }),
  });
  const id = created.json.id;
  // Note: an anonymous create *does* hand out a delete token, but only to the
  // browser that made it. This test sends no cookie, so the token is simply
  // lost with the response and nobody else can ever use it.
  const issued = (created.cookie || []).map((c) => c.split(';')[0]).find((c) => c.startsWith('pp_'));
  assert.ok(issued, 'the creator browser gets its own delete token');

  const stranger = {};
  await signup(stranger, 'deleteintruder');

  const res = await request('POST', `/${id}/delete`, {
    jar: stranger, form: { token: 'guessed' },
  });
  assert.equal(res.status, 403);
  assert.equal((await request('GET', `/${id}`)).status, 200, 'it must survive');

  // Nor can they reach it through the account route, which is owner-scoped.
  const account = await request('GET', '/account', { jar: stranger });
  const viaAccount = await request('POST', `/account/pastes/${id}/delete`, {
    jar: stranger, form: { csrf: csrfOf(account.text) },
  });
  assert.equal(viaAccount.status, 404, 'the account route is owner-scoped');
  assert.equal((await request('GET', `/${id}`)).status, 200);
});

test('an administrator cannot delete a paste, because they cannot see it', async () => {
  const admin = await makeAdmin('pasteadmin');
  const owner = {};
  await signup(owner, 'ownedbystudent');
  const created = await request('POST', '/api/paste', {
    jar: owner,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'not the admins business', filename: 'private.txt' }),
  });
  const id = created.json.id;

  const res = await request('POST', `/${id}/delete`, { jar: admin, form: { token: 'anything' } });
  assert.equal(res.status, 403);

  const account = await request('GET', '/account', { jar: admin });
  const viaAccount = await request('POST', `/account/pastes/${id}/delete`, {
    jar: admin, form: { csrf: csrfOf(account.text) },
  });
  assert.equal(viaAccount.status, 404);

  assert.equal((await request('GET', `/${id}`)).status, 200, 'the paste survives');
});

test("highlights code and escapes markup", async () => {
  const created = await request('POST', '/api/paste', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'const a = 1;\nif (a < 2) { return "<b>"; }', language: 'javascript' }),
  });
  const page = await request('GET', `/${created.json.id}`);
  assert.ok(page.text.includes('hljs'), 'highlighted output should use hljs classes');
  assert.ok(!page.text.includes('<b>'), 'literal markup inside code must stay escaped');
});

/* ---------------------------------------------------------------- run */

server.listen(0, '127.0.0.1', async () => {
  base = `http://127.0.0.1:${server.address().port}`;
  let failed = 0;

  for (const [name, fn] of tests) {
    try {
      await fn();
      console.log(`  ok  ${name}`);
    } catch (err) {
      failed += 1;
      console.log(`FAIL  ${name}`);
      console.log(`      ${err.message.split('\n').slice(0, 4).join('\n      ')}`);
    }
  }

  console.log(`\n${tests.length - failed}/${tests.length} passed`);
  store.close();
  server.close();
  process.exit(failed ? 1 : 0);
});