'use strict';

const config = require('./config');
const pow = require('./pow');

const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/**
 * Honeypot field name. It is hidden from people with CSS enabled, so only
 * automated form fillers fill it in.
 */
const HONEYPOT_FIELD = 'website';

function isHoneypotFilled(form) {
  return typeof form?.[HONEYPOT_FIELD] === 'string' && form[HONEYPOT_FIELD].trim() !== '';
}

/**
 * Verifies a captcha challenge.
 *
 * Two providers, both checked server-side:
 *
 *  - `pow` (default): the client finds a nonce such that SHA-256 of the
 *    challenge starts with N zero bits. Verified here with node:crypto, so a
 *    client that lies about having solved it gains nothing.
 *  - `turnstile`: the token is posted to Cloudflare and Cloudflare's verdict is
 *    what counts. A client-side "success" callback is meaningless.
 *
 * Underneath both sits a honeypot field, and the signup rate limit is the real
 * backstop: this is friction against automated bulk signup, not an
 * authentication control.
 *
 * @returns {Promise<{ok: boolean, reason?: string}>}
 */
async function verify({ form = {}, query = {}, headers = {}, remoteip = '' }) {
  const provider = config.captcha.provider;

  if (isHoneypotFilled(form)) {
    // Never say "honeypot" to the client; it is a hint to work around.
    return { ok: false, reason: 'Could not verify you are human. Try again.' };
  }

  if (provider === 'pow') {
    const result = pow.verify(config.serverSecret, {
      challenge: form.pow_challenge,
      sig: form.pow_sig,
      nonce: form.pow_nonce,
    });
    return result.ok
      ? { ok: true }
      : { ok: false, reason: `${result.reason}. Reload the page and try again.` };
  }

  if (provider !== 'turnstile') {
    return { ok: true };
  }

  const token =
    form['cf-turnstile-response'] ||
    query['cf-turnstile-response'] ||
    headers['cf-turnstile-response'];

  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, reason: 'Please complete the captcha.' };
  }

  try {
    const body = new URLSearchParams({ secret: config.captcha.turnstileSecret, response: token });
    if (remoteip) body.set('remoteip', remoteip);

    const response = await fetch(VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(config.captcha.timeoutMs),
    });

    if (!response.ok) {
      return { ok: false, reason: 'Captcha check failed. Try again.' };
    }

    const result = await response.json();
    if (result?.success === true) return { ok: true };

    return { ok: false, reason: 'Captcha check failed. Try again.' };
  } catch {
    // Failing closed on a network error would lock everyone out during a
    // Cloudflare outage, so the honeypot result stands and signup rate limits
    // are what actually protect the endpoint.
    return { ok: true, degraded: true };
  }
}

/** True when a real captcha is in force rather than the honeypot alone. */
function isRealCaptcha() {
  return config.captcha.provider === 'pow' || config.captcha.provider === 'turnstile';
}

/**
 * Fields to embed in the signup form for the active provider. Turnstile renders
 * its own widget; proof-of-work needs the challenge plus two hidden inputs the
 * client fills in.
 */
function formFields() {
  if (!isRealCaptcha()) return { html: '', script: '' };
  if (config.captcha.provider === 'turnstile') {
    return {
      html: `<div class="cf-turnstile" data-sitekey="${escapeAttr(config.captcha.turnstileSiteKey)}"></div>`,
      script: `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`,
    };
  }
  const issued = pow.issue(config.serverSecret, config.pow.bits);
  return {
    html: `<div class="pow" data-pow
       data-challenge="${escapeAttr(issued.challenge)}"
       data-sig="${escapeAttr(issued.sig)}"
       data-bits="${issued.bits}"
       data-budget="${config.pow.budgetMs}">
    <div class="pow-track"><div class="pow-fill" data-pow-fill></div></div>
    <p class="hint" data-pow-status>checking your browser is real&hellip;</p>
    <input type="hidden" name="pow_challenge" value="${escapeAttr(issued.challenge)}" data-pow-challenge>
    <input type="hidden" name="pow_sig" value="${escapeAttr(issued.sig)}" data-pow-sig>
    <input type="hidden" name="pow_nonce" value="" data-pow-nonce>
  </div>`,
    script: '',
  };
}

/**
 * Returns both the markup and any script tag for the active provider, issuing
 * exactly one challenge. Calling the two separately would hand the form a
 * different challenge from the one the page verifies against.
 */
function fields() {
  return formFields();
}

function escapeAttr(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function warnAtBoot(log) {
  // Logging must never be the thing that stops the service from starting.
  const warn = typeof log?.warn === 'function' ? log.warn.bind(log) : () => {};
  if (config.captcha.provider === 'pow') {
    warn(
      `[paste] proof-of-work captcha active at ${config.pow.bits} bits ` +
        `(~${Math.pow(2, config.pow.bits).toLocaleString()} hashes, about a second). ` +
        'Signups are also limited per IP and screened by a honeypot.',
    );
    return;
  }
  if (isRealCaptcha()) {
    if (!config.captcha.turnstileSiteKey) {
      warn('[paste] PASTE_CAPTCHA=turnstile but PASTE_TURNSTILE_SITE_KEY is unset; the widget will not render');
    }
    return;
  }
  warn(
    `[paste] No captcha configured: signup is protected only by a honeypot and ` +
      `${config.authRate.signup.max}/${config.authRate.signup.windowMs / 3600000}h per IP. ` +
      'Set PASTE_TURNSTILE_SECRET (and PASTE_TURNSTILE_SITE_KEY) to enable Turnstile.',
  );
}

module.exports = { verify, isRealCaptcha, fields, isHoneypotFilled, HONEYPOT_FIELD, warnAtBoot };