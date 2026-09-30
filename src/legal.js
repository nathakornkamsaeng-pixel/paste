'use strict';

/*
 * Version 1 of the legal and policy documents.
 *
 * These are seeded into the settings table on first boot and are editable from
 * /admin/settings afterwards. Everything the operator needs to fill in is
 * written as a {{token}}, which is substituted when the page is served; any
 * token still unresolved is flagged on the page so a half-finished document is
 * obvious rather than quietly published with blanks.
 *
 * Scope: Thailand's Personal Data Protection Act B.E. 2562 (2019) is the
 * primary regime, because that is where the operator is established. GDPR
 * (EU/EEA), UK GDPR and common US state laws are covered in the same document
 * because the site is open to visitors from those places.
 *
 * These drafts need a review by someone qualified in the operator's
 * jurisdiction before being relied on. They are engineering work product, not
 * legal advice.
 */

const PLACEHOLDER = '{{unset}}';

/**
 * Bump this whenever the document text below changes. Stored copies are
 * refreshed on boot when it differs from what is already saved, which is what
 * stops the source and the live pages drifting apart.
 */
const DOCS_VERSION = '2';

const SETTING_KEYS = {
  operator_name: '',
  operator_country: 'Thailand',
  privacy_contact: '',
  effective_date: '',
};

const RETENTION_DEFAULTS = {
  retention_pastes: '14',
  retention_backups: '30',
  liability_cap: 'the amount you paid us in the twelve months before the claim',
  legal_version: '1',
};

/** Retired placeholders, and the data behind them, dropped from the pages. */
const RETIRED_KEYS = ['operator_address', 'operator_email', 'operator_registration'];

/** Tokens that are nice to have but must not block: they carry defaults. */
const OPTIONAL = new Set(['effective_date', 'legal_version', 'liability_cap']);


const PRIVACY_V1 = `## Who runs this site

**{{operator_name}}**, {{operator_country}}. Privacy questions: **{{privacy_contact}}**.

A pastebin: you can save text and code and get a short link. You do not need an
account, and pastes you create are readable by anyone holding the link.

## Scope

This notice is written for the **Personal Data Protection Act B.E. 2562
(2019)** (Thailand), and deliberately covers the rest of Asia: the Personal Data
Protection Act (Singapore), the Personal Data Protection Act 2010 (Malaysia),
Law No. 27/2022 (Indonesia), the Data Privacy Act 2012 (Philippines), the
Personal Data Protection Decree (Vietnam), the APPI (Japan) and the PIPA
(Korea), because what we do is the same or stricter than any of them require.

It also addresses the core requirements of the **EU/EEA GDPR**, the **UK GDPR**
and the major **US state** laws, for the limited data this site handles. It is
not a full Article 13 GDPR notice for every processing scenario, and it is not
legal advice.

## What we collect

Deliberately very little.

**Anonymous pasting.** The paste, the filename you type if you give one, the
settings you choose, and a view counter. No account, and **no cookie at all**.

**If you sign up.** Your username, a scrypt hash of your password (never the
password), your pastes, and sign-in times.

**Server logs.** IP address, path, status and timestamp, for abuse handling and
faults. Kept for {{retention_pastes}} days.

**Nothing else.** No analytics, no advertising, no tracking pixels, no
profiling, and no special-category data. Please do not put sensitive data in a
paste.

## Why we may process it

- **Legitimate interests** — keeping the service secure, rate limiting abuse and
  diagnosing faults. We have weighed this against your interests and concluded
  it does not override them, because we collect little and discard it quickly.
- **Performance of a contract** — running an account you asked us to create.
- **Legal obligation** — the limited security records above.
- **Consent** — for optional cookies. There currently are none beyond the
  strictly necessary session cookie.

## Who we share it with

- **Cloudflare**, our network and security provider, acting as our processor.
  Some traffic is therefore handled outside Thailand.
- Our email provider, only if you ask us to contact you.
- **Nobody else.** We do not sell or share personal data for advertising.

Where data leaves Thailand, we rely on Cloudflare's own adequacy and contractual
safeguards. Contact us for details.

## How long we keep it

- **Never-expiring pastes** — until you delete them.
- **Expiring pastes** — until the expiry, then deleted automatically.
- **Burn-after-read** — deleted the moment it is read. No copy, no backup.
- **Accounts** — until you delete them.
- **Logs** — {{retention_pastes}} days; backups {{retention_backups}} days.
- **Deleted data** — gone from the live database immediately, and from backups
  within {{retention_backups}} days.

## Your rights

You can do all of these yourself from **/account**, without contacting us:

- **Export** your data as a machine-readable file.
- **Delete** your account, which also deletes your pastes.
- **Change** your password.

You can also ask us to confirm and copy what we hold (access), correct it
(rectification), object to or restrict processing based on legitimate interests
(objection / restriction), withdraw consent, receive your data in a portable
format (portability), or complain to your regulator.

We answer for free and never penalise you for asking. If an administrator
resets your password you are signed out and must choose a new one.

Regulators: the **PDPC** in Thailand; your local authority in the EU or UK; your
state attorney general in the US. We would rather you came to us first.

## Automated decisions

None that carry legal or similarly significant effect. Rate limiting is the same
fixed rule for everyone and builds no profile.

## Security

Passwords are scrypt-hashed and never stored in plain text. Session tokens are
stored only as a hash, so a copy of our database does not yield live sessions.
Traffic is HTTPS with HSTS. Administrators cannot read the content of pastes
through the administration panel. Personal data is accessible only to the
operator account.

## Breaches

We notify the **PDPC within 72 hours** of becoming aware of a breach likely to
risk your rights, and notify you directly where the risk is high. We keep a
record of every breach, including those below the threshold.

## Children

Not directed at children under 13, and we do not knowingly collect their data.

## Changes

The effective date appears at the top. Material changes are announced to
signed-in users before they take effect. Version {{legal_version}}.`;

const TERMS_V1 = `## Using this site

By using it you agree to these terms. If you do not agree, do not use it. These
terms are governed by the laws of {{operator_country}}, and
**{{operator_name}}** operates the site.

## Your account

One account per person. You are responsible for what happens under yours, so keep
the password to yourself, and tell us promptly if you think someone else has
access.

We may suspend or close an account used to break the law, attack the service or
harass others.

## What you may not post

Do not use a paste to:

- break the law or infringe someone else's rights;
- publish someone's personal data without their consent;
- distribute malware or content that is unlawful where it is hosted;
- impersonate anyone or misrepresent a paste's origin;
- get around the rate limits or the proof-of-work check.

## Your content

You keep ownership of what you post. You grant only the narrow permission needed
to host and display it: store it, serve it, and show it to whoever holds the
link.

**We remove pastes on request** from someone whose data or rights are being
infringed, and any content that breaks the rules above.

## No warranty

The service is provided as-is. We do not promise it will always be available or
that data can never be lost, so keep your own copies of anything important. A
burn-after-read paste is deleted on first read and cannot be recovered by
anyone, including us.

## Liability

To the extent the law allows, {{operator_name}} is not liable for indirect or
consequential loss arising from your use of the site, and total liability is
limited to {{liability_cap}}. Nothing here limits liability that cannot lawfully
be limited.

## Changes

The effective date at the top shows which version applies. Version
{{legal_version}}.`;

const COOKIES_V1 = `We use one cookie, and only one.

**\`paste_session\`** — set when you sign in, and needed to stay signed in. It
holds a random token; we store only a hash of it. Strictly necessary to provide
the account features you asked for, expires after 30 days, and is never used for
advertising or analytics.

**If you are not signed in, no cookie is set at all.** Creating a paste does not
need one.

### Analytics and advertising

None. No advertising cookies, no analytics cookies, no third-party trackers
anywhere on this site.

### Managing cookies

Clear or block cookies in your browser at any time. Blocking \`paste_session\`
keeps you signed out. Nothing else here depends on a cookie.

### Do Not Track

We honour Global Privacy Control and Do Not Track: we do not use them to collect
data, and we do not sell or share your data with anyone regardless.`;

const IMPRINT_V1 = `## Site operator

**{{operator_name}}**
**Country:** {{operator_country}}

**Contact:** {{privacy_contact}}

## About

paste stores text and code you paste and gives you a short link, operated by the
person above. Nothing here is owned or endorsed by the operator unless
explicitly stated; trademarks belong to their respective owners.

## Content

User submissions are not reviewed before publication. If something here
infringes your rights, contact the address above with the link and your reason
and it will be actioned.

## Availability

Provided without guarantee of availability.`;

const DOC_KEYS = {
  doc_privacy: PRIVACY_V1,
  doc_terms: TERMS_V1,
  doc_cookies: COOKIES_V1,
  doc_imprint: IMPRINT_V1,
};

function defaults() {
  return { ...SETTING_KEYS, ...RETENTION_DEFAULTS };
}

/**
 * Fills in anything that has never been set.
 *
 * Only absent keys are written, so an administrator's edits survive every
 * restart: this runs on each boot and must never clobber.
 *
 * @returns {{seeded: string[], settings: object}}
 */
function seed(store) {
  const existing = store.getSettings();
  const seeded = [];

  const wanted = { ...defaults(), ...DOC_KEYS };
  for (const [key, value] of Object.entries(wanted)) {
    if (existing[key] === undefined) {
      existing[key] = value;
      seeded.push(key);
    }
  }

  /*
   * Document refresh on a version bump.
   *
   * Legal text should not silently keep drifting from what is published, so a
   * new version replaces the stored copies. Any previous text is preserved
   * under doc_previous_* rather than destroyed, so hand-edits are recoverable.
   */
  const refreshed = [];
  if (existing.docs_version !== DOCS_VERSION) {
    for (const [key, value] of Object.entries(DOC_KEYS)) {
      if (!existing[key] || existing[key] === value) continue;
      seeded.push(`backup_${key}`, key);
      existing[`backup_${key}`] = existing[key];
      existing[key] = value;
      refreshed.push(key);
    }
    existing.docs_version = DOCS_VERSION;
    seeded.push('docs_version');
  }

  if (seeded.length > 0) {
    store.setSettings(seeded.reduce((acc, k) => ({ ...acc, [k]: existing[k] }), {}));
  }
  return { seeded, settings: existing, refreshed };
}

function syncDocuments(store) {
  const settings = store.getSettings();
  const removed = [];

  // Keys the operator no longer wants collected or published. Dropping the row
  // matters: leaving it behind would keep it listed as "outstanding" and could
  // put it back into a document if one were ever hand-edited to use it.
  for (const key of RETIRED_KEYS) {
    if (settings[key] !== undefined) {
      store.deleteSetting(key);
      removed.push(key);
    }
  }

  // A stored document is refreshed only when it references a placeholder that
  // is no longer declared, i.e. only when it is currently broken. A document an
  // administrator has edited normally has no unknown tokens, so their work is
  // left alone.
  const declared = new Set([...Object.keys(SETTING_KEYS), ...Object.keys(RETENTION_DEFAULTS)]);
  const refreshed = [];
  for (const [key, current] of Object.entries(DOC_KEYS)) {
    const stored = store.getSettings()[key];
    if (stored === undefined || stored === current) continue;
    const referencesUnknown = [...String(stored).matchAll(/\{\{([a-z0-9_]+)\}\}/g)]
      .some((m) => !declared.has(m[1]));
    if (!referencesUnknown) continue;
    store.setSettings({ [key]: current });
    refreshed.push(key);
  }
  return { refreshed, removed };
}

/**
 * Tokens still blank, but only counting the ones that matter.
 *
 * Optional values with defaults are not outstanding work, and an unset
 * effective date is cosmetic rather than a compliance gap.
 */
function requiredTokens(settings) {
  const referenced = new Set();
  for (const [key, value] of Object.entries(settings)) {
    if (!key.startsWith('doc_') || key.startsWith('backup_doc_')) continue;
    for (const m of String(value).matchAll(/\{\{([a-z0-9_]+)\}\}/g)) referenced.add(m[1]);
  }
  return [...referenced]
    .filter((name) => !OPTIONAL.has(name))
    .filter((name) => !String(settings[name] ?? '').trim())
    .sort();
}

function missingTokens(settings) {
  const referenced = new Set();
  for (const [key, value] of Object.entries(settings)) {
    if (!key.startsWith('doc_')) continue;
    for (const m of String(value).matchAll(/\{\{([a-z0-9_]+)\}\}/g)) referenced.add(m[1]);
  }
  return [...referenced]
    .filter((name) => !String(settings[name] ?? '').trim())
    .sort();
}

/**
 * Substitutes {{token}} values.
 *
 * Two distinct failure modes, both left visible on purpose:
 *
 *  - an unknown token is kept verbatim, so a typo in a document shows up rather
 *    than silently deleting a sentence;
 *  - a known token with no value renders as an explicit `[not set: name]`
 *    marker, because substituting an empty string would produce a legally
 *    meaningless sentence such as "** **, , Thailand.".
 */
function render(text, settings) {
  return String(text).replace(/\{\{([a-z0-9_]+)\}\}/g, (whole, name) => {
    const value = settings[name];
    if (value === undefined || value === null) return whole;
    const text2 = String(value);
    return text2.trim() === '' ? `[not set: ${name}]` : text2;
  });
}

module.exports = { SETTING_KEYS, RETENTION_DEFAULTS, DOC_KEYS, DOCS_VERSION, requiredTokens, seed, syncDocuments, render, PRIVACY_V1, TERMS_V1, COOKIES_V1, IMPRINT_V1, defaults, missingTokens, PLACEHOLDER };