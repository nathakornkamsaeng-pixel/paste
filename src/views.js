'use strict';

const { escapeHtml } = require('./highlight');
const config = require('./config');

const EXPIRY_CHOICES = [
  ['never', 'Never'],
  ['10m', '10 minutes'],
  ['1h', '1 hour'],
  ['1d', '1 day'],
  ['1w', '1 week'],
  ['30d', '30 days'],
];

/**
 * The product name, in one place.
 *
 * Kept as a constant rather than spelled inline because it reaches the page
 * title, the Open Graph tags, the header, the manifest, the API's self-
 * description and the legal pages. When those were separate literals they
 * drifted, and a rebrand meant finding all of them by hand.
 *
 * This is the *product* name. The word "paste" on its own is still the noun
 * throughout — a paste you create, a list of your pastes, the /api/paste
 * endpoint — and must not be changed along with it.
 */
const SITE_NAME = 'Everlyce paste';

/**
 * Bumped whenever the artwork in brand/ changes.
 *
 * The favicons and PWA icons are served with a 7-day max-age and sit behind a
 * CDN, so a rebuild of the artwork is invisible at the edge until those objects
 * expire — leaving parts of the site on the old mark and parts on the new one.
 * Tagging the URLs with a version makes a brand change atomic instead: every
 * asset is a fresh object at every edge location, at once. Same approach as
 * pos.everlyce.com's BRAND_VERSION.
 */
const BRAND_VERSION = 4;

/**
 * The brand mark, inlined rather than fetched.
 *
 * It is the only asset on the critical path, and inlining means it inherits
 * the surrounding layout instead of shifting it while loading.
 *
 * Keep this byte-for-byte equivalent to brand/icon.svg. That file is the
 * source of truth and the build renders the favicons and PWA icons from it, so
 * the two drifting apart is what puts an off-brand logo in the page header.
 */
const MARK = `<svg class="mark" viewBox="0 0 512 512" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="markGradient" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#1d3a6b"/>
          <stop offset="0.55" stop-color="#24518f"/>
          <stop offset="1" stop-color="#2f7ad4"/>
        </linearGradient>
        <linearGradient id="markSheen" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="#ffffff" stop-opacity="0.18"/>
          <stop offset="0.55" stop-color="#ffffff" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <rect width="512" height="512" rx="112" fill="url(#markGradient)"/>
      <rect width="512" height="256" rx="112" fill="url(#markSheen)"/>
      <g fill="#f8f9fb">
        <rect x="128" y="96" width="80" height="320" rx="40"/>
        <rect x="128" y="96" width="256" height="80" rx="40"/>
        <rect x="128" y="336" width="256" height="80" rx="40"/>
      </g>
      <rect x="128" y="216" width="192" height="80" rx="40" fill="#a78bfa"/>
    </svg>`;

/** Summary text for a paste, for link previews and list rows. */
function excerpt(content, max = 180) {
  const flat = String(content ?? '').replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function layout({
  title,
  body,
  nonce,
  lang = 'en',
  head = '',
  user = null,
  description = `Share text and code with ${SITE_NAME}. No account needed.`,
  socialImage = true,
  ogType = 'website',
  url = null,
}) {
  const fullTitle = title === SITE_NAME ? SITE_NAME : `${title} · ${SITE_NAME}`;
  const origin = config.publicOrigin;
  // Passed in rather than derived from the request, so there is no shared
  // mutable state to get wrong when two requests render at once.
  const canonical = url ?? `${origin}/`;

  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(fullTitle)}</title>
<meta name="description" content="${escapeHtml(description)}">
<meta name="color-scheme" content="light">
<link rel="icon" href="/branding/favicon.svg?v=${BRAND_VERSION}" type="image/svg+xml">
<link rel="alternate icon" href="/branding/favicon.ico?v=${BRAND_VERSION}" sizes="48x48">
<link rel="icon" href="/branding/favicon-32.png?v=${BRAND_VERSION}" sizes="32x32" type="image/png">
<link rel="icon" href="/branding/favicon-16.png?v=${BRAND_VERSION}" sizes="16x16" type="image/png">
<link rel="apple-touch-icon" href="/branding/apple-touch-icon.png?v=${BRAND_VERSION}">
<link rel="manifest" href="/branding/site.webmanifest?v=${BRAND_VERSION}">
<meta name="theme-color" content="#ffffff">
<meta name="twitter:card" content="summary_large_image">
<meta property="og:type" content="${escapeHtml(ogType)}">
<meta property="og:site_name" content="${SITE_NAME}">
<meta property="og:title" content="${escapeHtml(fullTitle)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:url" content="${escapeHtml(canonical)}">
${socialImage ? `<meta property="og:image" content="${escapeHtml(`${origin}/branding/og.png?v=${BRAND_VERSION}`)}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${SITE_NAME}">` : ''}
<link rel="stylesheet" href="/static/app.css">${head}
</head>
<body data-max-bytes="${config.tiers.anonymous.maxPasteBytes}">
<a class="skip" href="#main">Skip to content</a>
<header class="bar">
  <a class="brand" href="/">${MARK}<span>${SITE_NAME}</span></a>
  <nav class="nav">
    <a href="/">New</a>
    <a href="/recent">Recent</a>
    ${user
      ? `<a href="/account" class="account">${escapeHtml(user.username)}</a>`
      : '<a href="/login">Log in</a>'}
  </nav>
  </header>
<main id="main">
${body}
</main>
<footer class="foot">
  <a href="/privacy">Privacy</a><span class="sep">·</span><a href="/terms">Terms</a><span class="sep">·</span><a href="/cookies">Cookies</a><span class="sep">·</span><a href="/imprint">Operator</a><span class="sep">·</span><a href="/api/paste">API</a><span class="sep">·</span><a href="/healthz">Status</a>
</footer>
<script nonce="${escapeHtml(nonce)}" src="/static/app.js" defer></script>
</body>
</html>`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function humanAge(ms) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function humanDuration(ms) {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'}`;
  return `${Math.round(hours / 24)} days`;
}

function homePage({ user = null, nonce, error = null, values = {} }) {
  const tierMax = user ? config.tiers.account.maxPasteBytes : config.tiers.anonymous.maxPasteBytes;
  const banner = error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '';
  const options = EXPIRY_CHOICES.map(
    ([value, label]) =>
      `<option value="${value}"${values.ttl === value ? ' selected' : ''}>${escapeHtml(label)}</option>`,
  ).join('');

  return layout({
    title: SITE_NAME,
    nonce,
    user,
    body: `
${banner}<h1>New paste</h1>
<form class="stack" method="post" action="/">
  <textarea class="editor" name="content" rows="18" spellcheck="false" autocapitalize="off"
            autocorrect="off" placeholder="Paste your text or code here"
            autofocus>${escapeHtml(values.content ?? '')}</textarea>
  <div class="options">
    <label>Expires
      <select name="ttl">${options}</select>
    </label>
    <label><input type="checkbox" name="burn" value="1"${values.burn ? ' checked' : ''}> Burn after read</label>
    <label><input type="checkbox" name="private" value="1"${values.private ? ' checked' : ''}> Require password</label>
    ${user ? `<label><input type="checkbox" name="visibility" value="unlisted"${values.visibility === 'unlisted' ? ' checked' : ''}> Unlisted</label>` : ''}
  </div>
  <input class="secondary" type="text" name="filename" maxlength="${config.maxFilenameLen}"
         value="${escapeHtml(values.filename ?? '')}" placeholder="Filename (optional)"
         autocomplete="off" spellcheck="false">
  <input class="secondary pw" type="password" name="password" autocomplete="new-password"
         placeholder="Password">
  <div class="actions">
    <button type="submit" class="btn">Create paste</button>
    <span class="counter" data-counter>0 B / ${formatBytes(tierMax)}</span>
  </div>
</form>
<p class="muted">${
  user
    ? `<a href="/account">Your pastes</a>`
    : `<a href="/login">Log in</a> for 4 MiB pastes and unlisted sharing`
}</p>
`,
  });
}

function pastePage({ user = null, nonce, paste, rendered, selfUrl, session }) {
  const badges = [];
  if (paste.burn) badges.push('<span class="badge warn">burn</span>');
  if (paste.password_hash) badges.push('<span class="badge">password</span>');

  const meta = [
    formatBytes(Buffer.byteLength(paste.content, 'utf8')),
    `${paste.views} view${paste.views === 1 ? '' : 's'}`,
    humanAge(Date.now() - paste.created_at),
  ];
  if (paste.language) meta.push(escapeHtml(paste.language));
  if (paste.expires_at) meta.push(`expires in ${escapeHtml(humanDuration(paste.expires_at - Date.now()))}`);

  const notice = paste.burn
    ? '<p class="notice error" role="alert">This paste was destroyed by being read.</p>'
    : '';

  const deleteSection = session?.deleteToken
    ? `
<div class="divider"></div>
<h1>Delete</h1>
<form method="post" action="/${escapeHtml(paste.id)}/delete">
  <input type="hidden" name="token" value="${escapeHtml(session.deleteToken)}">
  <button type="submit" class="btn danger small">Delete this paste</button>
</form>`
    : '';

  return layout({
    title: paste.filename || SITE_NAME,
    nonce,
    user,
    ogType: 'article',
    url: selfUrl,
    description: excerpt(paste.content) || `a paste on ${SITE_NAME}`,
    body: `
<div class="paste-bar">
  <div class="paste-title">
    <h1>${escapeHtml(paste.filename || 'Untitled paste')}</h1>
    <p class="meta">${meta.join(' &middot; ')}${badges.length ? ` ${badges.join(' ')}` : ''}</p>
  </div>
  <div class="actions">
    <button type="button" class="btn quiet small" data-copy="${escapeHtml(selfUrl)}">Copy link</button>
    <a class="btn quiet small" href="/raw/${escapeHtml(paste.id)}">Raw</a>
    <a class="btn quiet small" href="/dl/${escapeHtml(paste.id)}">Download</a>
  </div>
</div>
${notice}<div class="listing">${rendered.html}</div>
${deleteSection}
`,
  });
}

function passwordPage({ user = null, nonce, id, error = null, selfUrl }) {
  const banner = error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '';
  return layout({
    title: 'Password required',
    nonce,
    user,
    body: `
${banner}<h1>Password required</h1>
<form class="stack" method="post" action="/${escapeHtml(id)}">
  <input type="password" name="password" placeholder="Password" autocomplete="off" required>
  <div class="actions"><button type="submit" class="btn">Unlock</button></div>
</form>
<p class="muted">Unlocking this link shows the paste without asking again.</p>
`,
  });
}

function recentPage({ user = null, nonce, rows }) {
  if (rows.length === 0) {
    return layout({
      title: 'Recent',
      nonce,
      user,
      body: `<h1>Recent</h1>
<div class="blank"><strong>No public pastes yet</strong><p><a href="/">Create the first one</a></p></div>`,
    });
  }

  const items = rows
    .map((row) => {
      const badges = [];
      if (row.protected) badges.push('<span class="badge">password</span>');

      const meta = [humanAge(Date.now() - row.created_at)];
      if (row.language) meta.push(escapeHtml(row.language));
      meta.push(`${row.views} view${row.views === 1 ? '' : 's'}`);
      if (row.expires_at) meta.push(`expires in ${escapeHtml(humanDuration(row.expires_at - Date.now()))}`);

      return `<li>
  <a class="list-title" href="/${escapeHtml(row.id)}">${escapeHtml(row.filename || row.id)}</a>
  <p class="meta">${meta.join(' &middot; ')}${badges.length ? ` ${badges.join(' ')}` : ''}</p>
</li>`;
    })
    .join('\n');

  return layout({
    title: 'Recent',
    nonce,
    user,
    body: `<h1>Recent</h1>\n<ul class="list">\n${items}\n</ul>`,
  });
}

function errorPage({ user = null, nonce, status, title, message }) {
  return layout({
    title: `${status}`,
    nonce,
    user,
    body: `<h1>${escapeHtml(String(status))}</h1>
<p class="muted">${escapeHtml(message)}</p>
<p class="muted"><a href="/">Go home</a></p>`,
  });
}

function bait() {
  return `<div class="bait" aria-hidden="true">
  <label>Leave this empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label>
</div>`;
}

function signupPage({ nonce, user = null, error = null, values = {}, csrfToken = '', captchaScript = '', captchaWidget = '' }) {
  const banner = error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '';
  return layout({
    title: 'Sign up',
    nonce,
    user,
    head: captchaScript,
    body: `
${banner}<h1>Create an account</h1>
<form class="stack" method="post" action="/signup" autocomplete="off">
  <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
  ${bait()}
  <input type="text" name="username" placeholder="Username" value="${escapeHtml(values.username ?? '')}"
         autocomplete="username" autocapitalize="none" spellcheck="false" required>
  <input type="password" name="password" placeholder="Password (10 characters or more)"
         autocomplete="new-password" required>
  <input type="password" name="confirm" placeholder="Confirm password" autocomplete="new-password" required>
  ${captchaWidget}
  <div class="actions"><button type="submit" class="btn">Create account</button></div>
</form>
<p class="muted">Already have an account? <a href="/login">Log in</a></p>
`,
  });
}

function loginPage({ nonce, user = null, error = null, values = {}, next = '/', csrfToken = '' }) {
  const banner = error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '';
  return layout({
    title: 'Log in',
    nonce,
    user,
    body: `
${banner}<h1>Log in</h1>
<form class="stack" method="post" action="/login">
  <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
  <input type="hidden" name="next" value="${escapeHtml(next)}">
  ${bait()}
  <input type="text" name="username" placeholder="Username" value="${escapeHtml(values.username ?? '')}"
         autocomplete="username" autocapitalize="none" spellcheck="false" required>
  <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
  <div class="actions"><button type="submit" class="btn">Log in</button></div>
</form>
<p class="muted">No account? <a href="/signup">Sign up</a></p>
`,
  });
}

/** One of the caller's own pastes, with the actions that make sense for it. */
function pasteRow({ paste, csrfToken }) {
  const badges = [];
  if (paste.burn) badges.push('<span class="badge warn">burn</span>');
  if (paste.protected) badges.push('<span class="badge">password</span>');
  if (paste.visibility === 'unlisted') badges.push('<span class="badge">unlisted</span>');

  // A burn paste is destroyed on read, so there is nothing left to edit or
  // relabel. Offering those controls would just be broken buttons.
  const actions = [
    `<a class="btn quiet small" href="/${escapeHtml(paste.id)}">Open</a>`,
    paste.burn ? '' : `<a class="btn quiet small" href="/${escapeHtml(paste.id)}/edit">Edit</a>`,
    `<a class="btn quiet small" href="/raw/${escapeHtml(paste.id)}">Raw</a>`,
    `<form class="actions" method="post" action="/account/pastes/${escapeHtml(paste.id)}/visibility">
       <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
       <input type="hidden" name="visibility" value="${paste.visibility === 'unlisted' ? 'public' : 'unlisted'}">
       <button type="submit" class="btn quiet small">${paste.visibility === 'unlisted' ? 'Make public' : 'Make unlisted'}</button>
     </form>`,
    `<form class="actions" method="post" action="/account/pastes/${escapeHtml(paste.id)}/delete">
       <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
       <button type="submit" class="btn quiet small">Delete</button>
     </form>`,
  ].filter(Boolean).join('\n      ');

  return `<li>
  <a class="list-title" href="/${escapeHtml(paste.id)}">${escapeHtml(paste.filename || paste.id)}</a>
  <p class="meta">${escapeHtml(formatBytes(paste.size))} &middot; ${paste.views} view${paste.views === 1 ? '' : 's'} &middot; ${escapeHtml(humanAge(Date.now() - paste.created_at))}${badges.length ? ` ${badges.join(' ')}` : ''}</p>
  <div class="actions">
      ${actions}
  </div>
</li>`;
}

function accountPage({ nonce, user, pastes, stats, csrfToken, flash = null, error = null }) {
  const notice = [
    flash ? `<p class="notice ok" role="status">${escapeHtml(flash)}</p>` : '',
    error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '',
  ].join('');
  const rows = pastes.length === 0
    ? '<div class="blank"><strong>Nothing yet</strong><p>Your pastes will be listed here.</p></div>'
    : `<ul class="list">\n${pastes.map((p) => pasteRow({ paste: p, csrfToken })).join('\n')}\n</ul>`;

  return layout({
    title: user.username,
    nonce,
    user,
    body: `
${notice}<h1>${escapeHtml(user.username)}</h1>
<p class="meta">Joined ${escapeHtml(humanAge(Date.now() - user.created_at))} &middot; ${stats.total} paste${stats.total === 1 ? '' : 's'} &middot; ${escapeHtml(formatBytes(stats.accountMax))} per paste</p>
<div class="actions">
  <a class="btn quiet small" href="/">New paste</a>
  ${user.isAdmin ? '<a class="btn quiet small" href="/admin">Admin</a>' : ''}
  <form class="actions" method="post" action="/logout">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <button type="submit" class="btn quiet small">Log out</button>
  </form>
</div>
<div class="divider"></div>
<h1>Your pastes</h1>
${rows}

<div class="divider"></div>
<h1>Account</h1>
<div class="actions">
  <a class="btn quiet small" href="/account/password">Change password</a>
  <a class="btn quiet small" href="/account/export">Download my data</a>
  ${user.isAdmin ? '<a class="btn quiet small" href="/admin/settings">Site settings</a>' : ''}
</div>

<details class="more" style="margin-top:1.25rem">
  <summary>Delete my account</summary>
  <form method="post" action="/account/delete">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <p class="muted">Removes your account, your sessions and all ${pastes.length} of your pastes. This cannot be undone.</p>
    <input type="password" name="password" placeholder="Confirm your password" autocomplete="current-password" required>
    <button type="submit" class="btn danger small">Delete account and pastes</button>
  </form>
</details>
`,
  });
}

function adminPage({ nonce, user, accounts, query, audit, stats, csrfToken, flash = null, error = null }) {
  const notice = [
    flash ? `<p class="notice ok" role="status">${escapeHtml(flash)}</p>` : '',
    error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '',
  ].join('');

  const rows = accounts.length === 0
    ? '<tr><td colspan="6">No accounts match.</td></tr>'
    : accounts
        .map((account) => {
          const when = new Date(account.created_at).toISOString().slice(0, 10);
          const isSelf = account.id === user.id;

          const more = isSelf
            ? '<span class="muted">You</span>'
            : `<details class="more">
          <summary>More</summary>
          <form method="post" action="/admin/users/${account.id}/delete">
            <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
            <label><input type="checkbox" name="pastes" value="delete" checked>
              Also delete their ${account.pastes} paste${account.pastes === 1 ? '' : 's'}</label>
            <button type="submit" class="btn danger small">Delete account</button>
          </form>
          <form method="post" action="/admin/users/${account.id}/password">
            <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
            <input type="password" name="password" placeholder="New password" autocomplete="new-password" required>
            <input type="password" name="confirm" placeholder="Confirm" autocomplete="new-password" required>
            <button type="submit" class="btn small">Set password</button>
          </form>
        </details>`;

          return `<tr>
  <td class="name">${escapeHtml(account.username)}${account.is_admin ? ' <span class="badge accent">admin</span>' : ''}</td>
  <td class="right">${account.pastes}</td>
  <td class="right">${escapeHtml(formatBytes(Number(account.bytes) || 0))}</td>
  <td class="dim">${when}</td>
  <td>${more}</td>
</tr>`;
        })
        .join('\n');

  const logRows = audit.length === 0
    ? '<tr><td colspan="3">Nothing recorded yet.</td></tr>'
    : audit
        .map(
          (entry) => `<tr>
  <td class="dim">${escapeHtml(new Date(entry.at).toISOString().slice(0, 16).replace('T', ' '))}</td>
  <td>${escapeHtml(entry.actor_name)}</td>
  <td>${escapeHtml(entry.action)}${entry.target ? ` <span class="muted">${escapeHtml(entry.target)}</span>` : ''}</td>
</tr>`,
        )
        .join('\n');

  return layout({
    title: 'Admin',
    nonce,
    user,
    body: `
${notice}<h1>Admin</h1>
<p class="meta">${stats.users} account${stats.users === 1 ? '' : 's'} &middot; ${stats.admins} admin${stats.admins === 1 ? '' : 's'} &middot; ${stats.pastes} paste${stats.pastes === 1 ? '' : 's'}</p>
<div class="actions" style="margin-bottom:1.5rem">
  <a class="btn quiet small" href="/admin/settings">Site settings &amp; legal documents</a>
</div>

<form class="search" method="get" action="/admin">
  <input type="text" name="q" value="${escapeHtml(query)}" placeholder="Search usernames" autocomplete="off" spellcheck="false">
  <button type="submit" class="btn quiet small">Search</button>
</form>

<table class="table">
  <thead><tr><th>Account</th><th class="right">Pastes</th><th class="right">Size</th><th>Joined</th><th></th></tr></thead>
  <tbody>\n${rows}\n</tbody>
</table>

<h1>Audit log</h1>
<p class="muted">Append-only. Password values are never recorded.</p>
<table class="table">
  <thead><tr><th>When</th><th>Actor</th><th>Action</th></tr></thead>
  <tbody>\n${logRows}\n</tbody>
</table>
`,
  });
}

function apiPage({ user = null, nonce, docs }) {
  const rows = Object.entries(docs.routes)
    .map(([route, what]) => `<tr><td>${escapeHtml(route)}</td><td>${escapeHtml(what)}</td></tr>`)
    .join('\n');

  const fields = Object.entries(docs.create.fields)
    .map(([name, about]) => `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(about)}</td></tr>`)
    .join('\n');

  return layout({
    title: 'API',
    nonce,
    user,
    body: `
<h1>API</h1>
<pre class="listing" style="padding:1rem;font-size:.85rem;white-space:pre-wrap"><code>curl -X POST ${escapeHtml(docs.create.path)} \\
  -H 'Content-Type: application/json \\
  -d '{"content":"hello","ttl":"1h"}'</code></pre>

<h1 style="margin-top:2rem">Fields</h1>
<table class="docs">\n${fields}\n</table>

<h1>Routes</h1>
<table class="docs">\n${rows}\n</table>

<p class="muted">Maximum paste size ${escapeHtml(formatBytes(docs.limits.max_paste_bytes))}. This page is also available as JSON.</p>
`,
  });
}

function editPastePage({ nonce, user = null, paste, content, csrfToken, error = null }) {
  const banner = error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '';
  const options = EXPIRY_CHOICES.map(
    ([value, label]) => `<option value="${value}">${escapeHtml(label)}</option>`,
  ).join('');

  return layout({
    title: paste.filename || 'Edit',
    nonce,
    user,
    body: `
${banner}<h1>Edit ${escapeHtml(paste.filename || paste.id)}</h1>
<p class="muted">The link stays the same, so anything already shared still points here.</p>
<form class="stack" method="post" action="/${escapeHtml(paste.id)}/edit">
  <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
  <textarea class="editor" name="content" rows="18" spellcheck="false">${escapeHtml(content)}</textarea>
  <div class="options">
    <label>Expires <select name="ttl">${options}</select></label>
  </div>
  <input class="secondary" type="text" name="filename" maxlength="${config.maxFilenameLen}"
         value="${escapeHtml(paste.filename ?? '')}" placeholder="Filename (optional)">
  <div class="actions"><button type="submit" class="btn">Save changes</button></div>
</form>
`,
  });
}

const DOC_TITLES = {
  privacy: 'Privacy Policy',
  terms: 'Terms of Service',
  cookies: 'Cookies',
  imprint: 'Operator details',
};

function legalPage({ nonce, user, kind, bodyHtml, outstanding = [], settings = {} }) {
  const notice = outstanding.length > 0 && user?.isAdmin
    ? `<p class="notice error" role="status">Still unset: ${outstanding.map((k) => escapeHtml(k)).join(', ')}</p>`
    : '';

  return layout({
    title: DOC_TITLES[kind] ?? kind,
    nonce,
    user,
    // Legal pages should not be previewed as rich cards.
    socialImage: false,
    description: `${DOC_TITLES[kind] ?? kind} for ${settings.operator_name || SITE_NAME}.`,
    body: `
<h1>${escapeHtml(DOC_TITLES[kind] ?? kind)}</h1>
${notice}<div class="prose">${bodyHtml}</div>
`,
  });
}

function passwordChangePage({ nonce, user = null, banner = '', csrfToken, forced = false }) {
  return layout({
    title: 'Change password',
    nonce,
    user,
    body: `
${banner}<h1>${forced ? 'Choose a new password' : 'Change password'}</h1>
${
  forced
    ? ''
    : '<p class="muted">Changing your password signs you out on every other device.</p>'
}
<form class="stack" method="post" action="/account/password">
  <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
  <input type="password" name="password" placeholder="New password (10 characters or more)"
         autocomplete="new-password" required>
  <input type="password" name="confirm" placeholder="Confirm new password" autocomplete="new-password" required>
  <div class="actions"><button type="submit" class="btn">Set password</button></div>
</form>
`,
  });
}

/*
 * Two of these are required: without a name and a contact the published pages
 * cannot identify the controller, which is the one thing every regime here
 * insists on. The rest carry defaults and are only worth touching if they are
 * wrong for you. There is no address field on purpose.
 */
const OPERATOR_FIELDS = [
  ['operator_name', 'Operator name', 'text', 'Your name or company name', true],
  ['privacy_contact', 'Privacy contact', 'text', 'Where privacy requests go', true],
  ['operator_country', 'Country', 'text', 'Thailand', false],
  ['effective_date', 'Effective date', 'text', '2026-09-30', false],
  ['retention_pastes', 'Log retention (days)', 'text', '14', false],
  ['retention_backups', 'Backup retention (days)', 'text', '30', false],
  ['liability_cap', 'Liability cap', 'text', 'Amount or wording', false],
  ['legal_version', 'Legal version', 'text', '1', false],
];

const DOC_FIELDS = [
  ['doc_privacy', 'Privacy Policy'],
  ['doc_terms', 'Terms of Service'],
  ['doc_cookies', 'Cookie notice'],
  ['doc_imprint', 'Operator details page'],
];

function settingsPage({ nonce, user, settings, outstanding = [], csrfToken, flash = null }) {
  const fields = OPERATOR_FIELDS.map(
    ([key, label, type, hint, required]) => `
    <label class="field">
      <span>${escapeHtml(label)}${required ? ' <span class="req">required</span>' : ''}</span>
      <input type="text" name="${escapeHtml(key)}" value="${escapeHtml(settings[key] ?? '')}"
             placeholder="${escapeAttr(hint)}" autocomplete="off"${required ? ' required' : ''}>
    </label>`,
  ).join('');

  const docs = DOC_FIELDS.map(
    ([key, label]) => `
    <label class="field">
      <span>${escapeHtml(label)} <a href="/${key.replace('doc_', '')}" target="_blank" rel="noopener">view</a></span>
      <textarea name="${escapeHtml(key)}" rows="14" spellcheck="false">${escapeHtml(settings[key] ?? '')}</textarea>
    </label>`,
  ).join('');

  return layout({
    title: 'Settings',
    nonce,
    user,
    body: `
${flash ? '<p class="notice ok" role="status">Saved.</p>' : ''}<h1>Site settings</h1>
${
  outstanding.length
    ? `<p class="notice error" role="status">Not filled in yet: ${outstanding.map((k) => escapeHtml(k)).join(', ')}</p>`
    : '<p class="notice ok">All operator details are filled in.</p>'
}
<p class="muted">These fill the legal pages below. Anything left blank shows as a warning to administrators.</p>
<form method="post" action="/admin/settings">
  <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
  <h1 style="margin-top:2rem">Operator</h1>
  <div class="fields">${fields}</div>
  <h1 style="margin-top:2.5rem">Documents</h1>
  <p class="muted">Markdown. Use <code>{{token}}</code> to insert a value from the section above.</p>
  <div class="fields">${docs}</div>
  <div class="actions" style="margin-top:1.5rem"><button type="submit" class="btn">Save settings</button></div>
</form>
`,
  });
}

function escapeAttr(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function setupPage({ nonce, csrfToken, captchaScript = '', captchaWidget = '', error = null }) {
  const banner = error ? `<p class="notice error" role="alert">${escapeHtml(error)}</p>` : '';
  return layout({
    title: 'Setup',
    nonce,
    head: captchaScript,
    // No rich preview on a page that should never be linked to.
    socialImage: false,
    body: `
${banner}<h1>Finish setup</h1>
<p class="notice error" role="status">Open to anyone until an administrator exists. Whoever completes this first becomes the administrator.</p>
<p class="muted">Create the administrator account for this site.</p>
<form class="stack" method="post" action="/setup" autocomplete="off">
  <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
  ${bait()}
  <input type="text" name="username" placeholder="Your username" autocomplete="username"
         autocapitalize="none" spellcheck="false" required>
  <input type="password" name="password" placeholder="Password (10 characters or more)"
         autocomplete="new-password" required>
  <input type="password" name="confirm" placeholder="Confirm password" autocomplete="new-password" required>
  ${captchaWidget}
  <div class="actions"><button type="submit" class="btn">Create administrator</button></div>
</form>
<p class="muted">This page returns 404 permanently once an administrator exists.</p>
`,
  });
}

module.exports = {
  homePage,
  pastePage,
  passwordPage,
  recentPage,
  apiPage,
  errorPage,
  accountPage,
  signupPage,
  loginPage,
  editPastePage,
  adminPage,
  legalPage,
  passwordChangePage,
  settingsPage,
  setupPage,
  layout,
  formatBytes,
};