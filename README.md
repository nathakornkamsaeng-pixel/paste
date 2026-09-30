# paste

A small pastebin, live at **https://paste.everlyce.com**.

Anonymous, no accounts, no analytics. Pastes live in a local SQLite file.

## Features

- Create pastes from the web form, the JSON API, or a plain `text/plain` body
- Server-side syntax highlighting (highlight.js, vendored — no CDN at runtime)
- `raw` and download views
- Expiry: never, 10m, 1h, 1d, 1w, 30d, or an explicit number of seconds
- **Burn after read** — claimed with a single atomic `DELETE ... RETURNING`, so
  concurrent readers cannot both win. Once read, the row is **deleted outright**:
  no content, no metadata, no tombstone, nothing recoverable from the database.
  A test asserts the table holds zero rows for that id afterwards.
- Optional password, gated before the content is loaded
- Anonymous delete tied to a cookie-scoped secret rather than to anyone who
  knows the URL

### Accounts

Sign-up is open, username + password, no email and therefore no password reset.

- **Manage pastes from any device** — `/account` lists everything you made,
  with edit, delete, and unlist. Previously this was a per-browser cookie only.
- **Unlisted pastes** — never shown in `/recent`, reachable only by link.
- **Higher limits** — 4 MiB per paste instead of 1 MiB, 30 creates/min instead
  of 10.

Anonymous pasting still works with no account.

### Admin

`/admin`, for accounts listed in `PASTE_ADMINS`. Can search accounts, **reset
anyone's password**, and **delete accounts** (optionally with their pastes).

- Admin is granted by configuration, never by a request, so signup cannot
  self-promote even by posting `is_admin=1`.
- The flag is re-read from the database on every admin request, so revoking
  admin takes effect immediately rather than at the admin's next login.
- A non-admin gets **404**, not 403, so the panel is not advertised.
- A password reset **revokes every existing session** for that account.
- An admin cannot delete their own account, and the last remaining admin cannot
  be deleted — both lockouts are refused.
- Every privileged action is appended to `audit_log`, which is never updated or
  deleted. **Password values are never written to it.**

```bash
node --no-warnings scripts/admin.js list
printf '%s\n' 'a-good-password' | node --no-warnings scripts/admin.js create you
node --no-warnings scripts/admin.js grant  someone
node --no-warnings scripts/admin.js revoke someone
```

The password is read from stdin rather than the command line, where it would be
visible in the process list.

`PASTE_ADMINS` is the better mechanism because it re-applies on every boot, so a
restored database cannot leave you with no admin. `revoke` refuses to remove the
last one.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /` | new paste form |
| `POST /` | create (form-encoded) → 303 to the paste |
| `POST /api/paste` | create (JSON or `text/plain`) → 201 JSON |
| `GET /{id}` | view |
| `GET /raw/{id}` | `text/plain` |
| `GET /dl/{id}` | download attachment |
| `POST /{id}` | submit password |
| `POST /{id}/delete` | delete (needs the creator secret) |
| `GET /recent` | recent public pastes |
| `GET /healthz` | status JSON |
| `GET /signup`, `POST /signup` | register |
| `GET /login`, `POST /login` | sign in |
| `POST /logout` | sign out (CSRF token required) |
| `GET /account` | your pastes |
| `GET /{id}/edit`, `POST /{id}/edit` | edit a paste you own |
| `POST /account/pastes/{id}/visibility` | toggle unlisted |
| `POST /account/pastes/{id}/delete` | delete a paste you own |
| `GET /account/password`, `POST /account/password` | change password (forced after an admin reset) |
| `GET /account/export` | download your data as JSON |
| `POST /account/delete` | delete your account and pastes |
| `GET /privacy`, `/terms`, `/cookies`, `/imprint` | legal pages |
| `GET /setup` | first-run setup (404 once an admin exists) |
| `GET /admin` | admin panel (admins only) |
| `GET /admin/settings`, `POST /admin/settings` | operator details and legal documents |
| `POST /admin/users/{id}/password` | reset an account's password |
| `POST /admin/users/{id}/delete` | delete an account |

```bash
curl -X POST https://paste.everlyce.com/api/paste \
  -H 'Content-Type: application/json' \
  -d '{"content":"hello","ttl":"1h","burn":false,"filename":"note.txt"}'
```

`text/plain` bodies can set `X-Paste-Filename`, `X-Paste-Language`,
`X-Paste-TTL` and `X-Paste-Burn: 1`.

## Brand

`brand/` holds the source artwork; `scripts/build-brand.cjs` renders it into
`public/branding/`.

```bash
node scripts/build-brand.cjs          # needs rsvg-convert + Inter
node scripts/preview.mjs out.png 60   # ASCII preview, for checking artwork
```

Paste is an **Everlyce** product, so the mark is the Everlyce monogram, not a
pastebin glyph. It is a stem with three bars, the middle one short and accented.
`brand/icon.svg` is the source of truth and the build renders the favicons and
PWA icons from it; the header copy inlined in `src/views.js` is a duplicate of
it, and the two have to be edited together.

It follows [pos.everlyce.com](https://pos.everlyce.com), the closest sibling:

| | |
| --- | --- |
| Glyph | the **E** monogram, built from rounded rects, on the POS 64-unit grid scaled ×8 |
| Tile gradient | `#1d3a6b` → `#24518f` → `#2f7ad4`, the POS app icon's, verbatim |
| Corner radius | `rx 112/512`, i.e. the `14/64` every Everlyce mark uses |
| Terminals | fully rounded, so they match the tile's own corner |
| Accent bar | `#a78bfa` |
| Lockup | `Everlyce` large and near-white, `paste` tracked out beneath it in the accent |
| Card | navy opening out to the brand blue, as on the POS social card |

The one deliberate difference is the accent bar. POS takes green `#17b978` to
mark itself as the point-of-sale product; paste takes `#a78bfa`, a light tint of
the violet in [everlyce.com](https://everlyce.com)'s own mark. The tint matters
— plain `#7048e8` sits too close to the blue tile to separate at favicon sizes.

The site's `--accent` ramp in `public/app.css` is the POS ramp verbatim
(`#3563b8` / `#294f98` / `#edf2fa`) so the UI and the mark agree.

| Asset | Where it is used |
| --- | --- |
| `favicon.svg` / `.ico` / `favicon-{16,32,48}.png` | tab strip, bookmarks |
| `apple-touch-icon.png` | iOS home screen (needs PNG; no platform accepts SVG here) |
| `icon-{192,512}.png` | `site.webmanifest`, installable |
| `og.png` | link previews on Slack, Discord, iMessage |
| `logo.png` / `logo.svg` | the standalone lockup |

The header mark is **inlined** rather than fetched, so it cannot shift layout
while loading. The favicon variant is flatter than the main icon on purpose:
no sheen, for contrast at 16px.

Paste links get a real preview rather than the generic site card — the filename
and an excerpt of the content, with `og:type=article`. All of it goes through
the same escaping as the page body.

## Privacy & compliance

Operator is **{{operator_name}}**, {{operator_country}}. Contact:
{{privacy_contact}}.

**Only two fields are required**: your name, and a contact address for privacy
requests. Everything else carries a default. No street address is collected or
published — Thai PDPA requires you to identify the controller, not to publish a
postal address, and no Impressum obligation applies here.

The documents are scoped to **Thailand PDPA** and deliberately extend to the rest
of Asia (Singapore, Malaysia, Indonesia, Philippines, Vietnam, Japan, Korea),
with the core requirements of the EU/EEA GDPR, UK GDPR and the major US state
laws covered for the limited data this site handles. It says plainly that it is
not a full Article 13 notice and not legal advice.

The site is open to visitors from anywhere, so it carries the regimes that
actually reach it:

- **Thailand — Personal Data Protection Act B.E. 2562 (2019).** Primary, being
  where the operator is established.
- **EU/EEA — GDPR**, **UK — UK GDPR**, plus common US state laws.

Four public pages, generated from settings the administrator edits:

| Page | Source |
| --- | --- |
| `/privacy` | `doc_privacy` |
| `/terms` | `doc_terms` |
| `/cookies` | `doc_cookies` |
| `/imprint` | `doc_imprint` |

### Filling in the operator details

`/admin/settings` holds your name, country, contact, retention periods and the
four documents. There is deliberately **no address field**: a street address is
neither required by Thai PDPA nor by anything else this site falls under, and
not collecting it is the point. Everything is seeded on first boot and **never overwritten
afterwards**, so your edits survive restarts.

Documents use `{{token}}` placeholders that resolve to the operator fields, so
you fill your details in once and every page updates. The document set carries a
version number: when it changes, the stored copies are refreshed on the next
boot and the previous text is kept under `backup_doc_*` rather than discarded. A token whose value is
blank renders as a visible `[not set: name]` marker rather than an empty string,
because "** **, , Thailand." is a legally meaningless sentence. Until the
details are filled in, the service logs a warning on every start and the admin
panel shows a banner.

**These v1 drafts need review by someone qualified in your jurisdiction before
you rely on them.** They are engineering work product, not legal advice. In
particular, check the stated retention periods against what you have actually
configured in nginx and any backups.

### What is implemented, technically

- **Self-service export** at `/account/export` — one JSON file with the
  account, every paste including content, and session metadata. Session
  *tokens* are deliberately excluded: they are secrets, not user data.
- **Self-service deletion** at `/account/delete` — requires the password
  again, then removes the account, its sessions **and its pastes**. The pastes
  are deleted explicitly rather than by relying on the foreign key, which is
  `ON DELETE SET NULL` and would leave content reachable by link under an
  account that no longer exists.
- **Forced password change.** An administrator reset signs the user out
  everywhere and flags the account; until they choose their own password every
  route redirects to `/account/password`. `/healthz` and the legal pages stay
  reachable so monitoring keeps working.
- **One cookie.** `paste_session`, HttpOnly, SameSite=Lax, Secure, 30 days. No
  analytics, no advertising, no third-party scripts, no cookies for anonymous
  visitors at all. There is nothing to consent to, so there is no consent
  banner.
- **Audit log** records every privileged action, password reset, export and
  deletion. Password values are never written to it.

### Administrators cannot read pastes

The admin panel exposes **counts and sizes only** — never content, never
filenames, never paste ids. This is enforced at the store layer rather than in
the template, so a template mistake cannot leak it, and it is covered by tests
that assert the content is absent from `/admin`, `/admin/settings` and the
`listUsers` result itself.

Administrators can still open a paste they hold a link to, exactly as any other
visitor can. That is inherent to link-shared content: the link *is* the
capability, and there is no version of this site that can revoke that.

## Operations

```bash
systemctl status paste          # service
systemctl restart paste
journalctl -u paste -f          # logs
npm test                        # 117 integration tests
node --no-warnings scripts/admin.js list
```

**Light only.** There is no dark theme and no toggle, so there is no second
palette to drift out of sync and nothing to flash on load. Every text and
background pair in use is checked against WCAG AA (the lowest is 4.65, on
muted text).

The component vocabulary is deliberately tiny:

- **One button.** `.btn` filled for the single primary action on a page, and
  `.btn.quiet` for everything else that needs a target. Nothing else is a
  button; secondary actions are plain links.
- **One pill.** `.badge`, only for state that changes what a link means.
- **Two header links.** New and Recent. Account sits on the right; API, Sign up
  and Status live in the footer.
- **One inline script.** Gone entirely — with a single theme there is nothing
  for it to do.

The syntax highlighting uses highlight.js's light `github` theme. That matters:
the page is light, so a dark code block reads as a mistake rather than a
choice.

### Getting admin access: first-run setup

While no administrator exists, **/setup** is open. Visit it, pick a username
and password, and that account becomes the administrator — signed straight in.
From that moment **/setup returns 404 permanently**, so it cannot be used to
create a new admin later.

There is no token. The service says so loudly on every boot until setup is
done:

```
[paste] SETUP PENDING: no administrator exists yet.
[paste] Create one at  https://paste.everlyce.com/setup
[paste] That page is OPEN to anyone until it is done, and the first
[paste] person to complete it becomes the administrator.
```

**Worth knowing:** because there is no secret on the page, whoever reaches
`/setup` first becomes the administrator. That window is from deploy until you
complete it, so finish setup promptly — and if you need to close it without
setting anyone up, add a row to `users` with `is_admin = 1`, or use the shell
command below and restart.

The endpoint keeps the signup protections (honeypot, per-IP rate limit and the
proof-of-work check), so it cannot be cheaply automated; those are friction, not
an access control.

Prefer not to use the web screen at all? From a shell on the box:

```bash
printf '%s\n' 'a-good-password' | node --no-warnings scripts/admin.js create you
```

That closes setup too, because an administrator now exists.

`PASTE_ADMINS` remains available for granting admin to accounts you already
control, and warns at boot if the named accounts do not exist yet.

nginx serves TLS and proxies to `127.0.0.1:8790`:

- `/etc/nginx/sites-available/paste.everlyce.com`
- `/etc/nginx/conf.d/paste-limits.conf`

Certificate is Let's Encrypt via `certbot --webroot`, auto-renewed.

State lives in `/var/lib/paste/` (SQLite database + a 48-byte key used to
derive session secrets). The service runs as an ephemeral `DynamicUser` with
`ProtectSystem=strict`, so it can read its code but write only there.

## Configuration

Environment variables, all optional (see `src/config.js`):

| Variable | Default |
| --- | --- |
| `PASTE_HOST` | `127.0.0.1` |
| `PASTE_PORT` | `8790` |
| `PASTE_DB` | `/var/lib/paste/paste.db` |
| `PASTE_PUBLIC_ORIGIN` | `https://paste.everlyce.com` |
| `PASTE_MAX_BYTES` | `1048576` |
| `PASTE_CREATE_MAX` / `PASTE_CREATE_MAX_ACCOUNT` | `10` / `30` |
| `PASTE_MAX_BYTES` / `PASTE_MAX_BYTES_ACCOUNT` | `1048576` / `4194304` |
| `PASTE_READ_MAX` / `PASTE_READ_WINDOW_MS` | `240` / `60000` |
| `PASTE_SIGNUP_MAX` / `PASTE_SIGNUP_WINDOW_MS` | `5` / `3600000` |
| `PASTE_LOGIN_MAX` / `PASTE_LOGIN_ACCOUNT_MAX` | `10` / `5` |
| `PASTE_SESSION_TTL_MS` | `2592000000` (30 days) |
| `PASTE_REGISTRATION_OPEN` | `1` |
| `PASTE_CAPTCHA` | `pow` (or `turnstile` when a secret is set) |
| `PASTE_TURNSTILE_SECRET` / `PASTE_TURNSTILE_SITE_KEY` | unset |
| `PASTE_DEFAULT_VISIBILITY` | `public` |
| `PASTE_ADMINS` | empty (comma-separated usernames) |
| `PASTE_ADMINS` note | promoted on every boot; warns if the named accounts do not exist yet |
| `PASTE_ADMIN_MAX` / `PASTE_ADMIN_WINDOW_MS` | `60` / `60000` |

## Captcha

Self-hosted **proof of work**. No third-party account, no external script, no
network call to a vendor.

On the signup form the server issues a signed challenge. The browser searches
for a nonce such that `SHA-256(challenge + ':' + nonce)` begins with N zero
bits, in a Web Worker so the page stays responsive, and posts the nonce back.
The server recomputes the hash itself, so a client that merely claims to have
solved it gains nothing.

- **Stateless.** The challenge carries its own difficulty and timestamp, both
  covered by an HMAC over the deployment's secret. Nothing is stored, so
  nothing has to expire out of a cache.
- **Difficulty cannot be lowered by the client** — it lives inside the signed
  payload, not in a form field.
- **Served same-origin** at `/static/pow-worker.js`, so the CSP stays at
  `worker-src 'self'` with no `blob:` exception.
- The SHA-256 is written out in the worker and **checked against `node:crypto`
  in the test suite**, rather than trusted, because the solver uses a fast path
  that skips re-hashing the challenge prefix.

Behind it sit the two things that actually enforce the limit: a hidden honeypot
field, and **5 signups per hour per IP**.

| Variable | Default | |
| --- | --- | --- |
| `PASTE_POW_BITS` | `18` | difficulty. ~262k hashes |
| `PASTE_POW_BUDGET_MS` | `25000` | a slower device gives up rather than hanging |
| `PASTE_CAPTCHA` | `pow` | or `turnstile`, or `none` |

Solve time is exponentially distributed, so the mean is not what a visitor
feels. Measured on this box at 18 bits: median **221ms**, slowest **1155ms**.
At 20 bits real attempts ranged from 1M to 3.4M, i.e. 1s to 5s, which is why
the default is 18. Raise it if signup is actually being abused.

### What this does and does not stop

Honest limits, since this is a spam-friction control and not a security
boundary:

- **Stops** naive bots, headless form-fillers, and signup scripts that post
  without implementing the challenge. Each signup costs them real CPU.
- **Does not stop** a determined attacker. Anyone willing to write a native
  SHA-256 solver can produce proofs cheaply, and a solved challenge can be
  replayed inside its 15-minute window because verification is stateless.
  The per-IP rate limit is what actually bounds the damage.
- If signup is being abused in a way that matters, set
  `PASTE_TURNSTILE_SECRET` and `PASTE_TURNSTILE_SITE_KEY` to switch to
  Turnstile, which is verified server-side against Cloudflare and is harder to
  solve at scale.

## Security notes

- Every response carries a strict CSP (`default-src 'none'` with a per-response
  nonce, no `unsafe-inline`), plus `nosniff`, `DENY` framing and `no-referrer`.
  `sendHtml` rejects unknown options so a header cannot be silently dropped.
- Paste content is user input and is treated as hostile: it is escaped, and
  highlight.js escapes its own output. Filenames are stripped of path
  separators, quotes, control characters and dot-runs before they reach a
  `Content-Disposition` header.
- The app binds loopback only, so nginx is the sole entry point.
- The vhost recovers the client IP from `CF-Connecting-IP` but only for
  connections arriving from Cloudflare's published ranges, so the header cannot
  be spoofed by hitting the origin directly to escape the rate limits.
- The creator's delete right and the password-unlock right are separate derived
  secrets. Knowing a paste's password does not grant the ability to delete it,
  and the delete control is only rendered for a session holding that right.
- `/recent` deliberately omits burn, password-protected and unlisted pastes: a
  burn paste in a public listing could be destroyed by any visitor, and a
  locked or unlisted one would disclose its filename.
- Accounts use scrypt password hashing and a session table that stores only the
  SHA-256 of each session token, so a database copy does not hand out live
  sessions.
- Login returns one message for an unknown username and a wrong password, and
  performs a dummy scrypt when no user matched, so neither the body nor the
  response time reveals whether an account exists.
- Anonymous CSRF tokens for the signup/login forms are HMAC-signed timestamps,
  needing no storage and expiring on their own. Every *authenticated* write
  instead requires the per-session token plus a same-origin `Origin` header.
- `?next=` only accepts same-site relative paths, so it cannot bounce a
  just-signed-in user to another domain.
- Signup and login forms are also protected by a hidden honeypot field.
- Cross-site writes are judged on `Sec-Fetch-Site` first (browser-set, not
  script-writable, and the only signal that distinguishes a sandboxed frame from
  a real same-origin request), then on `Origin` compared against the `Host` the
  request arrived on. `X-Forwarded-Host` is deliberately never trusted, since a
  client could pair a spoofed value with a matching `Origin`. `Origin: null` is
  treated as opaque rather than foreign, because sandboxed frames, `file://`
  pages and privacy browsers legitimately send it; the protections that carry
  the weight are unaffected, since every authenticated write needs an
  unguessable per-session CSRF token and the session cookie is `SameSite=Lax`.

### Worth knowing

The origin IP is public, so someone bypassing Cloudflare can still reach nginx
directly over plain HTTP. That is the existing posture for the other
`everlyce.com` vhosts and was left consistent. To close it, restrict `:80` and
`:443` at the firewall to Cloudflare's ranges — but do that only if the other
sites on this box are migrated too, since they share the listeners.

## License

**GNU Affero General Public License v3.0** — see [`LICENSE`](LICENSE) for the
full text.

AGPL rather than GPL, deliberately: paste is a **network service**. Section 13
is the part that matters here. If you run a modified version of this and let
other people reach it over a network, you must offer them the corresponding
source of your version. Deploying it as a service is exactly the case AGPL was
written to cover, and the plain GPL would let a hosted fork stay closed.

To satisfy section 13 when you deploy your own build, publish a **Source** link
that leads to the source of the running version, and keep it in step with what
you actually serve. This repository is that link for the unmodified build.

    Copyright (C) 2026 Everlyce

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
    License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.

`package.json` declares the SPDX id `AGPL-3.0-only`. If you would rather permit
relicensing under the "or later" terms, change it to `AGPL-3.0-or-later` and
say "either version 3 of the License, or (at your option) any later version" in
the notice above.
