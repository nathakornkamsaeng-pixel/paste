# Operations

Day-to-day notes for the host that runs Everlyce paste. Paths below match the
deployment described in the README (`/var/lib/paste/`, nginx in front,
loopback on `127.0.0.1:8790`). They are examples. Nothing in this file is a
secret, and none of the commands embed one.

The service is one process (`src/server.js`) with a SQLite file and a 48-byte
key next to it (`secret`). Both have to be backed up together. Restoring the
database without the key invalidates sessions and proof-of-work signatures.

With `DynamicUser=`, systemd may place that state under `/var/lib/private/paste`
rather than `/var/lib/paste`. `systemctl show paste -p StateDirectory -p FragmentPath`
is the way to see which path this host actually uses. The examples use
`/var/lib/paste`.

## SQLite backup

Prefer an online backup. `sqlite3 .backup` uses SQLite's backup API, so it is
consistent while the service is running and while WAL mode is on. Copying the
file with `cp` while the process is up can catch a half-written WAL.

```bash
install -d -m 700 /var/backups/paste
sqlite3 /var/lib/paste/paste.db ".backup /var/backups/paste/paste.db"
cp -a /var/lib/paste/secret /var/backups/paste/secret
chmod 600 /var/backups/paste/paste.db /var/backups/paste/secret
```

The destination should not be the same directory the service writes, and it
should not be world-readable: `secret` is the live signing key.

### Stop and copy

Use this when `sqlite3` is not installed. Stop the service first so the WAL is
checkpointed and the copy is one consistent set of files. `-wal` and `-shm`
may already be gone after a clean shutdown; that is fine.

```bash
systemctl stop paste
install -d -m 700 /var/backups/paste
cp -a /var/lib/paste/paste.db /var/backups/paste/paste.db
# Present only if the process was killed mid-write. Harmless to skip when absent.
cp -a /var/lib/paste/paste.db-wal /var/backups/paste/paste.db-wal 2>/dev/null || true
cp -a /var/lib/paste/paste.db-shm /var/backups/paste/paste.db-shm 2>/dev/null || true
cp -a /var/lib/paste/secret /var/backups/paste/secret
chmod 600 /var/backups/paste/paste.db /var/backups/paste/secret
systemctl start paste
```

Restore by stopping the service, replacing both `paste.db` and `secret`, and
starting again. Do not restore a database from one host onto another host's
`secret`.

### systemd timer

A timer is the right place for this. An `ExecStartPre` on `paste.service`
would also take a snapshot, but a failed backup would then refuse to start
the site. Leave the pre-start hook unused unless you accept that.

`/etc/systemd/system/paste-backup.service`:

```ini
[Unit]
Description=Online backup of the Everlyce paste database and signing key
# Does not start or stop paste. sqlite3 .backup is safe while it is up.

[Service]
Type=oneshot
Environment=PASTE_STATE=/var/lib/paste
Environment=PASTE_BACKUP_DIR=/var/backups/paste
# systemd does not expand ${VAR} inside ExecStart; the shell does.
ExecStart=/bin/sh -c 'install -d -m 700 "$PASTE_BACKUP_DIR" && sqlite3 "$PASTE_STATE/paste.db" ".backup $PASTE_BACKUP_DIR/paste.db" && cp -a "$PASTE_STATE/secret" "$PASTE_BACKUP_DIR/secret" && chmod 600 "$PASTE_BACKUP_DIR/paste.db" "$PASTE_BACKUP_DIR/secret"'
```

`/etc/systemd/system/paste-backup.timer`:

```ini
[Unit]
Description=Daily Everlyce paste backup

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now paste-backup.timer
```

If you still want a snapshot immediately before start, this is the line, and
it is not recommended as the only copy:

```ini
# ExecStartPre=/usr/bin/sqlite3 /var/lib/paste/paste.db ".backup /var/backups/paste/paste-prestart.db"
```

## Expired pastes, sessions, and audit_log

Expired pastes are not served: every read filters on `expires_at`. They still
occupy pages until something deletes the row.

Two deleters run in the service, and neither one prints or returns paste
content:

- On each request, at most once per `PASTE_SWEEP_INTERVAL_MS` (default 60s).
- On startup, and again on that same interval, even when the site is quiet.
  A zero interval disables the timer. The request-path sweep still runs, and
with a zero interval it runs on every request because that path uses the same
number as its throttle.

Both delete expired pastes and expired sessions. `node --no-warnings scripts/maintain.js sweep` does the same thing once, from a shell. `stats` prints counts and the file size only.

`audit_log` is append-only. The sweeper does not update or delete it, and
`maintain.js` has no command that does. It grows by one row per privileged
action (password reset, export, account deletion, admin grant). That is small
next to paste bodies, but it is unbounded.

To reclaim free pages after a large sweep:

```bash
node --no-warnings scripts/maintain.js vacuum
```

`VACUUM` rewrites the database and takes a write lock for the duration. Run
it while the site is quiet, or stop the service first. It does not delete
rows by itself.

To archive audit history, do it on a **backup**, not as a cron on the live
file. `at` is Unix epoch milliseconds.

```bash
sqlite3 /var/backups/paste/paste.db "DELETE FROM audit_log WHERE at < (strftime('%s','now') - 365*24*3600) * 1000; VACUUM;"
```

Keep the live log. It is the record that a compromised admin session still
leaves a trail. Shrinking it on the running database throws that away.

## Cloudflare origin lock

The app binds `127.0.0.1` only. nginx is the public listener. The vhost
trusts `CF-Connecting-IP` only when the TCP peer is in Cloudflare's published
ranges, so a client that hits the origin directly cannot spoof that header to
escape rate limits.

That does not stop the direct connection. The origin IP is public, and anyone
can open `http://<origin>/` and reach nginx. That is the current posture,
shared with the other `everlyce.com` vhosts on this box because they share
`:80` and `:443`.

Closing it means: packets to those two ports are accepted only from
Cloudflare, plus whatever you still need for Let's Encrypt and for SSH (SSH
is not on 80 or 443 and is unaffected).

**Every other vhost on the same listeners has to move at the same time.**
A site on this box that is *not* behind Cloudflare will go dark the moment
the firewall drops non-Cloudflare sources on `:80` and `:443`. There is no
per-vhost exception at the firewall, because the listeners are shared. Do
the nginx `allow`/`deny` form only if you are certain every `server` block
on those ports includes it; a block that forgets the include stays open and
the ones that have it close. The firewall is the version that cannot be
forgotten per vhost.

Certificate renewal via `certbot --webroot` writes a file and does not need
an inbound connection from Let's Encrypt to a non-Cloudflare path, as long
as Cloudflare still proxies `/.well-known/acme-challenge/` to the origin.
Confirm that before you drop the rest of the internet.

### Refresh the ranges

Cloudflare publishes the lists and changes them. Do not paste a snapshot
into the unit and forget it.

- <https://www.cloudflare.com/ips-v4>
- <https://www.cloudflare.com/ips-v6>

```bash
curl -fsSL https://www.cloudflare.com/ips-v4 -o /etc/nginx/cloudflare-ips-v4
curl -fsSL https://www.cloudflare.com/ips-v6 -o /etc/nginx/cloudflare-ips-v6
```

Re-fetch on a timer (weekly is enough) and reload nginx or nftables afterwards.

### Firewall (covers every vhost at once)

`/usr/local/sbin/cloudflare-origin-lock`, run as root after each refresh:

```bash
#!/bin/sh
# Accept tcp/80 and tcp/443 only from Cloudflare's current published ranges.
# Drops everyone else, including clients of any other vhost on those ports.
# Does not touch SSH or 127.0.0.1:8790.
set -eu
v4=$(mktemp)
v6=$(mktemp)
trap 'rm -f "$v4" "$v6"' EXIT
curl -fsSL https://www.cloudflare.com/ips-v4 > "$v4"
curl -fsSL https://www.cloudflare.com/ips-v6 > "$v6"
{
  echo 'table inet cloudflare_origin {'
  echo '  set cf_v4 { type ipv4_addr; flags interval; elements = {'
  paste -sd, "$v4"
  echo '  } }'
  echo '  set cf_v6 { type ipv6_addr; flags interval; elements = {'
  paste -sd, "$v6"
  echo '  } }'
  echo '  chain input {'
  echo '    type filter hook input priority -10; policy accept;'
  echo '    tcp dport { 80, 443 } ip saddr != @cf_v4 drop'
  echo '    tcp dport { 80, 443 } ip6 saddr != @cf_v6 drop'
  echo '  }'
  echo '}'
} > /etc/nftables.d/cloudflare-origin.nft
nft -f /etc/nftables.d/cloudflare-origin.nft
```

`policy accept` leaves SSH and other ports alone. Only 80 and 443 gain the
extra drop. Loopback clients never hit the input hook, so local health
checks to nginx still work. If this host's nftables is already a single
table you manage by hand, fold the two sets and the two drop rules into
that table instead of loading a second one.

Apply only after the other vhosts are orange-clouded (proxied) in DNS.
Until then, leave the firewall open and rely on the `CF-Connecting-IP`
range check, which is already in the vhost.

### nginx allow/deny (per server block)

Use this only when every `server` that listens on 80 or 443 gets the same
include. A block without it remains reachable from the open internet.

`/etc/nginx/conf.d/cloudflare-allow.conf` is generated, not written by hand:

```bash
{
  echo '# generated from https://www.cloudflare.com/ips-v4 and ips-v6'
  while read -r cidr; do
    [ -n "$cidr" ] && echo "allow $cidr;"
  done < /etc/nginx/cloudflare-ips-v4
  while read -r cidr; do
    [ -n "$cidr" ] && echo "allow $cidr;"
  done < /etc/nginx/cloudflare-ips-v6
  echo 'deny all;'
} > /etc/nginx/cloudflare-allow.conf
nginx -t && systemctl reload nginx
```

Inside **each** `server` block that listens on 80 or 443:

```nginx
include /etc/nginx/cloudflare-allow.conf;
```

Put the include before `location` blocks. `deny all` answers 403 from nginx,
which still accepts the TCP connection; the firewall version never accepts
it. Prefer the firewall if the goal is "the origin IP does not speak HTTP
to the rest of the internet".

After either change, from a non-Cloudflare network `curl --resolve paste.everlyce.com:443:<origin-ip> https://paste.everlyce.com/` should fail, and the same request through the public Cloudflare name should succeed.

## Captcha

One provider is active. The default is the built-in proof of work. There is
no second captcha beside it.

| `PASTE_CAPTCHA` | Behaviour |
| --- | --- |
| unset, and no Turnstile secret | proof of work |
| `pow` | proof of work, even if Turnstile variables are set |
| `turnstile` | Turnstile. Also selected automatically when `PASTE_TURNSTILE_SECRET` is set and `PASTE_CAPTCHA` is unset |
| `none` | honeypot and the signup rate limit only |

Switch to Turnstile by setting both of these and restarting. Do not invent
another widget.

```bash
# in the service environment, not in the repository
PASTE_TURNSTILE_SECRET=...
PASTE_TURNSTILE_SITE_KEY=...
# optional; implied by the secret when PASTE_CAPTCHA is unset
PASTE_CAPTCHA=turnstile
```

The site key is public and rendered into the signup page. The secret is not.
Verification is a server-side call to Cloudflare. If that call fails (network,
timeout), the honeypot result stands and the signup rate limit is what still
applies — failing closed would lock registration during a Cloudflare outage.

Proof of work stays available by unsetting those two variables, or by setting
`PASTE_CAPTCHA=pow`, and restarting.

A solved proof-of-work challenge is remembered in this process and rejected
on replay until restart. The memory is not shared across processes and is
not written to SQLite. After a restart, a captured solution still works
until its own 15-minute timestamp expires. A client that can mint new
solutions is unaffected; the per-IP signup limit is the backstop, as before.

## Brand restart checklist

`BRAND_VERSION` in `src/views.js` and the `?v=` query in
`public/branding/site.webmanifest` are the same number. Bump both when
`brand/` changes, rebuild `public/branding/`, then restart.

On startup the process re-reads `src/views.js` and the manifest from disk
and compares them to the `BRAND_VERSION` it already loaded:

- They match: one info line, including a reminder that the next change still
  needs a restart. The inlined header mark and the brand-asset cache are
  filled for the life of the process.
- Disk `BRAND_VERSION` differs from the loaded one: a warning that this
  process keeps serving the old mark until restart. Reloading the files
  does not change what this process serves.
- The manifest `?v=` differs from the loaded version: a warning that the
  page and the edge icons will disagree until both numbers match and the
  service restarts.

The check logs and continues. A mismatch does not stop the process and does
not change responses.

There is no dark theme. Do not add one to make a brand change visible;
restart is the mechanism.
