'use strict';

const crypto = require('node:crypto');
const config = require('./config');
const { Store } = require('./store');
const { createApp, makeSecrets } = require('./app');
const legal = require('./legal');

function start() {
  const store = new Store(config.dbPath);

  // Seeds operator details and the legal documents on first boot only; an
  // administrator's later edits are never overwritten.
  const { seeded, settings, refreshed } = legal.seed(store);
  if (seeded.length > 0 && refreshed.length > 0) {
    console.log(`[paste] legal documents updated to version ${legal.DOCS_VERSION}; previous copies kept as backup_doc_*`);
  }
  // Purges values for placeholders that have been retired from the documents,
  // so an address or registration number cannot linger in the database.
  const { removed } = legal.syncDocuments(store);
  if (removed.length > 0) {
    console.log(`[paste] retired operator field(s) removed: ${removed.join(', ')}`);
  }
  const outstanding = legal.requiredTokens(settings);
  if (seeded.length > 0) {
    console.log(`[paste] seeded ${seeded.length} legal/operator setting(s)`);
  }
  if (outstanding.length > 0) {
    console.warn(
      `[paste] operator details not filled in yet: ${outstanding.join(', ')}. ` +
        'Set them in the admin panel at /admin/settings before relying on the legal pages.',
    );
  }

  const secrets = makeSecrets();

  if (store.setupNeeded()) {
    // No token: the page is open until somebody claims it. Worth shouting
    // about, because whoever gets there first becomes the administrator.
    const rule = '-'.repeat(60);
    console.log(`[paste] ${rule}`);
    console.log('[paste] SETUP PENDING: no administrator exists yet.');
    console.log(`[paste] Create one at  ${config.publicOrigin}/setup`);
    console.log('[paste] That page is OPEN to anyone until it is done, and the first');
    console.log('[paste] person to complete it becomes the administrator.');
    console.log('[paste] It returns 404 from then on.');
    console.log(`[paste] ${rule}`);
  }

  const { handler, createLimiters, readLimiter, signupLimiter, loginLimiter, adminLimiter } = createApp({ store, secrets });

  const server = require('node:http').createServer((req, res) => {
    handler(req, res).catch((err) => {
      console.error('[paste] handler rejected:', err);
      if (!res.writableEnded) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('internal error');
      }
    });
  });

  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.keepAliveTimeout = 15_000;

  // Pastes are read-only for anyone holding the URL, so give slow clients a
  // bounded window rather than letting a stalled read hold a socket forever.
  server.setTimeout(30_000);

  server.on('error', (err) => {
    console.error('[paste] server error:', err.message);
    process.exit(1);
  });

  // Promotes configured admins on every boot. Idempotent, and it only ever
  // grants, never revokes, so a transient config cannot strip access.
  const promoted = store.syncAdmins(config.admins);
  if (promoted.length > 0) {
    console.log(`[paste] promoted to admin: ${promoted.join(', ')}`);
    for (const name of promoted) store.audit({ actorName: 'boot', action: 'admin.grant', target: name });
  }
  if (config.admins.length > 0 && store.adminCount() === 0) {
    console.warn(
      `[paste] PASTE_ADMINS is set to ${config.admins.join(', ')} but none of those accounts exist yet. ` +
        'Sign up with that username, then restart, or run scripts/admin.js grant.',
    );
  }

  server.listen(config.port, config.host, () => {
    console.log(`[paste] listening on http://${config.host}:${config.port} -> ${config.publicOrigin}`);
    console.log(`[paste] admins: ${store.adminCount()} of ${store.userCount()} account(s)`);
    console.log(`[paste] db=${config.dbPath}`);
    console.log(
      `[paste] paste limit anonymous=${config.tiers.anonymous.maxPasteBytes}B ` +
        `account=${config.tiers.account.maxPasteBytes}B`,
    );
  });

  const shutdown = (signal) => {
    console.log(`[paste] ${signal} received, draining`);
    for (const limiter of [...Object.values(createLimiters), readLimiter, signupLimiter, loginLimiter, adminLimiter]) {
      limiter.stop();
    }
    server.close(() => {
      try {
        store.close();
      } catch {
        /* already closed */
      }
      process.exit(0);
    });
    // Do not hang forever on keep-alive connections.
    setTimeout(() => process.exit(0), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (err) => console.error('[paste] unhandled rejection:', err));
}

start();