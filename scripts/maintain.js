'use strict';

/*
 * Operator maintenance for the SQLite file. Counts and expiry only.
 *
 *   node --no-warnings scripts/maintain.js stats
 *   node --no-warnings scripts/maintain.js sweep
 *   node --no-warnings scripts/maintain.js vacuum
 *
 * stats and sweep never print paste content, filenames, or ids. sweep deletes
 * expired pastes and expired sessions. It does not delete audit_log rows;
 * that table is append-only. vacuum rewrites the file to reclaim free pages
 * and can block writers for the length of the rewrite — run it in a quiet
 * window, not from the request path.
 *
 * Archiving old audit rows is a manual step on a backup, documented in
 * docs/ops.md. This script will not do it.
 */

const config = require('../src/config');
const { Store } = require('../src/store');

function printStats(stats) {
  console.log(`pastes=${stats.pastes}`);
  console.log(`expired_pastes=${stats.expiredPastes}`);
  console.log(`sessions=${stats.sessions}`);
  console.log(`audit_rows=${stats.auditRows}`);
  console.log(`bytes=${stats.bytes}`);
  console.log(`freelist_pages=${stats.freelist}`);
  console.log(`page_size=${stats.pageSize}`);
}

function main() {
  const command = process.argv[2];
  if (!command || command === 'help' || command === '--help') {
    console.log('usage:');
    console.log('  node --no-warnings scripts/maintain.js stats');
    console.log('  node --no-warnings scripts/maintain.js sweep');
    console.log('  node --no-warnings scripts/maintain.js vacuum');
    process.exit(command ? 0 : 1);
  }

  if (!['stats', 'sweep', 'vacuum'].includes(command)) {
    console.error(`unknown command: ${command}`);
    process.exit(1);
  }

  const store = new Store(config.dbPath);
  try {
    if (command === 'stats') {
      printStats(store.retentionStats());
      return;
    }
    if (command === 'sweep') {
      const removed = store.sweep();
      console.log(`removed_pastes=${removed.pastes}`);
      console.log(`removed_sessions=${removed.sessions}`);
      printStats(store.retentionStats());
      return;
    }
    store.db.exec('VACUUM');
    console.log('vacuum=ok');
    printStats(store.retentionStats());
  } finally {
    store.close();
  }
}

main();
