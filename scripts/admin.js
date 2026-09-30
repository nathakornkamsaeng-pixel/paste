'use strict';

/*
 * Grants or revokes admin on an existing account.
 *
 *   node --no-warnings scripts/admin.js grant  everlyce
 *   node --no-warnings scripts/admin.js revoke everlyce
 *   node --no-warnings scripts/admin.js list
 *
 * Granting is the supported way to bootstrap the first admin on a box where
 * PASTE_ADMINS is not set. Prefer PASTE_ADMINS in the unit file: it re-applies
 * on every boot, so a database restore cannot silently leave you with no admin.
 */

const config = require('../src/config');
const { Store } = require('../src/store');
const auth = require('../src/auth');

/** Reads one line from stdin. TTY input is echoed-hidden where possible. */
function readPassword() {
  const fs = require('node:fs');
  const buffer = Buffer.alloc(512);
  try {
    fs.readSync(0, buffer, 0, 512, null);
    return buffer.toString('utf8').split('\n')[0].trim();
  } catch {
    return '';
  }
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === 'help' || command === '--help') {
    console.log('usage:');
    console.log('  node --no-warnings scripts/admin.js list');
    console.log('  printf \'%s\\n\' <password> | node --no-warnings scripts/admin.js create <username>');
    console.log('  node --no-warnings scripts/admin.js grant <username>');
    console.log('  node --no-warnings scripts/admin.js revoke <username>');
    process.exit(command ? 0 : 1);
  }

  const username = rest[0];
  if (!['list', 'help'].includes(command) && !username) {
    console.error('a username is required');
    process.exit(1);
  }

  const store = new Store(config.dbPath);

  try {
    if (command === 'create') {
      // Password comes from stdin so it never appears in the process list.
      const password = await readPassword();
      const problem = auth.validatePassword(password);
      if (problem) {
        console.error(problem);
        process.exit(1);
      }
      if (store.findUserByUsername(username)) {
        console.error(`already exists: ${username}`);
        process.exit(1);
      }
      const user = store.createUser(username, auth.hash(password));
      store.db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(user.id);
      store.setSettings({ setup_claimed: '1', setup_token_hash: '' });
      store.audit({ actorName: 'cli', action: 'admin.create', target: user.username });
      console.log(`${user.username} created and is now an admin`);
      process.exit(0);
    }

    if (command === 'list') {
      const users = store.listUsers({ limit: 200 });
      if (users.length === 0) {
        console.log('no accounts yet');
      } else {
        for (const user of users) {
          console.log(
            `${user.is_admin ? '[admin] ' : '        '} #${user.id} ${user.username}` +
              `  pastes=${user.pastes} bytes=${user.bytes} joined=${new Date(user.created_at).toISOString()}`,
          );
        }
      }
      process.exit(0);
    }

    const user = store.findUserByUsername(username);
    if (!user) {
      console.error(`no such user: ${username}`);
      process.exit(1);
    }

    if (command === 'grant') {
      if (user.is_admin) {
        console.log(`${user.username} is already an admin`);
      } else {
        store.db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(user.id);
        store.audit({ actorName: 'cli', action: 'admin.grant', target: user.username });
        console.log(`${user.username} is now an admin`);
      }
    } else if (command === 'revoke') {
      // Refuse to remove the last admin, which would lock everyone out of the
      // panel with no in-app way back in.
      if (user.is_admin && store.adminCount() <= 1) {
        console.error('refusing to revoke the only admin; grant another first');
        process.exit(1);
      }
      if (!user.is_admin) {
        console.log(`${user.username} is not an admin`);
      } else {
        store.db.prepare('UPDATE users SET is_admin = 0 WHERE id = ?').run(user.id);
        store.audit({ actorName: 'cli', action: 'admin.revoke', target: user.username });
        console.log(`${user.username} is no longer an admin`);
      }
    } else {
      console.error(`unknown command: ${command}`);
      process.exit(1);
    }

    process.exit(0);
  } finally {
    store.close();
  }
}

main();