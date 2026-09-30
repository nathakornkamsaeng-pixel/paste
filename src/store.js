'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const config = require('./config');

// Crockford-ish alphabet: no I, l, O or 0, so an id read off a screen or
// retyped by hand is much less likely to be misread than with base62.
const ID_ALPHABET = '123456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
const ID_LENGTH = 8;

const SCRYPT_KEYLEN = 32;

function newId() {
  // randomBytes can in principle return a value >= 256**1 with a single byte
  // masked off, so rejection-sample rather than modulo to keep ids uniform.
  const out = [];
  while (out.length < ID_LENGTH) {
    for (const byte of crypto.randomBytes(ID_LENGTH * 2)) {
      if (out.length === ID_LENGTH) break;
      if (byte < 256 - (256 % ID_ALPHABET.length)) {
        out.push(ID_ALPHABET[byte % ID_ALPHABET.length]);
      }
    }
  }
  return out.join('');
}

/** Hex SHA-256, so it can be stored directly in a TEXT column. */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('hex');
}

/**
 * Constant-time comparison that does not leak the length of either side: both
 * values are hashed to a fixed 32 bytes first, then compared.
 */
function tokenMatches(candidate, expected) {
  if (typeof candidate !== 'string' || candidate.length === 0) return false;
  if (typeof expected !== 'string' || expected.length === 0) return false;
  const a = Buffer.from(hashToken(candidate), 'hex');
  const b = Buffer.from(hashToken(expected), 'hex');
  return crypto.timingSafeEqual(a, b);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString('base64')}$${derived.toString('base64')}`;
}

function verifyPassword(password, stored) {
  if (typeof password !== 'string' || password.length === 0) return false;
  if (typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  let salt;
  let expected;
  try {
    salt = Buffer.from(parts[1], 'base64');
    expected = Buffer.from(parts[2], 'base64');
  } catch {
    return false;
  }
  if (expected.length !== SCRYPT_KEYLEN) return false;
  const actual = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  return crypto.timingSafeEqual(actual, expected);
}

class Store {
  constructor(dbPath = config.dbPath) {
    if (dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);

    // WAL keeps readers from blocking on the writer, and NORMAL sync is the
    // right trade-off here: a lost paste after a hard power cut is acceptable,
    // a corrupt database is not.
    if (dbPath !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = NORMAL');
    this.db.exec('PRAGMA foreign_keys = ON');
    this.db.exec('PRAGMA busy_timeout = 5000');

    // Append-only record of privileged actions. Never updated or deleted, so a
    // compromised admin session still leaves a trail.
    // Operator and legal-document settings. Values are plain text so they stay
    // inspectable and exportable; nothing here is a secret.
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL
      ) STRICT;
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY,
        at         INTEGER NOT NULL,
        actor_id   INTEGER,
        actor_name TEXT NOT NULL,
        action     TEXT NOT NULL,
        target     TEXT,
        detail     TEXT,
        ip         TEXT
      ) STRICT;
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS pastes (
        id            TEXT PRIMARY KEY,
        content       TEXT NOT NULL,
        filename      TEXT,
        language      TEXT,
        created_at    INTEGER NOT NULL,
        expires_at    INTEGER,
        burn          INTEGER NOT NULL DEFAULT 0,
        views         INTEGER NOT NULL DEFAULT 0,
        edit_token    TEXT NOT NULL,
        password_hash TEXT,
        owner_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        visibility    TEXT NOT NULL DEFAULT 'public',
        edited_at     INTEGER
      ) STRICT;
    `);

    // Users are created before pastes because pastes reference them. SQLite
    // tolerates the reverse at DDL time, but with foreign_keys=ON only the
    // dependency order is actually correct.
    //
    // username_lower is what uniqueness is enforced on, so "Alice" and
    // "alice" cannot both register.
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id             INTEGER PRIMARY KEY,
        username       TEXT NOT NULL,
        username_lower TEXT NOT NULL UNIQUE,
        password_hash  TEXT NOT NULL,
        created_at     INTEGER NOT NULL,
        disabled       INTEGER NOT NULL DEFAULT 0
      ) STRICT;
    `);

    // Only the SHA-256 of a session token is stored, so a database leak does
    // not hand out live sessions. csrf_token is per-session and random.
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id           TEXT PRIMARY KEY,
        token_hash   TEXT NOT NULL UNIQUE,
        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token   TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        expires_at   INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL
      ) STRICT;
    `);

    this.migrate();

    // recent-list and sweep queries both filter on these.
    this.db.exec('CREATE INDEX IF NOT EXISTS pastes_created_at ON pastes (created_at DESC)');
    this.db.exec('CREATE INDEX IF NOT EXISTS pastes_expires_at ON pastes (expires_at) WHERE expires_at IS NOT NULL');
    this.db.exec('CREATE INDEX IF NOT EXISTS pastes_owner ON pastes (owner_id, created_at DESC)');
    this.db.exec('CREATE INDEX IF NOT EXISTS sessions_token_hash ON sessions (token_hash)');
    this.db.exec('CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at DESC)');
  }

  /**
   * Adds columns introduced after the first release. SQLite has no
   * ADD COLUMN IF NOT EXISTS, so this checks pragma table_info first. Written
   * to be safe to run on every boot.
   */
  migrate() {
    const wanted = [
      ['pastes', 'owner_id', 'INTEGER REFERENCES users(id) ON DELETE SET NULL'],
      ['pastes', 'visibility', "TEXT NOT NULL DEFAULT 'public'"],
      ['pastes', 'edited_at', 'INTEGER'],
      ['users', 'is_admin', 'INTEGER NOT NULL DEFAULT 0'],
      ['users', 'must_change_password', 'INTEGER NOT NULL DEFAULT 0'],
    ];
    for (const [table, column, definition] of wanted) {
      const cols = this.db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
      if (cols.length === 0) continue;
      if (!cols.includes(column)) {
        this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
      }
    }
  }

  close() {
    this.db.close();
  }

  /**
   * @param {object} paste
   * @param {string} paste.content
   * @param {string|null} [paste.filename]
   * @param {string|null} [paste.language]
   * @param {number|null} [paste.ttlMs] absolute lifetime in ms, null = never
   * @param {boolean} [paste.burn]
   * @param {string|null} [paste.password]
   * @param {number|null} [paste.ownerId]
   * @param {'public'|'unlisted'} [paste.visibility]
   * @returns {{id: string, editToken: string, createdAt: number, expiresAt: number|null}}
   */
  create(paste) {
    const content = paste.content;
    const now = Date.now();
    const expiresAt = Number.isFinite(paste.ttlMs) ? now + paste.ttlMs : null;

    // 8 attempts is far beyond any realistic collision chance, but a unique
    // constraint violation here would be a 500 for the user, so retry anyway.
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const id = newId();
      const editToken = crypto.randomBytes(32).toString('base64url');
      try {
        this.db
          .prepare(
            `INSERT INTO pastes
               (id, content, filename, language, created_at, expires_at, burn, edit_token,
                password_hash, owner_id, visibility)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            id,
            content,
            paste.filename ?? null,
            paste.language ?? null,
            now,
            expiresAt,
            paste.burn ? 1 : 0,
            editToken,
            paste.password ? hashPassword(paste.password) : null,
            paste.ownerId ?? null,
            paste.visibility === 'unlisted' ? 'unlisted' : 'public',
          );
        return { id, editToken, createdAt: now, expiresAt };
      } catch (err) {
        const isCollision =
          err && typeof err.message === 'string' && err.message.includes('UNIQUE constraint failed');
        if (!isCollision) throw err;
      }
    }
    throw new Error('could not allocate a unique paste id');
  }

  /** Rows that have passed their expiry are treated as if they never existed. */
  isLive(row, now = Date.now()) {
    return Boolean(row) && (row.expires_at === null || row.expires_at > now);
  }

  /**
   * Fetch a paste for viewing.
   *
   * Burn-after-read pastes are fetched with DELETE ... RETURNING, which is a
   * single atomic statement: exactly one concurrent reader can ever observe
   * the row, so a burn paste cannot be read twice under a race.
   */
  claim(id, { consume = false } = {}) {
    if (!validId(id)) return null;
    const now = Date.now();

    if (consume) {
      const row = this.db
        .prepare(
          `DELETE FROM pastes
            WHERE id = ? AND burn = 1 AND (expires_at IS NULL OR expires_at > ?)
            RETURNING id, content, filename, language, created_at, expires_at, burn, views, password_hash`,
        )
        .get(id, now);
      if (row) return { ...row, burned: true };
      // Either it does not exist or it is not a burn paste; fall through so a
      // non-burn paste can still be served after a stale burn claim.
    }

    const row = this.db
      .prepare(
        `UPDATE pastes
            SET views = views + 1
          WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)
          RETURNING id, content, filename, language, created_at, expires_at, burn, views, password_hash`,
      )
      .get(id, now);

    if (!row) return null;
    if (row.burn) return { ...row, burned: true };
    return row;
  }

  /**
   * Metadata lookup, used to answer "is there a password?" and to re-derive
   * session tokens without serving the content or counting a view.
   *
   * edit_token is selected because the app derives its session secrets from
   * it. It never leaves the server: no route returns this row to a client.
   */
  peek(id) {
    if (!validId(id)) return null;
    const row = this.db
      .prepare(
        `SELECT id, filename, language, created_at, expires_at, burn, views, edit_token,
                password_hash, owner_id
           FROM pastes
          WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)`,
      )
      .get(id, Date.now());
    return row ?? null;
  }

  /**
   * Public listing for /recent.
   *
   * Burn-after-read, password-protected and unlisted pastes are deliberately
   * excluded: they are private-by-link, and listing a burn paste would let any
   * visitor destroy it by opening the page, while listing a locked one would
   * disclose its filename. Those remain reachable only by direct link.
   */
  recent(limit = config.recentLimit) {
    const capped = Math.max(1, Math.min(limit, 200));
    return this.db
      .prepare(
        `SELECT id, filename, language, created_at, expires_at, burn, views,
                CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END AS protected
           FROM pastes
          WHERE (expires_at IS NULL OR expires_at > ?)
            AND burn = 0
            AND password_hash IS NULL
            AND visibility = 'public'
          ORDER BY created_at DESC
          LIMIT ?`,
      )
      .all(Date.now(), capped);
  }

  count() {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM pastes').get();
    return row ? Number(row.n) : 0;
  }

  deleteWithToken(id, token) {
    if (!validId(id)) return false;
    const row = this.db.prepare('SELECT edit_token FROM pastes WHERE id = ?').get(id);
    if (!row) return false;
    if (!tokenMatches(token, row.edit_token)) return false;
    this.db.prepare('DELETE FROM pastes WHERE id = ?').run(id);
    return true;
  }

  /** Purges expired rows. Safe to call concurrently from several processes. */
  sweep(now = Date.now()) {
    const info = this.db
      .prepare('DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at <= ?')
      .run(now);
    let purgedSessions = 0;
    try {
      const s = this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
      purgedSessions = Number(s.changes ?? 0);
    } catch {
      // A pre-accounts database has no sessions table yet.
    }
    return Number(info.changes ?? 0) + purgedSessions;
  }

  /* ------------------------------------------------------------ accounts */

  findUserByUsername(username) {
    if (typeof username !== 'string') return null;
    const row = this.db
      .prepare('SELECT id, username, username_lower, password_hash, created_at, disabled, is_admin, must_change_password FROM users WHERE username_lower = ?')
      .get(username.trim().toLowerCase());
    return row ?? null;
  }

  getUser(id) {
    if (!Number.isInteger(id)) return null;
    const row = this.db
      .prepare('SELECT id, username, username_lower, password_hash, created_at, disabled, is_admin, must_change_password FROM users WHERE id = ?')
      .get(id);
    return row ?? null;
  }

  createUser(username, passwordHash) {
    const now = Date.now();
    const trimmed = username.trim();
    const info = this.db
      .prepare('INSERT INTO users (username, username_lower, password_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(trimmed, trimmed.toLowerCase(), passwordHash, now);
    return { id: Number(info.lastInsertRowid), username: trimmed, createdAt: now };
  }

  updatePassword(userId, passwordHash) {
    this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, userId);
  }

  /** Invalidates every session for a user. Used on password change. */
  deleteSessionsForUser(userId) {
    const info = this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    return Number(info.changes ?? 0);
  }

  createSession(userId, ttlMs) {
    const raw = crypto.randomBytes(32).toString('base64url');
    const id = crypto.randomHash ? crypto.randomUUID() : newId();
    const csrf = crypto.randomBytes(24).toString('base64url');
    const now = Date.now();
    const expiresAt = now + ttlMs;

    this.db
      .prepare(
        `INSERT INTO sessions (id, token_hash, user_id, csrf_token, created_at, expires_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(id, hashToken(raw), userId, csrf, now, expiresAt, now);

    return { token: raw, csrfToken: csrf, expiresAt, userId };
  }

  /**
   * Resolves a session token to its user. Returns null for anything unknown,
   * expired, or belonging to a disabled account.
   */
  resolveSession(rawToken) {
    if (typeof rawToken !== 'string' || rawToken.length < 20) return null;
    const now = Date.now();
    const row = this.db
      .prepare(
        `SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.user_id,
                u.username, u.username_lower, u.disabled, u.is_admin, u.must_change_password
           FROM sessions s
           JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = ?`,
      )
      .get(hashToken(rawToken));

    if (!row) return null;
    if (row.expires_at <= now) {
      this.db.prepare('DELETE FROM sessions WHERE id = ?').run(row.session_id);
      return null;
    }
    if (row.disabled) return null;

    return {
      sessionId: row.session_id,
      userId: row.user_id,
      username: row.username,
      isAdmin: Boolean(row.is_admin),
      // Set when an admin reset this account's password. While it stands, the
      // app allows nothing except changing the password.
      mustChangePassword: Boolean(row.must_change_password),
      csrfToken: row.csrf_token,
      expiresAt: row.expires_at,
    };
  }

  touchSession(sessionId, now = Date.now()) {
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now, sessionId);
  }

  destroySession(rawToken) {
    if (typeof rawToken !== 'string' || rawToken.length < 20) return false;
    const info = this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(rawToken));
    return Number(info.changes ?? 0) > 0;
  }

  userCount() {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM users').get();
    return row ? Number(row.n) : 0;
  }

  /* --------------------------------------------------------------- admin */

  /**
   * Makes the named users admins. Idempotent, so this runs on every boot.
   *
   * Driven by configuration rather than a flag on the registration form:
   * self-promotion is the classic way an admin panel ends up owned by whoever
   * registered a name first.
   */
  syncAdmins(usernames) {
    const wanted = (Array.isArray(usernames) ? usernames : String(usernames || '').split(','))
      .map((name) => String(name || '').trim().toLowerCase())
      .filter(Boolean);

    const changed = [];
    for (const name of wanted) {
      const user = this.findUserByUsername(name);
      if (!user) continue;
      if (user.is_admin) continue;
      this.db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(user.id);
      changed.push(user.username);
    }
    return changed;
  }

  adminCount() {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1').get();
    return row ? Number(row.n) : 0;
  }

  isAdmin(userId) {
    if (!Number.isInteger(userId)) return false;
    const row = this.db.prepare('SELECT is_admin FROM users WHERE id = ?').get(userId);
    return Boolean(row?.is_admin);
  }

  /**
   * Account list for the admin view. `query` matches a username prefix or
   * substring; the LIMIT is capped so a wildcard query cannot pull the table.
   */
  listUsers({ query = '', limit = 100 } = {}) {
    const capped = Math.max(1, Math.min(limit, 200));
    const needle = `%${String(query || '').trim().toLowerCase()}%`;

    return this.db
      .prepare(
        `SELECT u.id, u.username, u.created_at, u.disabled, u.is_admin,
                (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions,
                (SELECT COUNT(*) FROM pastes p WHERE p.owner_id = u.id) AS pastes,
                (SELECT COALESCE(SUM(length(p.content)), 0) FROM pastes p WHERE p.owner_id = u.id) AS bytes
           FROM users u
          WHERE (? = '%%' OR lower(u.username) LIKE ?)
          ORDER BY u.created_at DESC
          LIMIT ?`,
      )
      .all(needle, needle, capped);
  }

  /** Includes is_admin; used before acting on an account. */
  getUserFull(id) {
    if (!Number.isInteger(id)) return null;
    const row = this.db
      .prepare(
        'SELECT id, username, username_lower, created_at, disabled, is_admin FROM users WHERE id = ?',
      )
      .get(id);
    return row ?? null;
  }

  /**
   * Deletes an account.
   *
   * `deletePastes` decides the fate of the user's content. Sessions go either
   * way via ON DELETE CASCADE, which also logs the target out everywhere.
   */
  deleteUser(id, { deletePastes = false } = {}) {
    const user = this.getUserFull(id);
    if (!user) return { ok: false, reason: 'not_found' };

    const pastes = this.db.prepare('SELECT COUNT(*) AS n FROM pastes WHERE owner_id = ?').get(id);
    const pasteCount = pastes ? Number(pastes.n) : 0;

    let removedPastes = 0;
    if (deletePastes) {
      const info = this.db.prepare('DELETE FROM pastes WHERE owner_id = ?').run(id);
      removedPastes = Number(info.changes ?? 0);
    }

    const info = this.db.prepare('DELETE FROM users WHERE id = ?').run(id);
    return { ok: Number(info.changes ?? 0) > 0, username: user.username, pasteCount, removedPastes };
  }

  /** Records a privileged action. Append-only. */
  audit({ actorId = null, actorName = 'system', action, target = null, detail = null, ip = null }) {
    this.db
      .prepare(
        `INSERT INTO audit_log (at, actor_id, actor_name, action, target, detail, ip)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(Date.now(), actorId, String(actorName), String(action), target, detail, ip);
  }

  recentAudit(limit = 50) {
    const capped = Math.max(1, Math.min(limit, 200));
    return this.db
      .prepare('SELECT at, actor_name, action, target, detail, ip FROM audit_log ORDER BY at DESC LIMIT ?')
      .all(capped);
  }

  auditCount() {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM audit_log').get();
    return row ? Number(row.n) : 0;
  }

  /* ------------------------------------------------------------ settings */

  getSettings() {
    const out = Object.create(null);
    for (const row of this.db.prepare('SELECT key, value FROM settings').all()) {
      out[row.key] = row.value;
    }
    return out;
  }

  setSettings(values) {
    const now = Date.now();
    const stmt = this.db.prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    );
    for (const [key, value] of Object.entries(values)) {
      // Key shape is constrained so a settings key can never be confused with a
      // column name or used to smuggle something into a query.
      if (!/^[a-z][a-z0-9_.]{0,63}$/.test(key)) continue;
      stmt.run(key, String(value ?? '').slice(0, 200_000), now);
    }
    return this.getSettings();
  }

  /** Removes a settings row entirely. */
  deleteSetting(key) {
    this.db.prepare('DELETE FROM settings WHERE key = ?').run(key);
  }

  /* --------------------------------------------------- account lifecycle */

  /**
   * Flags an account as needing a new password at next sign-in, and drops its
   * sessions so the reset takes effect immediately rather than whenever the
   * old session happens to expire.
   */
  requirePasswordChange(userId) {
    this.db.prepare('UPDATE users SET must_change_password = 1 WHERE id = ?').run(userId);
    const killed = this.deleteSessionsForUser(userId);
    return killed;
  }

  clearPasswordChange(userId) {
    this.db.prepare('UPDATE users SET must_change_password = 0 WHERE id = ?').run(userId);
  }

  mustChangePassword(userId) {
    if (!Number.isInteger(userId)) return false;
    const row = this.db.prepare('SELECT must_change_password FROM users WHERE id = ?').get(userId);
    return Boolean(row?.must_change_password);
  }

  /**
   * Everything we hold about one account, for the data-subject access and
   * portability requests. Content is included because it is the user's own;
   * this is exactly the kind of endpoint that must never be reachable for
   * somebody else's data, so it takes the user id as an argument rather than
   * reading it from the request.
   */
  exportUserData(userId) {
    const user = this.getUser(userId);
    if (!user) return null;

    const pastes = this.db
      .prepare(
        `SELECT id, filename, language, content, created_at, edited_at, expires_at,
                burn, views, visibility, length(content) AS bytes
           FROM pastes WHERE owner_id = ? ORDER BY created_at ASC`,
      )
      .all(userId);

    const sessions = this.db
      .prepare('SELECT created_at, last_seen_at, expires_at FROM sessions WHERE user_id = ?')
      .all(userId)
      // Token values are deliberately absent: they are secrets, not user data.
      .map((row) => ({ ...row }));

    return {
      exported_at: new Date().toISOString(),
      format: 'paste-account-export/1',
      account: {
        id: user.id,
        username: user.username,
        created_at: new Date(user.created_at).toISOString(),
        disabled: Boolean(user.disabled),
        is_admin: Boolean(user.is_admin),
        must_change_password: Boolean(user.must_change_password),
      },
      pastes: pastes.map((row) => ({
        ...row,
        created_at: row.created_at ? new Date(row.created_at).toISOString() : null,
        edited_at: row.edited_at ? new Date(row.edited_at).toISOString() : null,
        expires_at: row.expires_at ? new Date(row.expires_at).toISOString() : null,
      })),
      sessions,
      counts: { pastes: pastes.length, sessions: sessions.length },
    };
  }

  /**
   * Self-service erasure.
   *
   * Deletes the account and its sessions. The user's pastes are removed too:
   * leaving them behind would keep personal data attached to an identifier that
   * no longer has an owner to ask for its removal.
   */
  deleteAccount(userId) {
    const user = this.getUser(userId);
    if (!user) return { ok: false, reason: 'not_found' };
    if (user.is_admin && this.adminCount() <= 1) {
      return { ok: false, reason: 'last_admin' };
    }

    const pastes = this.db
      .prepare('SELECT COUNT(*) AS n FROM pastes WHERE owner_id = ?')
      .get(userId);
    const pasteCount = pastes ? Number(pastes.n) : 0;

    // Delete explicitly rather than leaning on the foreign key. That column is
    // ON DELETE SET NULL, which would leave the content in place, still
    // reachable by link and still attributed to an account that no longer
    // exists -- the opposite of what an erasure request is asking for.
    this.db.prepare('DELETE FROM pastes WHERE owner_id = ?').run(userId);

    const info = this.db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    return { ok: Number(info.changes ?? 0) > 0, username: user.username, pasteCount };
  }

  /* -------------------------------------------------------- first-run setup */

  /**
   * True only while this deployment has never had an administrator and the
   * claim has not been used.
   *
   * Once an admin exists the setup screen is permanently closed, so an account
   * cannot be bootstrapped later by whoever finds the route.
   */
  setupNeeded() {
    if (this.adminCount() > 0) return false;
    return this.getSettings().setup_claimed !== '1';
  }

  /** Creates the first administrator and closes setup for good. */
  claimSetup(username, passwordHash) {
    if (!this.setupNeeded()) return { ok: false, reason: 'closed' };
    const user = this.createUser(username, passwordHash);
    this.db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(user.id);
    this.setSettings({ setup_claimed: '1' });
    this.audit({ actorName: 'setup', action: 'admin.claim', target: user.username });
    return { ok: true, user: { id: user.id, username: user.username } };
  }

  /* ------------------------------------------------- paste ownership */

  /** Every paste belonging to a user, newest first. Content is not loaded. */
  listByOwner(userId, limit = 200) {
    const capped = Math.max(1, Math.min(limit, 500));
    return this.db
      .prepare(
        `SELECT id, filename, language, created_at, expires_at, burn, views, visibility, edited_at,
                length(content) AS size,
                CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END AS protected
           FROM pastes
          WHERE owner_id = ?
          ORDER BY created_at DESC
          LIMIT ?`,
      )
      .all(userId, capped);
  }

  /** Metadata for an owned paste, used to authorise edit/delete/unlist. */
  ownedMeta(id, userId) {
    if (!validId(id)) return null;
    const row = this.db
      .prepare(
        `SELECT id, filename, language, created_at, expires_at, burn, views, visibility, owner_id,
                edit_token, password_hash, length(content) AS size
           FROM pastes
          WHERE id = ? AND owner_id = ? AND (expires_at IS NULL OR expires_at > ?)`,
      )
      .get(id, userId, Date.now());
    return row ?? null;
  }

  /**
   * Replaces the content of an owned paste in place, keeping the same id and
   * URL. Burn pastes are excluded: by definition their content is already gone.
   */
  updateOwned(id, userId, { content, filename, language, ttlMs, password }) {
    if (!validId(id)) return false;
    const now = Date.now();
    const expiresAt = Number.isFinite(ttlMs) ? now + ttlMs : null;
    const info = this.db
      .prepare(
        `UPDATE pastes
            SET content = ?, filename = ?, language = ?, expires_at = ?,
                password_hash = ?, edited_at = ?
          WHERE id = ? AND owner_id = ? AND burn = 0
            AND (expires_at IS NULL OR expires_at > ?)`,
      )
      .run(
        content,
        filename ?? null,
        language ?? null,
        expiresAt,
        password ? hashPassword(password) : null,
        now,
        id,
        userId,
        now,
      );
    return Number(info.changes ?? 0) > 0;
  }

  setVisibility(id, userId, visibility) {
    if (!validId(id)) return false;
    const allowed = visibility === 'unlisted' ? 'unlisted' : 'public';
    const info = this.db
      .prepare('UPDATE pastes SET visibility = ? WHERE id = ? AND owner_id = ? AND burn = 0')
      .run(allowed, id, userId);
    return Number(info.changes ?? 0) > 0;
  }

  deleteOwned(id, userId) {
    if (!validId(id)) return false;
    const info = this.db.prepare('DELETE FROM pastes WHERE id = ? AND owner_id = ?').run(id, userId);
    return Number(info.changes ?? 0) > 0;
  }
}

function validId(id) {
  return typeof id === 'string' && id.length === ID_LENGTH && /^[0-9A-Za-z]+$/.test(id);
}

module.exports = { Store, validId, newId, tokenMatches, hashPassword, verifyPassword, ID_LENGTH };
