// User data access — port of src/UserRepository.php.
//
// C-SQL-1: every statement is ONE single-line literal with `?` placeholders.
// Statements are not split across lines with `+` and no fragment is assembled at
// call time — the control's source scan (docs/03) flags exactly that pattern
// under src/repositories/, so the literals are long on purpose. The searched and
// unsearched variants of `allUsers` are two separate statements for the same
// reason.
//
// C-SQL-3: a LIKE term is escaped for `%` and `_` before it is bound, so it can
// never widen into a wildcard. `vuln/sqli` removes this escape as a declared
// control change.

import { query, execute } from '../db/connection.js';
import { list } from '../config/env.js';
import { now, plusMs, sqlDateTime } from '../lib/clock.js';
import { hash } from '../security/passwords.js';

/** Escape LIKE metacharacters; the backslash is MariaDB's default escape char. */
export function escapeLike(term) {
  return String(term).replaceAll('%', '\\%').replaceAll('_', '\\_');
}

function normalizeEmail(email) {
  return String(email ?? '').trim().toLowerCase();
}

const SELECT_USER_BY_ID = 'SELECT id, username, email, password_hash, role, is_banned, ban_reason, avatar_path, mfa_enabled, created_at, updated_at FROM users WHERE id = ?';
const SELECT_USER_BY_EMAIL = 'SELECT id, username, email, password_hash, role, is_banned, ban_reason, avatar_path, mfa_enabled, created_at, updated_at FROM users WHERE email = ?';
const SELECT_USER_BY_USERNAME = 'SELECT id, username, email, password_hash, role, is_banned, ban_reason, avatar_path, mfa_enabled, created_at, updated_at FROM users WHERE username = ?';

export async function findById(id) {
  const rows = await query(SELECT_USER_BY_ID, [id]);
  return rows[0] ?? null;
}

export async function findByEmail(email) {
  const rows = await query(SELECT_USER_BY_EMAIL, [normalizeEmail(email)]);
  return rows[0] ?? null;
}

export async function findByUsername(username) {
  const rows = await query(SELECT_USER_BY_USERNAME, [String(username)]);
  return rows[0] ?? null;
}

/**
 * Role is elevated to `admin` when the email appears in ADMIN_EMAILS — admins
 * are defined in .env, never by a form field (docs/03 C-ASSIGN-1, C-ACL-2).
 */
export async function create(username, email, password) {
  const address = normalizeEmail(email);
  const admins = list('ADMIN_EMAILS').map((entry) => entry.toLowerCase());
  const role = admins.includes(address) ? 'admin' : 'user';

  await execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', [
    String(username),
    address,
    await hash(password),
    role,
  ]);

  const created = await findByEmail(address);
  if (created === null) throw new Error('User creation failed');
  return created;
}

const SELECT_ALL_USERS = 'SELECT u.id, u.username, u.email, u.role, u.is_banned, u.ban_reason, u.avatar_path, u.mfa_enabled, u.created_at, u.updated_at, (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id AND p.deleted_at IS NULL) AS post_count FROM users u ORDER BY u.created_at DESC LIMIT 500';
const SELECT_USERS_SEARCH = 'SELECT u.id, u.username, u.email, u.role, u.is_banned, u.ban_reason, u.avatar_path, u.mfa_enabled, u.created_at, u.updated_at, (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id AND p.deleted_at IS NULL) AS post_count FROM users u WHERE u.username LIKE ? OR u.email LIKE ? ORDER BY u.created_at DESC LIMIT 500';

export async function allUsers(search = '') {
  if (search === '') return query(SELECT_ALL_USERS);
  const like = `%${escapeLike(search)}%`;
  return query(SELECT_USERS_SEARCH, [like, like]);
}

export async function setMfaEnabled(userId, enabled) {
  await execute('UPDATE users SET mfa_enabled = ? WHERE id = ?', [enabled ? 1 : 0, userId]);
}

/** Admin accounts can never be banned through this path (docs/02 B22). */
export async function setBanned(userId, banned, reason = null) {
  await execute("UPDATE users SET is_banned = ?, ban_reason = ? WHERE id = ? AND role != 'admin'", [
    banned ? 1 : 0,
    reason,
    userId,
  ]);
}

export async function updatePassword(userId, newPassword) {
  await execute('UPDATE users SET password_hash = ? WHERE id = ?', [await hash(newPassword), userId]);
}

/** The stored avatar filename (a generated name; never a client path). */
export async function setAvatarPath(userId, path) {
  return execute('UPDATE users SET avatar_path = ? WHERE id = ?', [path, userId]);
}

export async function setEmail(userId, email) {
  if ((await findByEmail(email)) !== null) return false;
  await execute('UPDATE users SET email = ? WHERE id = ?', [normalizeEmail(email), userId]);
  return true;
}

export async function ensureAdminRolesFromEnv() {
  let changed = 0;
  for (const address of list('ADMIN_EMAILS')) {
    const user = await findByEmail(address);
    if (user !== null && user.role !== 'admin') {
      await execute("UPDATE users SET role = 'admin' WHERE id = ?", [user.id]);
      changed += 1;
    }
  }
  return changed;
}

/** Minutes-ago timestamp for the throttle window, taken from the app clock. */
export function timestampMinutesAgo(minutes) {
  return sqlDateTime(plusMs(-Math.abs(Number(minutes)) * 60_000, now()));
}

export async function recentFailureCount(email, ip, windowMinutes) {
  const rows = await query('SELECT COUNT(*) AS n FROM login_attempts WHERE (email = ? OR ip = ?) AND success = 0 AND attempted_at > ?', [
    normalizeEmail(email),
    String(ip),
    timestampMinutesAgo(windowMinutes),
  ]);
  return Number(rows[0]?.n ?? 0);
}

export async function recordAttempt(email, ip, success) {
  await execute('INSERT INTO login_attempts (email, ip, success) VALUES (?, ?, ?)', [
    normalizeEmail(email),
    String(ip),
    success ? 1 : 0,
  ]);
}
