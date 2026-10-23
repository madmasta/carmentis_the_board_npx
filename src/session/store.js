// Database-backed sessions — replaces PHP's native file sessions
// (docs/02 section 3, docs/03 C-SESS-1..4, docs/07 section 2).
//
// The rules this file is responsible for:
//   * cookie flags: HttpOnly, SameSite=Lax, Secure over https, Path=/, no
//     Domain, session-scoped (no Max-Age);
//   * ids are crypto.randomBytes(16) hex, and a presented id that is unknown or
//     expired is never adopted — a fresh empty session is created instead
//     (the `use_strict_mode` equivalent);
//   * the id is regenerated on login, MFA completion, privilege change and
//     clear, and the old row is deleted;
//   * every request re-reads the user row and kills the session if the account
//     has been banned;
//   * the session payload stays in the `sessions` table, never in the cookie.

import { randomBytes } from 'node:crypto';
import { query, execute } from '../db/connection.js';
import { get } from '../config/env.js';
import { now, plusMs, sqlDateTime } from '../lib/clock.js';
import { setHeader } from '../http/headers.js';
import { addFlash } from '../http/flash.js';

export const BAN_FLASH = 'Your account has been suspended. Contact an administrator.';

/** Sliding expiry for the row; the cookie itself stays session-scoped. */
export const SESSION_TTL_MINUTES = 60 * 24 * 7;

const ID_PATTERN = /^[0-9a-f]{32}$/;

function newId() {
  return randomBytes(16).toString('hex');
}

function emptyData() {
  return {
    auth_user_id: null,
    mfa_pending_user_id: null,
    csrf_token: null,
    flash: [],
    intended_path: null,
    mfa_last_sent: 0,
    auth_created_at: null,
  };
}

function cookieName() {
  return get('SESSION_NAME', 'theboard_session');
}

function writeCookie(res, id, { https, maxAgeSeconds = null }) {
  const parts = [`${cookieName()}=${id}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (https) parts.push('Secure');
  if (maxAgeSeconds !== null) parts.push(`Max-Age=${maxAgeSeconds}`);
  // Deliberately no Domain and no request-supplied host (C-COOKIE-1).
  setHeader(res, 'Set-Cookie', parts.join('; '));
}

/** Expired rows are dropped as part of normal traffic. */
async function sweep() {
  await execute('DELETE FROM sessions WHERE expires_at < ?', [sqlDateTime(now())]);
}

/**
 * Load (or create) the session for this request, apply the ban kill, and make
 * sure the cookie is set. Returns the session object.
 */
export async function start(req, res) {
  await sweep();

  const presented = req.cookies?.[cookieName()] ?? null;
  let session = null;

  if (presented !== null && ID_PATTERN.test(presented)) {
    const row = await query('SELECT id, user_id, data, expires_at FROM sessions WHERE id = ?', [presented]);
    if (row.length === 1) {
      let data = row[0].data;
      if (typeof data === 'string') {
        try {
          data = JSON.parse(data);
        } catch {
          data = null;
        }
      }
      session = {
        id: row[0].id,
        userId: row[0].user_id ?? null,
        data: { ...emptyData(), ...(data ?? {}) },
        isNew: false,
      };
    }
  }

  if (session === null) {
    // Unknown, expired or malformed: never adopt the presented id.
    session = { id: newId(), userId: null, data: emptyData(), isNew: true };
  }

  if (session.userId !== null) {
    const users = await query('SELECT id, is_banned FROM users WHERE id = ?', [session.userId]);
    if (users.length === 0) {
      await destroy(session, res, { https: req.https });
      session = { id: newId(), userId: null, data: emptyData(), isNew: true };
    } else if (Number(users[0].is_banned) === 1) {
      // The ban takes effect mid-session (docs/02 section 3): the payload is
      // wiped and the user is told why, in the flash of the next render.
      await clearSession(session, res, { https: req.https });
      addFlash(session, 'error', BAN_FLASH);
    }
  }

  await save(session, res, { https: req.https });
  return session;
}

async function insertRow(session) {
  await execute(
    'INSERT INTO sessions (id, user_id, data, expires_at) VALUES (?, ?, ?, ?) ' +
      'ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), data = VALUES(data), expires_at = VALUES(expires_at)',
    [session.id, session.userId, JSON.stringify(session.data), sqlDateTime(plusMs(SESSION_TTL_MINUTES * 60_000))],
  );
}

/**
 * Persist the payload and refresh the row expiry. The cookie is only written
 * while the response has not started yet: the id is already set by start(), and
 * a later write (for example from regenerate() during login, which happens
 * before the redirect) still lands. After the response has begun there is
 * nothing to change.
 */
export async function save(session, res, { https = false } = {}) {
  await insertRow(session);
  if (!res.headersSent) writeCookie(res, session.id, { https });
  session.isNew = false;
}

/** New id, old row deleted, CSRF token rotated. */
export async function regenerate(session, res, { https = false } = {}) {
  await execute('DELETE FROM sessions WHERE id = ?', [session.id]);
  session.id = newId();
  session.data.csrf_token = null;
  session.isNew = true;
  await save(session, res, { https });
  return session;
}

/** Delete the row, drop the payload, expire the cookie. */
export async function destroy(session, res, { https = false } = {}) {
  await execute('DELETE FROM sessions WHERE id = ?', [session.id]);
  session.userId = null;
  session.data = emptyData();
  writeCookie(res, '', { https, maxAgeSeconds: -1 });
}

/** Keep the cookie, wipe the payload (used by the ban kill). */
async function clearSession(session, res, { https = false } = {}) {
  await execute('DELETE FROM sessions WHERE id = ?', [session.id]);
  session.id = newId();
  session.userId = null;
  session.data = emptyData();
  await save(session, res, { https });
}

function clearFlashQueue(session) {
  session.data.flash = [];
}

/** Attach a user id to the session (called by the login completion path). */
export async function establish(session, user, res, { https = false } = {}) {
  await regenerate(session, res, { https });
  session.userId = Number(user.id);
  session.data.auth_user_id = Number(user.id);
  session.data.auth_created_at = sqlDateTime(now());
  await save(session, res, { https });
  return session;
}

/** Drop the auth link without touching anything else in the payload. */
export async function clearAuthentication(session, res, { https = false } = {}) {
  await execute('DELETE FROM sessions WHERE id = ?', [session.id]);
  session.id = newId();
  session.userId = null;
  const flash = session.data.flash ?? [];
  session.data = { ...emptyData(), flash };
  await save(session, res, { https });
  return session;
}

export function currentUser(session) {
  return session?.data?.auth_user_id ?? null;
}
