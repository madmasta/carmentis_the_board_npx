// Email-based one-time codes — port of src/Mfa.php (docs/02 B12/B13, docs/03
// C-MFA-1 and C-RACE-1).
//
// The lifecycle rules are PHP's: a code is 6 digits, stored hashed, expires,
// allows a capped number of attempts, is burned on success, and a fresh issue
// invalidates any outstanding code for that user.
//
// The one thing the port adds is the transaction + row lock (C-RACE-1): PHP did
// the check-then-act without a lock, and `vuln/race_condition` reproduces that
// by removing the lock again. `docs/04` §9 pins the proof as counts, not timing.

import { randomInt } from 'node:crypto';

import { query, execute, transaction, forUpdate } from '../db/connection.js';
import { int } from '../config/env.js';
import { now, plusMs, sqlDateTime } from '../lib/clock.js';
import { hash, verify as verifyHash } from './passwords.js';

export const ERR_EMPTY = 'Please enter the verification code.';
export const ERR_FORMAT = 'The code must be exactly 6 digits.';
export const ERR_NONE_PENDING = 'No pending verification code. Please request a new one.';
export const ERR_ATTEMPTS = 'Too many incorrect attempts. Request a new code.';
export const ERR_EXPIRED = 'This code has expired. Request a new one.';
export const ERR_INCORRECT = 'Incorrect code. Please try again.';

export function ttlMinutes() {
  return int('OTP_TTL_MINUTES', 10);
}

export function maxAttempts() {
  return int('OTP_MAX_ATTEMPTS', 5);
}

function generateCode() {
  return String(randomInt(0, 1_000_000)).padStart(6, '0');
}

/** Issue a new code, invalidating any outstanding one for the same user. */
export async function issueCode(userId) {
  await execute('UPDATE mfa_codes SET used_at = ? WHERE user_id = ? AND used_at IS NULL', [
    sqlDateTime(now()),
    userId,
  ]);

  const code = generateCode();
  await execute('INSERT INTO mfa_codes (user_id, code_hash, expires_at) VALUES (?, ?, ?)', [
    userId,
    await hash(code),
    sqlDateTime(plusMs(ttlMinutes() * 60_000)),
  ]);

  return code;
}

/** Resend protection: at most one code per 60 seconds (docs/02 B13). */
export const RESEND_COOLDOWN_SECONDS = 60;

/**
 * Verify a submitted code. Returns the error list; an empty list is success.
 *
 * The read, the attempt counter and the burn all happen on one connection with
 * the pending row locked, so 20 simultaneous submissions cannot all succeed.
 */
export async function verify(userId, submitted) {
  const code = String(submitted ?? '').trim();
  if (code === '') return [ERR_EMPTY];
  if (!/^\d{6}$/.test(code)) return [ERR_FORMAT];

  const limit = maxAttempts();

  return transaction(async (conn) => {
    const row = await forUpdate(conn, 'SELECT id, code_hash, expires_at, attempts FROM mfa_codes WHERE user_id = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1', [
      userId,
    ]);
    if (row === null) return [ERR_NONE_PENDING];

    if (Number(row.attempts) >= limit) {
      await conn.query('UPDATE mfa_codes SET used_at = ? WHERE id = ?', [sqlDateTime(now()), row.id]);
      return [ERR_ATTEMPTS];
    }

    // Stored as UTC text (docs/07 section 10); parse it as UTC.
    if (new Date(`${String(row.expires_at).replace(' ', 'T')}Z`).getTime() < now().getTime()) {
      await conn.query('UPDATE mfa_codes SET used_at = ? WHERE id = ?', [sqlDateTime(now()), row.id]);
      return [ERR_EXPIRED];
    }

    // The counter is incremented before the comparison, as in PHP, so a burst of
    // guesses cannot sit inside a slow hash window.
    await conn.query('UPDATE mfa_codes SET attempts = attempts + 1 WHERE id = ?', [row.id]);

    if (!(await verifyHash(code, String(row.code_hash)))) return [ERR_INCORRECT];

    await conn.query('UPDATE mfa_codes SET used_at = ? WHERE id = ?', [sqlDateTime(now()), row.id]);
    return [];
  });
}

/** Outstanding (unused, unexpired) code rows for a user — exploit-test helper. */
export async function pendingCodes(userId) {
  return query('SELECT id, code_hash, expires_at, attempts FROM mfa_codes WHERE user_id = ? AND used_at IS NULL ORDER BY id DESC', [
    userId,
  ]);
}
