// CSRF tokens (docs/02 B13, docs/03 C-CSRF-1) — port of src/Csrf.php.
//
// One token per session, 32 random bytes as hex, compared with
// crypto.timingSafeEqual, rotated when a login completes. The check runs before
// the login/admin guard in every handler, which is the order docs/02 section 2
// pins.

import { randomBytes, timingSafeEqual } from 'node:crypto';

export const CSRF_FIELD = 'csrf_token';
export const CSRF_ERROR = 'Invalid or missing CSRF token. Go back and try again.';

function newToken() {
  return randomBytes(32).toString('hex');
}

/** The session's token, created on first use. */
export function issue(session) {
  if (!session.data.csrf_token) session.data.csrf_token = newToken();
  return session.data.csrf_token;
}

/** Drop the current token; the next issue() mints a new one. */
export function rotate(session) {
  session.data.csrf_token = null;
  return issue(session);
}

function bytes(value) {
  return Buffer.from(String(value ?? ''), 'utf8');
}

/**
 * Length mismatch returns false before the comparison — the same observable
 * behaviour as PHP's hash_equals (docs/07 section 10).
 */
export function verify(session, submitted) {
  const expected = session?.data?.csrf_token;
  if (typeof expected !== 'string' || expected.length === 0) return false;
  if (typeof submitted !== 'string' || submitted.length === 0) return false;
  const a = bytes(expected);
  const b = bytes(submitted);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
