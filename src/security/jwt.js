// Signed tokens for password reset and remember-me (docs/02 section 7,
// docs/03 C-JWT-1, C-CRYPTO-1, C-REDIRECT-2).
//
// The discipline:
//   * `HS256` only. The verify call passes `algorithms: ['HS256']` explicitly, so
//     an `alg: none` token or an algorithm substitution in the header is refused
//     before the payload is ever looked at;
//   * the secret is 32 random bytes or more, taken from `JWT_SECRET` or generated
//     once into `var/secret.key` (mode 0600). There is no fallback constant — a
//     missing, short or unreadable secret is a hard error, not a default;
//   * expiry is at most 15 minutes, and `iss`/`sub`/`purpose` are checked;
//   * a reset token is single-use: the `jti` is written to `jwt_claims` with an
//     insert that fails on a duplicate key, so the mark and the check are one
//     atomic statement — a replayed token whose signature is still perfectly
//     valid is refused;
//   * a reset URL is built from `APP_URL` only; the token never travels to a
//     host the request chose (C-REDIRECT-2).

import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import jwt from 'jsonwebtoken';

import { get } from '../config/env.js';
import { root } from '../db/admin.js';
import { execute, query } from '../db/connection.js';
import { sqlDateTime } from '../lib/clock.js';

export const JWT_ALGORITHMS = ['HS256'];
export const JWT_MAX_AGE_SECONDS = 15 * 60;
export const JWT_ISSUER = 'theboard';
export const JWT_PURPOSES = new Set(['password_reset', 'remember_me']);

export const INVALID_TOKEN = 'That reset link is no longer valid.';

const SECRET_FILE = 'var/secret.key';
let cachedSecret = null;

/** The signing key: env, or a key this app generated once and stored at 0600. */
export function signingSecret() {
  if (cachedSecret !== null) return cachedSecret;

  const fromEnv = get('JWT_SECRET');
  if (fromEnv !== null && fromEnv !== '') {
    if (Buffer.byteLength(fromEnv, 'utf8') < 32) throw new Error('JWT_SECRET must be at least 32 bytes.');
    cachedSecret = fromEnv;
    return cachedSecret;
  }

  const path = join(root(), SECRET_FILE);
  if (existsSync(path)) {
    const stored = readFileSync(path, 'utf8').trim();
    if (Buffer.byteLength(stored, 'utf8') < 32) throw new Error(`${SECRET_FILE} must hold at least 32 bytes.`);
    cachedSecret = stored;
    return cachedSecret;
  }

  const generated = randomBytes(32).toString('hex');
  mkdirSync(join(root(), 'var'), { recursive: true });
  writeFileSync(path, `${generated}\n`, { mode: 0o600 });
  cachedSecret = generated;
  return cachedSecret;
}

/** True when the key file was written with owner-only permissions. */
export function secretFileMode() {
  const path = join(root(), SECRET_FILE);
  if (!existsSync(path)) return null;
  return statSync(path).mode & 0o777;
}

/** Mint a token. `purpose` is bound into the payload and re-checked on verify. */
export function issue({ sub, purpose, maxAgeSeconds = JWT_MAX_AGE_SECONDS }) {
  if (!JWT_PURPOSES.has(purpose)) throw new Error(`Unknown token purpose: ${purpose}`);
  const requested = Number.parseInt(String(maxAgeSeconds), 10);
  const seconds = Math.min(Number.isFinite(requested) && requested > 0 ? requested : JWT_MAX_AGE_SECONDS, JWT_MAX_AGE_SECONDS);
  const jti = randomBytes(16).toString('hex');

  const token = jwt.sign({ sub: String(sub), purpose, iss: JWT_ISSUER }, signingSecret(), {
    algorithm: 'HS256',
    expiresIn: seconds,
    jwtid: jti,
  });

  return { token, jti, maxAgeSeconds: seconds };
}

/** Test seam: forget the cached key so a case can supply its own. */
export function resetSecretCache() {
  cachedSecret = null;
}

/** Signature, algorithm, issuer, expiry and purpose — no side effects. */
export function decode(token, purpose) {
  try {
    const payload = jwt.verify(String(token ?? ''), signingSecret(), {
      algorithms: [...JWT_ALGORITHMS],
      issuer: JWT_ISSUER,
    });
    if (payload.purpose !== purpose) return { ok: false, message: INVALID_TOKEN };
    if (typeof payload.jti !== 'string' || payload.jti === '') return { ok: false, message: INVALID_TOKEN };
    return { ok: true, payload };
  } catch {
    return { ok: false, message: INVALID_TOKEN };
  }
}

/** Has this jti already been spent? */
export async function isConsumed(jti) {
  const rows = await query('SELECT jti FROM jwt_claims WHERE jti = ?', [jti]);
  return rows.length > 0;
}

/**
 * Verify and spend a token in one step. The insert is the claim: a duplicate key
 * means someone has already used this token, and that is true no matter how
 * recently the first use happened.
 */
export async function consume(token, purpose) {
  const checked = decode(token, purpose);
  if (!checked.ok) return checked;

  const result = await execute(
    'INSERT IGNORE INTO jwt_claims (jti, purpose, user_id, consumed_at) VALUES (?, ?, ?, ?)',
    [checked.payload.jti, purpose, Number.isInteger(Number(checked.payload.sub)) ? Number(checked.payload.sub) : null, sqlDateTime(new Date())],
  );

  // `INSERT IGNORE` reports 0 affected rows for a duplicate; a plain insert would
  // have thrown, which is the same answer with more noise.
  if (result.affectedRows === 0) return { ok: false, message: INVALID_TOKEN };

  return checked;
}

/** Verify without spending (remember-me: usable until it expires). */
export async function verifyActive(token, purpose) {
  const checked = decode(token, purpose);
  if (!checked.ok) return checked;
  if (await isConsumed(checked.payload.jti)) return { ok: false, message: INVALID_TOKEN };
  return checked;
}

/** Forget spent claims older than `days`; keeps the table from growing forever. */
export async function pruneClaims(days = 30) {
  return execute('DELETE FROM jwt_claims WHERE consumed_at IS NOT NULL AND consumed_at < ?', [
    sqlDateTime(new Date(Date.now() - days * 24 * 60 * 60 * 1000)),
  ]);
}

/** The reset link: APP_URL decides the host, always. */
export function resetLink(token) {
  const base = String(get('APP_URL', 'http://localhost:8088')).replace(/\/+$/, '');
  return `${base}/reset-password?token=${encodeURIComponent(token)}`;
}
