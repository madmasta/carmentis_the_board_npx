// Login state machine — port of src/Auth.php (docs/02 B7..B12, docs/03
// C-AUTH-1..3, C-SESS-1..4).
//
// `attemptLogin` returns one of five states and never mixes transport concerns
// into it: ok | mfa | banned | throttled | invalid. The controller turns a state
// into a flash message and a redirect, which is what keeps the exploit tests
// able to assert on one thing at a time.
//
// One signature difference from `docs/01` §5: the session lives in the request
// context, so the function takes `ctx` first (PHP reached $_SESSION globally).

import { get } from '../config/env.js';
import { clearAuthentication, establish, regenerate as regenerateSession } from '../session/store.js';
import { fakeVerify, verify as verifyPassword } from '../security/passwords.js';
import { exceeded as throttleExceeded, windowSeconds } from '../security/login-throttle.js';
import * as users from '../repositories/user.repository.js';

export const SESSION_USER = 'auth_user_id';
export const SESSION_MFA_PENDING = 'mfa_pending_user_id';
export const SESSION_MFA_LAST_SENT = 'mfa_last_sent';
export const SESSION_AUTH_CREATED = 'auth_created_at';

/** Never trust X-Forwarded-For: the peer address is the identity (docs/03 C-AUTH-4). */
export function clientIp(req) {
  return req?.socket?.remoteAddress ?? '0.0.0.0';
}

/**
 * Credentials + throttle + ban. Mutates the session only for the `mfa` state
 * (the pending marker) and the `ok` state (completing the login).
 */
export async function attemptLogin(ctx, email, password, ip) {
  const address = String(email ?? '').trim().toLowerCase();
  if (address === '' || String(password ?? '') === '') return { status: 'invalid' };

  const recentFailures = await users.recentFailureCount(address, ip, windowSeconds() / 60);
  if (throttleExceeded({ email: address, ip, recentFailures })) {
    return { status: 'throttled', waitSeconds: windowSeconds() };
  }

  const user = await users.findByEmail(address);

  if (user === null) {
    // Burn the same time a real hash check would take, so a missing account and
    // a wrong password answer at the same rate.
    await fakeVerify(password);
  } else if (Number(user.is_banned) === 1) {
    if (await verifyPassword(password, String(user.password_hash))) return { status: 'banned' };
  } else if (await verifyPassword(password, String(user.password_hash))) {
    await users.recordAttempt(address, ip, true);

    if (Number(user.mfa_enabled) === 1) {
      ctx.session.data[SESSION_MFA_PENDING] = Number(user.id);
      return { status: 'mfa', user };
    }

    await completeLogin(ctx, user);
    return { status: 'ok', user };
  }

  await users.recordAttempt(address, ip, false);
  return { status: 'invalid' };
}

/** New session id, rotated CSRF token, user attached (C-SESS-2: fixation defense). */
export async function completeLogin(ctx, user) {
  ctx.session.data[SESSION_MFA_PENDING] = null;
  await establish(ctx.session, user, ctx.res, { https: ctx.req.https === true });
  ctx.user = user;
  return user;
}

/** The user awaiting MFA, if this session is mid-challenge. */
export async function mfaPendingUser(ctx) {
  const pending = ctx.session.data?.[SESSION_MFA_PENDING];
  if (!pending) return null;
  return users.findById(Number(pending));
}

/**
 * Drop an in-progress challenge: a code already emailed stays valid until it
 * expires, but this session is no longer mid-login.
 */
export function abandonMfaChallenge(ctx) {
  ctx.session.data[SESSION_MFA_PENDING] = null;
  ctx.session.data[SESSION_MFA_LAST_SENT] = 0;
}

/** Log out: row deleted, cookie expired (docs/02 B14). */
export async function logout(ctx) {
  // C-SESS-2: the id rotates on clear and the old row is deleted, exactly as PHP
  // deleting the session file meant. A new anonymous session takes its place so
  // the logout flash still has somewhere to live.
  await clearAuthentication(ctx.session, ctx.res, { https: ctx.req.https === true });
  ctx.user = null;
}

/** Wipe the payload but keep a usable session for the next flash (docs/02 B11). */
export async function clearSession(ctx) {
  await clearAuthentication(ctx.session, ctx.res, { https: ctx.req.https === true });
  ctx.user = null;
  return ctx.session;
}

export function sessionName() {
  return get('SESSION_NAME', 'theboard_session');
}

export { regenerateSession };
