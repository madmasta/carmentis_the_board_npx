// Remember-me cookies (docs/02 section 7, docs/03 C-JWT-1, C-SESS-2).
//
// The cookie holds a signed token, never an identity: `sub` is only honoured
// after the signature, the algorithm, the issuer, the expiry and the purpose have
// all been checked, and the account is re-read from the database — a banned or
// deleted account gets nothing. The token lifetime is the same 15 minutes the
// control caps every token at; "remember me" buys a fresh session for a short
// window, not a permanent one.

import { setHeader } from '../http/headers.js';
import { bool } from '../config/env.js';
import { JWT_MAX_AGE_SECONDS, issue, verifyActive } from '../security/jwt.js';
import { findById } from '../repositories/user.repository.js';
import { establish } from '../session/store.js';

export const REMEMBER_COOKIE = 'theboard_remember';
export const REMEMBER_MAX_AGE_SECONDS = JWT_MAX_AGE_SECONDS;

export async function issueRemember(ctx, user) {
  const { token } = issue({ sub: String(user.id), purpose: 'remember_me', maxAgeSeconds: REMEMBER_MAX_AGE_SECONDS });
  const parts = [`${REMEMBER_COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${REMEMBER_MAX_AGE_SECONDS}`];
  if (ctx.req.https === true) parts.push('Secure');
  setHeader(ctx.res, 'Set-Cookie', parts.join('; '));
  return token;
}

export function clearRemember(ctx) {
  const parts = [`${REMEMBER_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=-1'];
  if (ctx.req.https === true) parts.push('Secure');
  setHeader(ctx.res, 'Set-Cookie', parts.join('; '));
}

function tokenFrom(ctx) {
  const value = ctx.req.cookies?.[REMEMBER_COOKIE];
  return typeof value === 'string' ? value : null;
}

/**
 * If the request carries a live remember token and there is no session, open a
 * session for that account. Returns the user, or null when nothing applied.
 */
export async function tryRemember(ctx) {
  if (ctx.user !== null || bool('REMEMBER_ME_DISABLED', false)) return ctx.user;
  const token = tokenFrom(ctx);
  if (token === null) return ctx.user;

  const checked = await verifyActive(token, 'remember_me');
  if (!checked.ok) {
    clearRemember(ctx);
    return ctx.user;
  }

  const user = await findById(Number(checked.payload.sub));
  if (user === null || Number(user.is_banned) === 1) {
    clearRemember(ctx);
    return ctx.user;
  }

  await establish(ctx.session, user, ctx.res, { https: ctx.req.https === true });
  ctx.user = user;
  return user;
}
