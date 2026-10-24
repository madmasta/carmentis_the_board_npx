// Auth pages and the login/MFA flow — port of src/Http/AuthController.php.
//
// The order inside each handler is the PHP order: CSRF first, then the state
// check, then the work. Flash copy is verbatim from the PHP target, because the
// ported integration cases assert on it (docs/02 B7..B14).

import { get } from '../config/env.js';
import { addFlash } from './flash.js';
import { Halt, csrf, post, posts, view } from './controller.js';
import { clearRemember, issueRemember } from '../auth/remember.js';
import { redirect } from './response.js';
import { Mailer } from '../mail/mailer.js';
import * as mfa from '../security/mfa.js';
import * as users from '../repositories/user.repository.js';
import * as validator from '../security/validator.js';
import { escapeHtml } from '../security/markup.js';
import {
  SESSION_MFA_LAST_SENT,
  abandonMfaChallenge,
  attemptLogin,
  clientIp,
  completeLogin,
  logout as endSession,
  mfaPendingUser,
} from '../auth/login.js';

/** Internal targets only — never a scheme-relative or absolute URL (C-REDIRECT-1). */
export function consumeIntendedPath(ctx) {
  const path = ctx.session.data.intended_path ?? '/';
  ctx.session.data.intended_path = null;
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) return '/';
  return path;
}

export async function loginForm(ctx) {
  if (ctx.user !== null) {
    redirect(ctx.res, '/');
    throw new Halt();
  }
  // Coming back to the form abandons a half-finished challenge.
  abandonMfaChallenge(ctx);
  view(ctx, 'login', { title: 'Log in', email: '' });
}

export async function login(ctx) {
  csrf(ctx);
  const in_ = posts(ctx, ['email', 'password']);
  const result = await attemptLogin(ctx, in_.email, in_.password, clientIp(ctx.req));

  switch (result.status) {
    case 'ok':
      // The remember-me cookie is minted only after a successful password check,
      // and carries a signed claim, never an identity (docs/03 C-JWT-1).
      if (post(ctx, 'remember') === '1') await issueRemember(ctx, result.user);
      addFlash(ctx.session, 'success', `Welcome back, ${result.user.username}!`);
      redirect(ctx.res, consumeIntendedPath(ctx));
      throw new Halt();
    case 'mfa': {
      const user = result.user;
      const code = await mfa.issueCode(Number(user.id));
      ctx.session.data[SESSION_MFA_LAST_SENT] = Math.floor(Date.now() / 1000);
      await sendCode(user, code);
      addFlash(
        ctx.session,
        'info',
        `We emailed you a verification code. It expires in ${mfa.ttlMinutes()} minutes.`,
      );
      redirect(ctx.res, '/mfa');
      throw new Halt();
    }
    case 'throttled':
      addFlash(ctx.session, 'error', 'Too many failed attempts. Please try again in a few minutes.');
      redirect(ctx.res, '/login');
      throw new Halt();
    case 'banned':
      addFlash(ctx.session, 'error', 'This account has been suspended. Contact an administrator.');
      redirect(ctx.res, '/login');
      throw new Halt();
    default:
      // Generic: do not reveal whether the account exists.
      addFlash(ctx.session, 'error', 'Invalid email or password.');
      redirect(ctx.res, '/login');
      throw new Halt();
  }
}

export async function mfaForm(ctx) {
  const user = await mfaPendingUser(ctx);
  if (user === null) {
    addFlash(ctx.session, 'error', 'No login in progress. Please log in again.');
    redirect(ctx.res, '/login');
    throw new Halt();
  }
  if (ctx.user !== null) {
    redirect(ctx.res, '/');
    throw new Halt();
  }
  view(ctx, 'mfa', { title: 'Two-factor verification', user });
}

export async function mfaSubmit(ctx) {
  csrf(ctx);
  const user = await mfaPendingUser(ctx);
  if (user === null) {
    addFlash(ctx.session, 'error', 'No login in progress. Please log in again.');
    redirect(ctx.res, '/login');
    throw new Halt();
  }

  const errors = await mfa.verify(Number(user.id), post(ctx, 'code') ?? '');
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, '/mfa');
    throw new Halt();
  }

  await completeLogin(ctx, user);
  addFlash(ctx.session, 'success', `Two-factor check complete. Welcome back, ${user.username}!`);
  redirect(ctx.res, consumeIntendedPath(ctx));
  throw new Halt();
}

export async function mfaResend(ctx) {
  csrf(ctx);
  const user = await mfaPendingUser(ctx);
  if (user === null) {
    redirect(ctx.res, '/login');
    throw new Halt();
  }

  const last = Number(ctx.session.data[SESSION_MFA_LAST_SENT] ?? 0);
  if (Math.floor(Date.now() / 1000) - last < mfa.RESEND_COOLDOWN_SECONDS) {
    addFlash(ctx.session, 'error', 'Please wait a moment before requesting another code.');
    redirect(ctx.res, '/mfa');
    throw new Halt();
  }

  const code = await mfa.issueCode(Number(user.id));
  ctx.session.data[SESSION_MFA_LAST_SENT] = Math.floor(Date.now() / 1000);
  await sendCode(user, code);
  addFlash(ctx.session, 'success', 'A new code was sent to your email.');
  redirect(ctx.res, '/mfa');
  throw new Halt();
}

export async function logout(ctx) {
  csrf(ctx);
  clearRemember(ctx);
  await endSession(ctx);
  redirect(ctx.res, '/login');
  throw new Halt();
}

async function sendCode(user, code) {
  const mailer = new Mailer();
  await mailer.send(
    String(user.email),
    `${get('APP_NAME', 'The Board')} verification code`,
    `<p>Your verification code is:</p>` +
      `<p style="font-size:24px;letter-spacing:4px;"><strong>${escapeHtml(code)}</strong></p>` +
      `<p>This code expires in ${mfa.ttlMinutes()} minutes and can be used once. ` +
      'If you did not try to log in, you can ignore this email.</p>',
  );
}

export async function registerForm(ctx) {
  if (ctx.user !== null) {
    redirect(ctx.res, '/');
    throw new Halt();
  }
  view(ctx, 'register', { title: 'Register', errors: [], old: {} });
}

export async function register(ctx) {
  csrf(ctx);
  const in_ = posts(ctx, ['username', 'email', 'password', 'password_confirm']);

  const errors = [
    ...validator.username(in_.username),
    ...validator.email(in_.email),
    ...validator.password(in_.password, in_.username, in_.email),
  ];
  if (in_.password !== in_.password_confirm) errors.push('Passwords do not match.');
  if (errors.length === 0 && (await users.findByEmail(in_.email)) !== null) {
    errors.push('An account with that email already exists.');
  }
  if (errors.length === 0 && (await users.findByUsername(in_.username)) !== null) {
    errors.push('That username is already taken.');
  }

  if (errors.length > 0) {
    view(ctx, 'register', {
      title: 'Register',
      errors,
      old: { username: in_.username, email: in_.email },
    });
    return;
  }

  const user = await users.create(in_.username, in_.email, in_.password);
  await completeLogin(ctx, user);

  const mailer = new Mailer();
  await mailer.send(
    String(user.email),
    `Welcome to ${get('APP_NAME', 'The Board')}`,
    `<p>Hi ${escapeHtml(String(user.username))},</p><p>Your account has been created.</p>`,
  );

  addFlash(ctx.session, 'success', `Account created. Welcome, ${user.username}!`);
  redirect(ctx.res, '/');
  throw new Halt();
}
