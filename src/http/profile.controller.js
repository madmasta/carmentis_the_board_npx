// Profile page and settings — port of src/Http/ProfileController.php.
//
// Every privileged change re-checks the current password, and the guard order is
// PHP's: CSRF, then requireLogin, then the password, then the change. The copy is
// verbatim (docs/02 B24..B27).

import { get } from '../config/env.js';
import { addFlash } from './flash.js';
import { Halt, csrf, posts, requireLogin, view } from './controller.js';
import { redirect } from './response.js';
import { Mailer } from '../mail/mailer.js';
import { escapeHtml } from '../security/markup.js';
import { verify as verifyPassword } from '../security/passwords.js';
import * as postRepository from '../repositories/post.repository.js';
import * as users from '../repositories/user.repository.js';
import * as validator from '../security/validator.js';

export async function show(ctx) {
  const user = requireLogin(ctx);
  const ownPosts = await postRepository.listByAuthor(Number(user.id));

  view(ctx, 'profile', { title: 'My profile', profile_user: user, posts: ownPosts });
}

/** MFA opt-in toggle; the current password must be supplied (C-AUTH-2). */
export async function update(ctx) {
  csrf(ctx);
  const user = requireLogin(ctx);
  const enabled = ctx.req.fields.mfa_enabled === '1';
  const { current_password: currentPassword } = posts(ctx, ['current_password']);

  if (!(await verifyPassword(currentPassword, String(user.password_hash)))) {
    addFlash(ctx.session, 'error', 'Password incorrect — MFA setting unchanged.');
    redirect(ctx.res, '/profile');
    throw new Halt();
  }

  await users.setMfaEnabled(Number(user.id), enabled);
  addFlash(ctx.session, 'success', enabled ? 'Email MFA is now enabled.' : 'MFA has been disabled.');
  redirect(ctx.res, '/profile');
  throw new Halt();
}

export async function changePassword(ctx) {
  csrf(ctx);
  if (ctx.user === null) {
    redirect(ctx.res, '/login');
    throw new Halt();
  }
  const user = ctx.user;
  const { current_password: currentPassword, new_password: newPassword, new_password_confirm: newPasswordConfirm } =
    posts(ctx, ['current_password', 'new_password', 'new_password_confirm']);

  if (!(await verifyPassword(currentPassword, String(user.password_hash)))) {
    addFlash(ctx.session, 'error', 'Current password is incorrect.');
    redirect(ctx.res, '/profile');
    throw new Halt();
  }

  const errors = validator.password(newPassword, String(user.username), String(user.email));
  if (newPassword !== newPasswordConfirm) errors.push('New passwords do not match.');
  if (await verifyPassword(newPassword, String(user.password_hash))) {
    errors.push('New password must differ from the current one.');
  }
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, '/profile');
    throw new Halt();
  }

  await users.updatePassword(Number(user.id), newPassword);
  addFlash(ctx.session, 'success', 'Password updated.');
  redirect(ctx.res, '/profile');
  throw new Halt();
}

export async function changeEmail(ctx) {
  csrf(ctx);
  if (ctx.user === null) {
    redirect(ctx.res, '/login');
    throw new Halt();
  }
  const user = ctx.user;
  const { current_password: currentPassword, new_email: newEmail } = posts(ctx, [
    'current_password',
    'new_email',
  ]);

  if (!(await verifyPassword(currentPassword, String(user.password_hash)))) {
    addFlash(ctx.session, 'error', 'Password incorrect — email not changed.');
    redirect(ctx.res, '/profile');
    throw new Halt();
  }

  const errors = validator.email(newEmail);
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, '/profile');
    throw new Halt();
  }

  const existing = await users.findByEmail(newEmail);
  if (existing !== null && Number(existing.id) !== Number(user.id)) {
    addFlash(ctx.session, 'error', 'That email is already in use.');
    redirect(ctx.res, '/profile');
    throw new Halt();
  }

  await users.setEmail(Number(user.id), newEmail);

  // The old address is told as well: if MFA was on, its destination changed.
  const mailer = new Mailer();
  await mailer.send(
    String(user.email),
    'Your email address was changed',
    `<p>The email address on your ${escapeHtml(String(get('APP_NAME', 'The Board')))} account ` +
      `was changed to ${escapeHtml(newEmail)}.</p>`,
  );

  addFlash(ctx.session, 'success', 'Email address updated.');
  redirect(ctx.res, '/profile');
  throw new Halt();
}
