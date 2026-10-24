// src/Http/AdminController.php — admin board CRUD, access grants, user
// management and the moderation feed (docs/02 B25-B29).
//
// Every state-changing action checks CSRF first, then the admin guard: that
// order is pinned by docs/02 section 2 and is what `broken_function_level_authz`
// and `csrf` downgrade (docs/03 C-CSRF-1, C-ACL-2). Field reads are individual
// and explicitly cast (C-ASSIGN-1) — no object is filled from the request body.

import { randomBytes } from 'node:crypto';
import * as boards from '../repositories/board.repository.js';
import * as postsRepo from '../repositories/post.repository.js';
import * as users from '../repositories/user.repository.js';
import * as validator from '../security/validator.js';
import { addFlash } from './flash.js';
import { csrf, notFound, posts, post, requireAdmin, view } from './controller.js';
import { redirect } from './response.js';
import { intParam } from './router.js';

/** PHP's mb_substr($s, 0, $n) on a form field that may be absent. */
function clip(value, max) {
  return String(value ?? '').slice(0, max);
}

/** ctype_digit($_GET['created']) — a decimal id or nothing. */
function digitParam(value) {
  return /^\d+$/.test(String(value ?? '')) ? Number(value) : null;
}

/** bin2hex(random_bytes(8)) — the one-time password PHP hands out. */
function oneTimePassword() {
  return randomBytes(8).toString('hex');
}

function descriptionErrors(description) {
  return description.length > 500 ? ['Description must be at most 500 characters.'] : [];
}

// ------------------------------------------------------------------- boards

export async function boardsPage(ctx) {
  requireAdmin(ctx);
  view(ctx, 'admin/boards', {
    title: 'Admin · Boards',
    boards: await boards.listAll(),
  });
}

export async function createBoard(ctx) {
  csrf(ctx);
  const admin = requireAdmin(ctx);
  const in_ = posts(ctx, ['name', 'description']);
  const defaultAccess = post(ctx, 'default_access') === '1';

  const errors = [...validator.boardName(in_.name), ...descriptionErrors(in_.description)];
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, '/admin/boards');
    return;
  }

  const id = await boards.create(in_.name, in_.description, defaultAccess, Number(admin.id));
  addFlash(ctx.session, 'success', 'Board created.');
  redirect(ctx.res, `/admin/boards/${id}`);
}

/** Board detail: edit + access management. */
export async function boardDetail(ctx, params) {
  requireAdmin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null) notFound(ctx);

  view(ctx, 'admin/board_detail', {
    title: `Admin · ${board.name}`,
    board,
    access_list: await boards.accessList(Number(board.id)),
    all_users: await users.allUsers(),
    old: { name: board.name, description: board.description },
  });
}

export async function updateBoard(ctx, params) {
  csrf(ctx);
  requireAdmin(ctx);
  const boardId = intParam(params, 'id');
  const board = await boards.find(boardId);
  if (board === null) notFound(ctx);

  const in_ = posts(ctx, ['name', 'description']);
  const defaultAccess = post(ctx, 'default_access') === '1';
  const errors = [...validator.boardName(in_.name), ...descriptionErrors(in_.description)];
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, `/admin/boards/${boardId}`);
    return;
  }

  await boards.update(boardId, in_.name, in_.description, defaultAccess);
  addFlash(ctx.session, 'success', 'Board updated.');
  redirect(ctx.res, `/admin/boards/${boardId}`);
}

/** POST /admin/boards/{id}/access — grant or revoke one user's access. */
export async function toggleAccess(ctx, params) {
  csrf(ctx);
  const admin = requireAdmin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null) notFound(ctx);

  const userId = Number.parseInt(String(ctx.req.fields.user_id ?? '0'), 10) || 0;
  const target = await users.findById(userId);
  if (target === null) notFound(ctx);

  if (post(ctx, 'action') === 'grant') {
    await boards.grantAccess(Number(board.id), userId, Number(admin.id));
    // PHP escaped the name into the flash and the template escaped it again;
    // the port stores it raw and lets the autoescaping template escape once.
    addFlash(ctx.session, 'success', `Access granted to ${target.username}.`);
  } else {
    await boards.revokeAccess(Number(board.id), userId);
    addFlash(ctx.session, 'success', `Access revoked from ${target.username}.`);
  }
  redirect(ctx.res, `/admin/boards/${board.id}`);
}

export async function deleteBoard(ctx, params) {
  csrf(ctx);
  const admin = requireAdmin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null) notFound(ctx);

  await boards.softDelete(Number(board.id), Number(admin.id));
  addFlash(ctx.session, 'success', 'Board deleted.');
  redirect(ctx.res, '/admin/boards');
}

// -------------------------------------------------------------------- users

export async function usersList(ctx) {
  requireAdmin(ctx);
  const search = String(ctx.req.query.q ?? '').trim();
  const createdId = digitParam(ctx.req.query.created);
  view(ctx, 'admin/users', {
    title: 'Admin · Users',
    users: await users.allUsers(search),
    search,
    created_user: createdId === null ? null : await users.findById(createdId),
  });
}

/** Admin manually adds a user account. */
export async function addUser(ctx) {
  csrf(ctx);
  requireAdmin(ctx);
  const in_ = posts(ctx, ['username', 'email', 'password']);

  let errors = [...validator.username(in_.username), ...validator.email(in_.email)];
  if (in_.password !== '') {
    errors = [...errors, ...validator.password(in_.password, in_.username, in_.email)];
  }
  if (errors.length === 0 && (await users.findByEmail(in_.email)) !== null) {
    errors.push('An account with that email already exists.');
  }
  if (errors.length === 0 && (await users.findByUsername(in_.username)) !== null) {
    errors.push('That username is already taken.');
  }
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, '/admin/users');
    return;
  }

  const password = in_.password !== '' ? in_.password : oneTimePassword();
  const user = await users.create(in_.username, in_.email, password);

  addFlash(
    ctx.session,
    'success',
    `User "${user.username}" created. Initial password: ${password} (shown once — share it securely.)`,
  );
  redirect(ctx.res, `/admin/users?created=${user.id}`);
}

export async function banUser(ctx, params) {
  csrf(ctx);
  requireAdmin(ctx);
  const target = await users.findById(intParam(params, 'id'));
  if (target === null) notFound(ctx);

  if (target.role === 'admin') {
    addFlash(ctx.session, 'error', 'Admin accounts cannot be banned.');
    redirect(ctx.res, '/admin/users');
    return;
  }

  const reason = clip(post(ctx, 'reason'), 255);
  await users.setBanned(Number(target.id), true, reason !== '' ? reason : 'Violated board rules');
  addFlash(ctx.session, 'success', `User ${target.username} banned.`);
  redirect(ctx.res, '/admin/users');
}

export async function unbanUser(ctx, params) {
  csrf(ctx);
  requireAdmin(ctx);
  const target = await users.findById(intParam(params, 'id'));
  if (target === null) notFound(ctx);

  await users.setBanned(Number(target.id), false, null);
  addFlash(ctx.session, 'success', `User ${target.username} unbanned.`);
  redirect(ctx.res, '/admin/users');
}

/** Admin resets a user's password; the new one is shown once. */
export async function resetPassword(ctx, params) {
  csrf(ctx);
  requireAdmin(ctx);
  const target = await users.findById(intParam(params, 'id'));
  if (target === null) notFound(ctx);

  const newPassword = oneTimePassword();
  await users.updatePassword(Number(target.id), newPassword);
  addFlash(ctx.session, 'success', `New password for "${target.username}": ${newPassword} (shown once)`);
  redirect(ctx.res, '/admin/users');
}

// -------------------------------------------------------------- moderation

export async function moderation(ctx) {
  requireAdmin(ctx);
  view(ctx, 'admin/moderation', {
    title: 'Admin · Moderation',
    posts: await postsRepo.recentPosts(100),
  });
}
