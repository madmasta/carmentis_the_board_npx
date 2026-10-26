// The ordered route table (docs/01 section 1).
//
// Rows follow docs/parity/route-inventory.md row order — that file is generated
// from the PHP front controller, and the order is the dispatch order. The two
// inline routes the extractor cannot see (`GET /admin`, `GET /health`) come from
// docs/02 section 1 and sit after the PHP rows; hook routes will be appended
// after the PHP rows too, before the 404 fallback.
//
// C-ACL-4: every entry declares a guard; router.js refuses to build otherwise.
// The guard is the *effective* requirement — see IMPLEMENTATION_NOTES item on the
// inventory's descriptive Guard column (POST /login and the /mfa rows must let an
// anonymous caller through, because the handler enforces the challenge state).

import { json, redirect } from './http/response.js';
import { buildTable } from './http/router.js';
import * as auth from './http/auth.controller.js';
import * as profile from './http/profile.controller.js';
import * as page from './http/page.controller.js';
import * as board from './http/board.controller.js';
import * as thread from './http/thread.controller.js';
import * as post from './http/post.controller.js';
import * as vote from './http/vote.controller.js';
import * as admin from './http/admin.controller.js';
import * as hooks from './http/hooks.controller.js';

function health(ctx) {
  json(ctx.res, { ok: true });
}

function adminIndex(ctx) {
  // A bare 303 to /admin/boards, no view, exactly like the PHP target.
  redirect(ctx.res, '/admin/boards');
}

/**
 * Rows are added at their inventory position as milestones land. `guard` and
 * `csrf` follow the inventory's method/path/CSRF columns; `guard` reflects what
 * the PHP handler actually enforces.
 */
export const routes = buildTable([
  // 1 — home (M3)
  { method: 'GET', path: '/', guard: 'login-or-anon', csrf: false, handler: page.home },

  // 2..13 — auth and profile (M2)
  { method: 'GET', path: '/login', guard: 'login-or-anon', csrf: false, handler: auth.loginForm },
  { method: 'POST', path: '/login', guard: 'anon', handler: auth.login },
  { method: 'POST', path: '/logout', guard: 'login', handler: auth.logout },
  { method: 'GET', path: '/register', guard: 'login-or-anon', csrf: false, handler: auth.registerForm },
  { method: 'POST', path: '/register', guard: 'anon', handler: auth.register },
  { method: 'GET', path: '/mfa', guard: 'login-or-anon', csrf: false, handler: auth.mfaForm },
  { method: 'POST', path: '/mfa', guard: 'login-or-anon', handler: auth.mfaSubmit },
  { method: 'POST', path: '/mfa/resend', guard: 'login-or-anon', handler: auth.mfaResend },
  { method: 'GET', path: '/profile', guard: 'login', handler: profile.show },
  { method: 'POST', path: '/profile', guard: 'login', handler: profile.update },
  { method: 'POST', path: '/profile/password', guard: 'login-or-anon', handler: profile.changePassword },
  { method: 'POST', path: '/profile/email', guard: 'login-or-anon', handler: profile.changeEmail },

  // 14..22 — boards, threads, posts, votes (M3)
  { method: 'GET', path: '/board/:id', guard: 'login', handler: board.show },
  { method: 'POST', path: '/board/:id/thread', guard: 'login', handler: board.createThread },
  { method: 'GET', path: '/thread/:id', guard: 'login', handler: thread.show },
  { method: 'POST', path: '/thread/:id/reply', guard: 'login', handler: thread.reply },
  // PHP dispatches GET /post/:id to ThreadController::show($id, true); the second
  // argument is unused by the handler, so the same function serves both rows.
  { method: 'GET', path: '/post/:id', guard: 'login', handler: thread.show },
  { method: 'GET', path: '/post/:id/edit', guard: 'login', handler: post.editForm },
  { method: 'POST', path: '/post/:id/edit', guard: 'login', handler: post.editSubmit },
  { method: 'POST', path: '/post/:id/delete', guard: 'admin', handler: post.remove },
  { method: 'POST', path: '/vote', guard: 'login', handler: vote.vote },

  // 23..34 — admin: boards, users, moderation (M4)
  { method: 'GET', path: '/admin/boards', guard: 'admin', csrf: false, handler: admin.boardsPage },
  { method: 'POST', path: '/admin/boards', guard: 'admin', handler: admin.createBoard },
  { method: 'GET', path: '/admin/boards/:id', guard: 'admin', csrf: false, handler: admin.boardDetail },
  { method: 'POST', path: '/admin/boards/:id', guard: 'admin', handler: admin.updateBoard },
  { method: 'POST', path: '/admin/boards/:id/access', guard: 'admin', handler: admin.toggleAccess },
  { method: 'POST', path: '/admin/boards/:id/delete', guard: 'admin', handler: admin.deleteBoard },
  { method: 'GET', path: '/admin/users', guard: 'admin', csrf: false, handler: admin.usersList },
  { method: 'POST', path: '/admin/users', guard: 'admin', handler: admin.addUser },
  { method: 'POST', path: '/admin/users/:id/ban', guard: 'admin', handler: admin.banUser },
  { method: 'POST', path: '/admin/users/:id/unban', guard: 'admin', handler: admin.unbanUser },
  { method: 'POST', path: '/admin/users/:id/password', guard: 'admin', handler: admin.resetPassword },
  { method: 'GET', path: '/admin/posts', guard: 'admin', csrf: false, handler: admin.moderation },

  // Inline routes (docs/02 section 1), after the PHP rows.
  { method: 'GET', path: '/admin', guard: 'anon', csrf: false, handler: adminIndex },
  { method: 'GET', path: '/health', guard: 'anon', csrf: false, handler: health },

  // Hook routes (docs/02 section 7) — Node-only, appended after the PHP rows as
  // docs/01 section 1 requires. Each is secure on `main`; a vuln branch downgrades
  // one control of one of these.
  { method: 'POST', path: '/profile/avatar', guard: 'login', handler: hooks.avatarUpload },
  { method: 'GET', path: '/avatar/:id', guard: 'login-or-anon', csrf: false, handler: hooks.avatarShow },
  { method: 'GET', path: '/attachment', guard: 'login', csrf: false, handler: hooks.attachment },
  { method: 'POST', path: '/preview', guard: 'login', handler: hooks.previewLink },
  { method: 'GET', path: '/board/:id/export.xml', guard: 'login', csrf: false, handler: hooks.boardExport },
  { method: 'POST', path: '/board/:id/import', guard: 'login', handler: hooks.boardImport },
  { method: 'GET', path: '/directory', guard: 'login', csrf: false, handler: hooks.directory },
  { method: 'POST', path: '/directory/search', guard: 'login', handler: hooks.directorySearch },
  { method: 'POST', path: '/directory/match', guard: 'login', handler: hooks.directoryMatch },
  { method: 'GET', path: '/admin/boards/:id/snapshot.json', guard: 'admin', csrf: false, handler: hooks.boardSnapshot },
  { method: 'POST', path: '/admin/boards/:id/restore', guard: 'admin', handler: hooks.boardRestore },
  { method: 'GET', path: '/thread/:id/export', guard: 'login', csrf: false, handler: hooks.threadExport },
  { method: 'GET', path: '/forgot-password', guard: 'anon', csrf: false, handler: hooks.forgotPasswordForm },
  { method: 'POST', path: '/forgot-password', guard: 'anon', handler: hooks.forgotPassword },
  { method: 'GET', path: '/reset-password', guard: 'anon', csrf: false, handler: hooks.resetPasswordForm },
  { method: 'POST', path: '/reset-password', guard: 'anon', handler: hooks.resetPassword },
]);
