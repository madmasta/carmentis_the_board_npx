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

  // Inline routes (docs/02 section 1), after the PHP rows.
  { method: 'GET', path: '/admin', guard: 'anon', csrf: false, handler: adminIndex },
  { method: 'GET', path: '/health', guard: 'anon', csrf: false, handler: health },
]);
