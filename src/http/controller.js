// Shared controller helpers — port of src/Http/Controller.php (docs/02 section 2).
//
// PHP aborts mid-handler with exit; Node cannot, so a guard that has already
// written its response throws `Halt`, which the pipeline catches and treats as
// "response complete, stop". That keeps the PHP reading order (CSRF → guard →
// object check → work) intact in the handlers themselves.

import { query } from '../db/connection.js';
import { addFlash, takeFlash } from './flash.js';
import { CSRF_ERROR, CSRF_FIELD, issue as issueCsrf, verify } from '../security/csrf.js';
import { render, renderError } from '../views.js';
import { redirect } from './response.js';

/** Thrown by a guard that already produced the response. */
export class Halt extends Error {
  constructor() {
    super('response complete');
    this.name = 'Halt';
  }
}

export async function loadUser(userId) {
  if (userId === null || userId === undefined) return null;
  // password_hash is loaded deliberately: every privileged change re-checks the
  // current password (docs/03 C-AUTH-2). It is never rendered — no template
  // receives a user row with a hash in it except through these controllers.
  const rows = await query(
    'SELECT id, username, email, password_hash, role, is_banned, ban_reason, avatar_path, mfa_enabled, created_at, updated_at FROM users WHERE id = ?',
    [userId],
  );
  return rows[0] ?? null;
}

/** The per-request context every handler receives. */
export function makeContext(req, res, session, user) {
  return { req, res, session, user };
}

/** Common template variables (PHP Controller::view()). */
export function view(ctx, template, vars = {}) {
  const user = ctx.user;
  return render(ctx.res, template, {
    ...vars,
    current_user: user,
    is_admin: user !== null && user.role === 'admin',
    // app_name comes from the Nunjucks global (views.js), which reads env per
    // render — passing it here would shadow the global inside the partials.
    // PHP rendered the hidden field via Csrf::field(), which issues the token on
    // demand; the port does the same so every form on the page carries one.
    csrf_token: issueCsrf(ctx.session),
    flash_messages: takeFlash(ctx.session),
  });
}

/** CSRF check, first thing in every state-changing handler (C-CSRF-1). */
export function csrf(ctx) {
  const submitted = ctx.req.fields[CSRF_FIELD];
  if (!verify(ctx.session, typeof submitted === 'string' ? submitted : null)) {
    renderError(ctx.res, 400, CSRF_ERROR);
    throw new Halt();
  }
}

/** Trimmed field values, the equivalent of PHP's posts(...) (docs/07 §10). */
export function posts(ctx, names) {
  const out = {};
  for (const name of names) {
    const value = ctx.req.fields[name];
    out[name] = typeof value === 'string' ? value.trim() : '';
  }
  return out;
}

export function post(ctx, name) {
  const value = ctx.req.fields[name];
  return typeof value === 'string' ? value.trim() : null;
}

/** B15: the intended path is the full request target, then filtered at login. */
export function requireLogin(ctx) {
  if (ctx.user === null) {
    ctx.session.data.intended_path = `${ctx.req.path}${queryStringOf(ctx.req)}`;
    addFlash(ctx.session, 'error', 'Please log in first.');
    redirect(ctx.res, '/login');
    throw new Halt();
  }
  return ctx.user;
}

export function requireAdmin(ctx) {
  const user = requireLogin(ctx);
  if (user.role !== 'admin') {
    renderError(ctx.res, 403, 'Administrator access required.');
    throw new Halt();
  }
  return user;
}

/** 403 for anonymous callers on a login-or-anon route. */
export function denyAnonymous(ctx) {
  if (ctx.user === null) {
    renderError(ctx.res, 403, 'You must be logged in to do that.');
    throw new Halt();
  }
}

function queryStringOf(req) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(req.query ?? {})) search.append(key, String(value));
  const q = search.toString();
  return q === '' ? '' : `?${q}`;
}

/** Guard application for the pipeline (docs/03 C-ACL-2/C-ACL-4). */
export async function applyGuard(ctx, guard) {
  if (guard === 'login') return requireLogin(ctx);
  if (guard === 'admin') return requireAdmin(ctx);
  if (guard === 'anon') {
    // A logged-in visitor is bounced away from login/register screens by the
    // handlers themselves, exactly as the PHP controllers do.
    return ctx.user;
  }
  return ctx.user;
}
