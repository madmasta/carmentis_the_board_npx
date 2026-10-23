// Template rendering — Nunjucks with autoescape on (docs/01 section 6,
// docs/03 C-XSS-2).
//
// Fences that matter for the catalog:
//   * `autoescape: true` is never turned off on `main`;
//   * templates never use `|safe` on request data. BBCode output goes through the
//     `markup` filter below, which returns a SafeString, so the only place raw
//     HTML can enter a page is `security/markup.js` — exactly what C-XSS-2's
//     source scan asserts;
//   * error pages render internals only when APP_DEBUG=1 (C-INFO-1).

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import nunjucks from 'nunjucks';
import { get, bool } from './config/env.js';
import { bannerTitle, bannerText, status as throttleStatus } from './security/login-throttle.js';
import { plain as plainText, render as renderMarkup } from './security/markup.js';
import { root } from './db/admin.js';

const TEMPLATES = join(root(), 'templates');

export const env = new nunjucks.Environment(new nunjucks.FileSystemLoader(TEMPLATES), {
  autoescape: true,
  throwOnUndefined: false,
  trimBlocks: false,
  lstripBlocks: false,
});

// The only raw-HTML exit in a template: the `markup` filter, whose output comes
// from security/markup.js. `plain` stays escaped (autoescape) on purpose — it is
// a teaser, not markup.
env.addFilter('markup', (value) => new nunjucks.runtime.SafeString(renderMarkup(value)));
env.addFilter('plain', (value) => plainText(value));
env.addGlobal('url', (path = '/') => `/${String(path).replace(/^\/+/, '')}`);
env.addGlobal('app_name', () => get('APP_NAME', 'The Board'));
// The header partial asks the throttle module directly, exactly as the PHP
// partial calls LoginThrottle::status() / ::bannerText().
env.addGlobal('throttle_status', () => throttleStatus());
env.addGlobal('throttle_title', () => bannerTitle());
env.addGlobal('throttle_text', () => bannerText());

/**
 * PHP view('profile/edit') maps to templates/profile/edit.php. Nunjucks needs
 * the extension in the name, so a bare name gets '.njk' and a '.php' suffix
 * inherited from a ported call site is rewritten.
 */
function templatePath(name) {
  if (name.endsWith('.php')) return `${name.slice(0, -4)}.njk`;
  if (/\.(njk|nj|html)$/.test(name)) return name;
  return `${name}.njk`;
}

function hasTemplate(path) {
  return existsSync(join(TEMPLATES, path));
}

/**
 * Render a template into the response. Status comes from `vars.status` when the
 * caller set one; the body is UTF-8 HTML.
 */
export function render(res, template, vars = {}) {
  const path = templatePath(template);
  if (!hasTemplate(path)) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Template not found');
    return;
  }
  const html = env.render(path, vars);
  res.statusCode = Number(vars.status ?? res.statusCode ?? 200);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(html);
}

/**
 * Error page. The stack trace appears only when APP_DEBUG=1 (C-INFO-1); the
 * stack is always written to the log separately by the pipeline.
 */
export function renderError(res, code, message, { trace = null } = {}) {
  const debugging = bool('APP_DEBUG', false);
  render(res, 'error', {
    status: Number(code),
    code: Number(code),
    message: String(message ?? 'Something went wrong.'),
    debug_trace: debugging && trace ? String(trace) : null,
  });
}

export function notFound(res) {
  renderError(res, 404, 'The page you requested does not exist.');
}

export function forbidden(res, message) {
  renderError(res, 403, message ?? 'You do not have permission to do that.');
}
