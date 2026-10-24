// Response helpers — the Node equivalent of PHP's redirect()/header() calls
// (docs/01 section 5, docs/03 C-HDR-2).
//
// Every redirect is a 303 with an internal path only, and every header write
// goes through src/http/headers.js#setHeader so the CRLF and CORS checks cannot
// be bypassed by a caller.

import { get } from '../config/env.js';
import { safeRedirectLocation, setHeader } from './headers.js';
import { renderError } from '../views.js';

/** PHP's redirect(): 303 with a Location built from an internal path. */
export function redirect(res, location) {
  const target = safeRedirectLocation(location);
  setHeader(res, 'Location', target);
  res.statusCode = 303;
  res.end();
}

export function json(res, payload, code = 200) {
  res.statusCode = code;
  setHeader(res, 'Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

export function text(res, body, code = 200, contentType = 'text/plain; charset=utf-8') {
  res.statusCode = code;
  setHeader(res, 'Content-Type', contentType);
  res.end(body);
}

/**
 * A stored or generated file, answered by the app. The Content-Type is chosen
 * from the application's own allowlist and the filename is sanitised here —
 * neither is taken from a client header (docs/03 C-UPLOAD-1, C-INFO-2).
 */
export function attachment(res, body, { contentType, filename = null, inline = false, code = 200 }) {
  res.statusCode = code;
  setHeader(res, 'Content-Type', contentType);
  setHeader(res, 'X-Content-Type-Options', 'nosniff');
  setHeader(res, 'Cache-Control', 'private, max-age=0, no-cache');

  if (filename !== null) {
    const safe = String(filename).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
    setHeader(res, 'Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename="${safe}"`);
  }

  setHeader(res, 'Content-Length', String(Buffer.byteLength(body)));
  res.end(body);
}

/**
 * Status page for 400/403/404/409/413/500. `template` is kept in the signature
 * so callers can point at a specific view; the error view is the default.
 */
export function status(res, code, template = 'error', vars = {}) {
  if (template === 'error') {
    renderError(res, code, vars.message ?? 'Something went wrong.', { trace: vars.trace ?? null });
    return;
  }
  renderError(res, code, vars.message ?? 'Something went wrong.', { trace: vars.trace ?? null });
}

/**
 * B25: the vote redirect only follows HTTP_REFERER when it starts with APP_URL,
 * exactly like the PHP controller.
 */
export function internalReferer(referer) {
  if (typeof referer !== 'string' || referer === '') return null;
  const appUrl = String(get('APP_URL', 'http://localhost:8088'));
  if (!referer.startsWith(appUrl)) return null;
  let path;
  try {
    const url = new URL(referer);
    path = `${url.pathname}${url.search}`;
  } catch {
    return null;
  }
  try {
    return safeRedirectLocation(path);
  } catch {
    return null;
  }
}
