// Security headers on every response, applied once in the pipeline
// (docs/03 C-HDR-1, C-HDR-2, C-HDR-3).

import { FORBIDDEN_HEADER_PREFIX, HSTS_HEADER, STATIC_HEADERS } from '../security/headers-policy.js';

// Control characters, CR and LF. A header name or value containing any of these
// is a response-splitting attempt, not a typo.
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;
const INVALID_NAME = /[^A-Za-z0-9\-_]/;

export class UnsafeHeaderValue extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnsafeHeaderValue';
  }
}

/** C-HDR-2 gate for every writeHeader()/setHeader() call. */
export function assertSafeHeader(name, value) {
  if (typeof name !== 'string' || name === '' || INVALID_NAME.test(name)) {
    throw new UnsafeHeaderValue(`refusing to set header with unsafe name: ${JSON.stringify(name)}`);
  }
  if (name.toLowerCase().startsWith(FORBIDDEN_HEADER_PREFIX)) {
    throw new UnsafeHeaderValue(`refusing to emit a CORS header: ${name} (C-HDR-3)`);
  }
  const values = Array.isArray(value) ? value : [value];
  for (const v of values) {
    const text = String(v);
    if (CONTROL_CHARS.test(text)) {
      throw new UnsafeHeaderValue(`refusing to set ${name} to a value containing control characters`);
    }
  }
}

/** The one way anything in src/ writes a header. */
export function setHeader(res, name, value) {
  assertSafeHeader(name, value);
  res.setHeader(name, value);
}

/**
 * The directory page shows the active search term in a client-side chip, and the
 * chip reads it from this header rather than re-parsing the URL, so the header goes
 * through the same C-HDR-2 gate as every other write. A term that cannot be a
 * header value simply does not get the header.
 */
export function searchEcho(res, term) {
  try {
    setHeader(res, 'X-Search-Term', String(term ?? ''));
    return true;
  } catch {
    return false;
  }
}

/** Apply the baseline set. Called before routing so even 404/403/500 carry it. */
export function applySecurityHeaders(res, { https = false } = {}) {
  for (const [name, value] of STATIC_HEADERS) setHeader(res, name, value);
  if (https) {
    const [name, value] = HSTS_HEADER;
    setHeader(res, name, value);
  }
}

/**
 * Validate a redirect target before it becomes a Location header.
 * Internal path only: must start with a single `/`, contain no control
 * characters, no scheme, no `//` and no backslash tricks (docs/03 C-HDR-2,
 * C-REDIR-2).
 */
export function safeRedirectLocation(location) {
  const value = String(location ?? '');
  if (CONTROL_CHARS.test(value)) {
    throw new UnsafeHeaderValue('redirect target contains control characters');
  }
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) {
    throw new UnsafeHeaderValue(`redirect target must be an internal path: ${JSON.stringify(value)}`);
  }
  return value;
}
