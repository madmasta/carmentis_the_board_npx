// Request parsing — the Node equivalent of PHP's superglobals (docs/01 section 5).
//
// Contract, all of it pinned by control proofs or parity behaviour:
//   * `path` has the trailing slash stripped and `''` folded to `/`, exactly like
//     the PHP front controller;
//   * `fields` mirrors `Controller::posts()`: values are trimmed strings;
//   * a `multipart/form-data` file part is exactly
//     `{ field, filename, mimeType, size, buffer }` with path separators already
//     stripped from `filename`;
//   * `MAX_POST_BYTES` caps the whole body (413), `MAX_UPLOAD_BYTES` caps one file
//     part (400 `File is too large`) and is enforced here, before any handler
//     runs — the size cap is a parser rule, type validation is a handler rule;
//   * `Host` / `X-Forwarded-Host` never reach URL or cookie construction; the
//     host must be on the allowlist (C-COOKIE-1).

import { get, int } from '../config/env.js';

/** Whole-request body cap. Above the 2 MiB upload cap so the upload still gets
 *  its own, more specific error. */
export const MAX_POST_BYTES = 4 * 1024 * 1024;
/** One multipart file part (docs/02 section 7, control C-UPLOAD-1). */
export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

export class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'RequestError';
    this.status = status;
  }
}

function stripTrailingSlash(rawPath) {
  let path = rawPath;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    /* leave the raw form; matching will simply fail into the 404 view */
  }
  path = path.replace(/\/+$/, '');
  return path === '' ? '/' : path;
}

function parseQuery(searchParams) {
  const query = Object.create(null);
  // PHP's URL parsing keeps the last occurrence of a repeated key.
  for (const [key, value] of searchParams.entries()) query[key] = value;
  return query;
}

function parseCookies(headerValue) {
  const cookies = {};
  if (!headerValue) return cookies;
  for (const part of String(headerValue).split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    if (name === '') continue;
    let value = part.slice(index + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    cookies[name] = value;
  }
  return cookies;
}

// C-ASSIGN-1: keys that could poison an object prototype are rejected before
// anything can assign from them, rather than silently dropped.
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function isDangerousKey(key) {
  return DANGEROUS_KEYS.has(String(key));
}

function assertSafeKeys(keys) {
  for (const key of keys) {
    if (isDangerousKey(key)) {
      throw new RequestError(400, 'Invalid request field name.');
    }
  }
}

function parseUrlencoded(text) {
  const fields = Object.create(null);
  for (const [key, value] of new URLSearchParams(text).entries()) fields[key] = value;
  assertSafeKeys(Object.keys(fields));
  return fields;
}

/**
 * Minimal multipart/form-data reader. Returns { fields, files }; a file part is
 * { field, filename, mimeType, size, buffer } with path separators stripped from
 * the client-supplied name.
 */
export function parseMultipart(buffer, boundary) {
  const fields = Object.create(null);
  const files = Object.create(null);
  if (!boundary) throw new RequestError(400, 'Malformed multipart body.');

  const delimiter = Buffer.from(`--${boundary}`);
  let position = 0;
  let sawFirst = false;

  while (true) {
    const start = buffer.indexOf(delimiter, position);
    if (start === -1) break;
    position = start + delimiter.length;
    if (buffer.slice(position, position + 2).toString() === '--') break; // closing delimiter
    if (buffer.slice(position, position + 2).toString() === '\r\n') position += 2;
    else continue;
    sawFirst = true;

    const headerEnd = buffer.indexOf('\r\n\r\n', position);
    if (headerEnd === -1) break;
    const rawHeaders = buffer.slice(position, headerEnd).toString('utf8');
    const bodyStart = headerEnd + 4;

    let bodyEnd = buffer.indexOf(delimiter, bodyStart);
    if (bodyEnd === -1) bodyEnd = buffer.length;
    // Trim the CRLF that precedes the next delimiter.
    if (buffer.slice(Math.max(0, bodyEnd - 2), bodyEnd).toString() === '\r\n') bodyEnd -= 2;

    const part = buffer.slice(bodyStart, bodyEnd);
    position = bodyEnd;

    let name = null;
    let filename = null;
    let mimeType = 'application/octet-stream';
    for (const line of rawHeaders.split('\r\n')) {
      const lower = line.toLowerCase();
      if (lower.startsWith('content-disposition:')) {
        const fieldMatch = /name="([^"]*)"/i.exec(line);
        if (fieldMatch) name = fieldMatch[1];
        const fileMatch = /filename="([^"]*)"/i.exec(line);
        if (fileMatch) filename = fileMatch[1];
      } else if (lower.startsWith('content-type:')) {
        mimeType = line.slice(line.indexOf(':') + 1).trim() || mimeType;
      }
    }
    if (name === null || name === '') continue;
    if (isDangerousKey(name)) throw new RequestError(400, 'Invalid request field name.');

    if (filename === null) {
      fields[name] = part.toString('utf8');
      continue;
    }

    // Strip any path the client put in the filename before anything else can
    // look at it (docs/03 C-UPLOAD-1, C-INFO-2).
    const bare = filename.split(/[\\/]/).pop() ?? '';
    if (part.length > MAX_UPLOAD_BYTES) {
      throw new RequestError(400, 'File is too large');
    }
    files[name] = {
      field: name,
      filename: bare,
      mimeType,
      size: part.length,
      buffer: part,
    };
  }

  if (!sawFirst && buffer.length > 0) throw new RequestError(400, 'Malformed multipart body.');
  return { fields, files };
}

async function readBody(req) {
  const limit = MAX_POST_BYTES;
  const chunks = [];
  let total = 0;
  let over = false;
  for await (const chunk of req) {
    if (over) continue; // keep draining: a reset mid-upload loses the 413
    total += chunk.length;
    if (total > limit) {
      over = true;
      chunks.length = 0;
      continue;
    }
    chunks.push(chunk);
  }
  if (over) throw new RequestError(413, 'Request body too large');
  return Buffer.concat(chunks);
}

/** Hosts the app will answer with (C-COOKIE-1). */
export function allowedHosts() {
  const configured = get('HOST_ALLOWLIST', '');
  const hosts = String(configured)
    .split(',')
    .map((host) => host.trim())
    .filter((host) => host !== '');
  if (hosts.length > 0) return hosts;

  const fromUrl = (() => {
    try {
      return new URL(get('APP_URL', 'http://localhost:8088')).host;
    } catch {
      return null;
    }
  })();
  const port = get('PORT', '8088');
  const base = fromUrl ? [...new Set([fromUrl, `localhost:${port}`, `127.0.0.1:${port}`, 'localhost', '127.0.0.1'])] : ['localhost', '127.0.0.1'];
  return base;
}

function hostOf(req) {
  const host = req.headers.host ?? '';
  return String(host).trim().toLowerCase();
}

/** `127.0.0.1:8088` -> `127.0.0.1`; an IPv6 literal in brackets is left alone. */
function withoutPort(host) {
  if (host.startsWith('[')) return host.replace(/\]:\d+$/, ']');
  const index = host.lastIndexOf(':');
  if (index === -1) return host;
  return /^\d+$/.test(host.slice(index + 1)) ? host.slice(0, index) : host;
}

/** The session cookie may only be issued for a host we were configured to serve. */
export function hostIsAllowed(req) {
  const host = hostOf(req);
  if (host === '') return false;
  // X-Forwarded-Host is never trusted, so it is not consulted at all. An
  // allowlist entry matches the Host with or without its port; an entry that
  // names a port must match it exactly.
  const bare = withoutPort(host);
  return allowedHosts().some((allowed) => {
    const entry = String(allowed).trim().toLowerCase();
    return entry !== '' && (host === entry || bare === withoutPort(entry));
  });
}

export async function parse(req) {
  const requestUrl = new URL(req.url ?? '/', 'http://localhost');
  const rawPath = requestUrl.pathname ?? '/';
  const path = stripTrailingSlash(rawPath);
  const segments = path === '/' ? [] : path.slice(1).split('/');
  const query = parseQuery(requestUrl.searchParams);
  const cookies = parseCookies(req.headers.cookie);
  assertSafeKeys(Object.keys(query));

  let fields = {};
  let files = {};
  const method = (req.method ?? 'GET').toUpperCase();

  if (method !== 'GET' && method !== 'HEAD') {
    const contentType = String(req.headers['content-type'] ?? '');
    const body = await readBody(req);
    if (contentType.toLowerCase().startsWith('application/x-www-form-urlencoded')) {
      fields = parseUrlencoded(body.toString('utf8'));
    } else if (contentType.toLowerCase().startsWith('multipart/form-data')) {
      const boundary = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
      const { fields: formFields, files: formFiles } = parseMultipart(
        body,
        (boundary?.[1] ?? boundary?.[2] ?? '').trim(),
      );
      fields = formFields;
      files = formFiles;
    } else if (body.length > 0) {
      // PHP ignores bodies of unknown content type; so do we.
      fields = {};
    }
  }

  return {
    method,
    path,
    segments,
    query,
    cookies,
    fields,
    files,
    https: isHttps(req),
    host: hostOf(req),
    ip: socketIp(req),
    referer: req.headers.referer ?? null,
  };
}

/** Equivalent of PHP's `$this->posts('a', 'b')`: trimmed string values. */
export function pickFields(parsed, names) {
  const out = {};
  for (const name of names) {
    const value = parsed.fields[name];
    out[name] = typeof value === 'string' ? value.trim() : '';
  }
  return out;
}

/** All submitted field names, including ones no allowlist accepts. */
export function fieldNames(parsed) {
  return Object.keys(parsed.fields);
}

export function isHttps(req) {
  // Only the socket state counts: X-Forwarded-Proto is not trusted (C-COOKIE-1).
  return req.socket?.encrypted === true;
}

function socketIp(req) {
  return req.socket?.remoteAddress ?? '';
}
