// Application log — the Node equivalent of PHP's error_log() sink, pointed at
// var/log/app.log (docs/07 section 9).
//
// Control C-INFO-3 pins the shape: one record per line, user-supplied values
// newline-stripped and truncated, and no secret material in the line. Secrets
// are kept out by construction: this module never receives a password, a hash,
// an OTP code or a session id, and the request logger records the matched route
// template rather than the raw request target.
//
// The one email that can appear is the `email=` field of the login-throttle
// bypass record, reproduced verbatim from the PHP target
// (`[SECURITY] login throttle BYPASSED (…): email=… ip=… failures=n/m`) —
// see docs/03 C-INFO-3.

import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { get } from '../config/env.js';
import { isoTimestamp } from './clock.js';

const ROOT = process.env.THEBOARD_ROOT ?? process.cwd();

export function logPath() {
  return get('APP_LOG') ?? join(ROOT, 'var', 'log', 'app.log');
}

/** Keep a record on one line and bounded, whatever the input was. */
export function sanitize(value, maxLength = 400) {
  const text = String(value ?? '')
    .replace(/\r?\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
}

function writeLine(line) {
  const target = logPath();
  try {
    mkdirSync(join(target, '..'), { recursive: true });
    appendFileSync(target, `${line}\n`, 'utf8');
  } catch {
    // A missing log directory must never turn into a 500.
  }
}

export function log(level, message, extra = '') {
  const line = `[${isoTimestamp()}] ${sanitize(level, 12)} ${sanitize(message)}${
    extra ? ` ${sanitize(extra)}` : ''
  }`;
  writeLine(line);
  if (level === 'error' || level === 'security') process.stderr.write(`${line}\n`);
  return line;
}

/** The `[SECURITY] …` prefix the PHP target uses for every guard message. */
export function security(message, extra = '') {
  return log('security', `[SECURITY] ${sanitize(message)}`, extra);
}

export function info(message, extra = '') {
  return log('info', message, extra);
}

export function warn(message, extra = '') {
  return log('warn', message, extra);
}

export function error(message, extra = '') {
  return log('error', message, extra);
}

/** Stack traces go to the log, never to the response (C-INFO-1). */
export function errorStack(err) {
  const stack = String(err?.stack ?? err ?? '')
    .split(/\r?\n/)
    .map((line) => sanitize(line, 300))
    .filter((line) => line !== '');
  for (const line of stack) writeLine(`[${isoTimestamp()}] stack  ${line}`);
}

/** Test seam: truncate the log so an assertion can read what one request wrote. */
export function clearForTests() {
  try {
    mkdirSync(join(logPath(), '..'), { recursive: true });
    appendFileSync(logPath(), '', 'utf8');
  } catch {
    /* ignore */
  }
}
