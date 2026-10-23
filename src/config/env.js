// Minimal .env loader — port of src/Env.php (docs/01 section 3).
//
// Same semantics as the PHP class:
//   * real environment variables win over the file (container friendly);
//   * `KEY=value` with optional surrounding quotes, `#` comments, blank lines
//     skipped, whitespace trimmed on both sides;
//   * get() before load() is a programming error and throws.
//
// One deliberate difference (docs/01 section 8): the file is re-read when its
// mtime changes, which reproduces the PHP dev-server behaviour of picking up an
// edited .env without a restart. Values are never written back anywhere.

import { readFileSync, statSync } from 'node:fs';
import { DEFAULTS } from './defaults.js';

let current = null; // { path, values, mtimeMs }

function parse(text) {
  const values = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const pos = line.indexOf('=');
    if (pos === -1) continue;
    const key = line.slice(0, pos).trim();
    let value = line.slice(pos + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    if (key !== '') values[key] = value;
  }
  return values;
}

function readFile(path) {
  const text = readFileSync(path, 'utf8');
  return { path, values: parse(text), mtimeMs: statSync(path).mtimeMs };
}

/** Load (or reload) the .env file. Mirrors Env::load(). */
export function load(path) {
  try {
    current = readFile(path);
  } catch (error) {
    throw new Error(`.env file not found or unreadable: ${path} (${error.message})`);
  }
  return current.path;
}

/** True when a .env has been loaded (scripts and tests use this to fail early). */
export function isLoaded() {
  return current !== null;
}

/** Absolute path of the loaded file, or null. */
export function loadedPath() {
  return current?.path ?? null;
}

const NO_FILE = Object.freeze({});

function fileValues() {
  // No .env loaded (tests set process.env directly, scripts run with the
  // environment): fall through to process.env, DEFAULTS and the caller's
  // fallback, exactly as PHP's getenv() would.
  if (current === null) return NO_FILE;
  // Dev parity with PHP: pick up edits to .env without a restart.
  try {
    const mtimeMs = statSync(current.path).mtimeMs;
    if (mtimeMs !== current.mtimeMs) current = readFile(current.path);
  } catch {
    /* file vanished mid-run: keep the values already parsed */
  }
  return current.values;
}

/**
 * Read one key. Precedence: process.env (non-empty) > .env file >
 * DEFAULTS > caller fallback. `undefined`/empty env vars are skipped, matching
 * PHP's `getenv() === false || === ''` test.
 */
export function get(key, fallback = null) {
  const fromEnv = process.env[key];
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv;

  const values = fileValues();
  if (key in values) return values[key];

  if (key in DEFAULTS) return DEFAULTS[key];

  return fallback;
}

export function int(key, fallback) {
  const value = get(key);
  if (value === null || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export function bool(key, fallback) {
  const value = get(key);
  if (value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

export function list(key) {
  const value = get(key, '');
  if (value === null || String(value).trim() === '') return [];
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item !== '');
}

/** Test seam: force a specific file (or nothing) to be the active .env. */
export function resetForTests(pathOrNull = null) {
  current = pathOrNull === null ? null : readFile(pathOrNull);
}
