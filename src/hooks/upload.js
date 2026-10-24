// Avatar and attachment uploads (docs/02 section 7, docs/03 C-UPLOAD-1).
//
// The discipline this file exists to enforce:
//   * the size cap is enforced by the request parser before any handler runs
//     (`request.js`, MAX_UPLOAD_BYTES) — nothing here has to be defensive about
//     an oversized buffer, and nothing here may relax that cap;
//   * a file is accepted only when its magic bytes AND its declared MIME type AND
//     its extension all agree with the allowlist — a `.png` containing PHP, or
//     `<svg>` containing script, is refused;
//   * the stored name is `crypto.randomUUID()` plus an extension the app chose.
//     The client's filename never reaches the filesystem, so `../`, absolute
//     paths, null bytes and double extensions cannot name a file;
//   * storage lives in `var/uploads/`, outside `public/`: nothing is reachable by
//     URL, so every read goes through `readStored()` and is answered by the
//     controller with a Content-Type the app picked (C-INFO-2).

import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { root } from '../db/admin.js';

export const UPLOAD_TYPES = [
  { mime: 'image/png', ext: 'png', magic: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  { mime: 'image/jpeg', ext: 'jpg', magic: (b) => b.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff])) },
  { mime: 'image/gif', ext: 'gif', magic: (b) => b.subarray(0, 6).toString('latin1') === 'GIF87a' || b.subarray(0, 6).toString('latin1') === 'GIF89a' },
  {
    mime: 'image/webp',
    ext: 'webp',
    magic: (b) => b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP',
  },
];

export const UNSUPPORTED_MESSAGE = `Unsupported file type. Allowed: ${UPLOAD_TYPES.map((t) => t.mime).join(', ')}.`;

/** A stored name is exactly `<uuid>.<allowed ext>` — nothing else resolves. */
const STORED_NAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z]{3,4}$/;

export function uploadsDir() {
  return join(root(), 'var', 'uploads');
}

function allowedExtensions() {
  return new Set(UPLOAD_TYPES.map((t) => t.ext));
}

/** The extension the app would give this MIME type, or null. */
export function extensionFor(mimeType) {
  return UPLOAD_TYPES.find((t) => t.mime === String(mimeType).toLowerCase())?.ext ?? null;
}

/**
 * Inspect a parsed file part (`{ field, filename, mimeType, size, buffer }`).
 * Returns `{ ok: true, type }` naming the matching allowlist entry, or
 * `{ ok: false, message }`. Order matters: type first, because that is the check
 * the vulnerability branch removes.
 */
export function inspect(file) {
  const buffer = file?.buffer;
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { ok: false, message: UNSUPPORTED_MESSAGE };
  }

  const declared = String(file.mimeType ?? '').toLowerCase();
  const byType = UPLOAD_TYPES.find((t) => t.mime === declared);
  if (byType === undefined || !byType.magic(buffer)) return { ok: false, message: UNSUPPORTED_MESSAGE };

  // The client's extension is only ever compared, never used: the stored name is
  // built from the allowlist entry. A name with more than one dot is refused even
  // when the last extension is allowed — `shell.php.png` is a smuggled second
  // extension, and it is rejected rather than normalised away.
  const filename = String(file.filename ?? '').toLowerCase();
  const parts = filename.split('.');
  const clientExt = parts.pop() ?? '';
  if (!allowedExtensions().has(clientExt) || parts.length !== 1 || parts[0] === '' || parts[0].includes('/') || parts[0].includes('\\')) {
    return { ok: false, message: UNSUPPORTED_MESSAGE };
  }

  return { ok: true, type: byType };
}

/** A filename this app would have produced, and nothing else. */
export function isStoredName(name) {
  return STORED_NAME.test(String(name ?? ''));
}

/**
 * Resolve a stored name to a path inside the uploads directory. Any name that is
 * not of the generated shape — including `..`, absolute paths, encoded
 * separators and double extensions — resolves to null rather than a path.
 */
export function resolveStored(name) {
  if (!isStoredName(name)) return null;
  const dir = resolve(uploadsDir());
  const path = resolve(dir, String(name));
  // Defence in depth: a name of the right shape still has to land inside dir.
  if (!path.startsWith(dir + sep)) return null;
  return path;
}

/** Write the accepted file; returns the generated name. */
export function store(file, type = inspect(file).type) {
  const filename = `${randomUUID()}.${type.ext}`;
  const dir = uploadsDir();
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, filename), file.buffer);
  return filename;
}

/** Read a stored file, or null when it does not exist. */
export function readStored(name) {
  const path = resolveStored(name);
  if (path === null || !existsSync(path)) return null;
  return readFileSync(path);
}

/** The allowlist entry for a stored name — the Content-Type the controller uses. */
export function typeOfStored(name) {
  const ext = String(name ?? '').split('.').pop();
  return UPLOAD_TYPES.find((t) => t.ext === ext) ?? null;
}

export function removeStored(name) {
  const path = resolveStored(name);
  if (path !== null && existsSync(path)) unlinkSync(path);
}

/** Sizes on disk, for the tests that assert the cap was enforced upstream. */
export function storedSize(name) {
  const path = resolveStored(name);
  return path === null || !existsSync(path) ? null : statSync(path).size;
}

export function listStored() {
  const dir = uploadsDir();
  return existsSync(dir) ? readdirSync(dir) : [];
}
