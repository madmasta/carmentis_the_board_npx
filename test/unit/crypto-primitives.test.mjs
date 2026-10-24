// C-CRYPTO-1 — CSPRNG-backed values and sound primitives (docs/03).
//
// The companion source scan lives in `test/security/controls.test.mjs#c-crypto-1`;
// this file proves the *shapes*: every secret is long, unpredictable and differs
// between calls, and hashing goes through bcryptjs at cost >= 10.

import { beforeEach, describe, expect, it } from 'vitest';
import { row, truncateAll } from '../helpers/db.mjs';
import { fakeSession } from '../helpers/ctx.mjs';
import { makeUser } from '../helpers/users.mjs';
import * as csrf from '../../src/security/csrf.js';
import * as mfa from '../../src/security/mfa.js';
import * as passwords from '../../src/security/passwords.js';
import * as uploads from '../../src/hooks/upload.js';

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x09]);

beforeEach(async () => {
  await truncateAll();
});

describe('c-crypto-1 generated secrets', () => {
  it('c-crypto-1 a CSRF token is 256 bits of hex and never repeats', () => {
    const tokens = new Set();
    for (let i = 0; i < 20; i += 1) {
      const session = fakeSession();
      const token = csrf.issue(session);
      expect(token).toMatch(/^[0-9a-f]{64}$/);
      tokens.add(token);
    }
    expect(tokens.size).toBe(20);
  });

  it('c-crypto-1 an OTP is six digits, differs between issues, and is stored hashed', async () => {
    const user = await makeUser('crypto-otp', 'crypto-otp@test.example', 'Passw0rdLong1');
    const codes = [];
    for (let i = 0; i < 5; i += 1) codes.push(await mfa.issueCode(Number(user.id)));

    for (const code of codes) expect(code).toMatch(/^\d{6}$/);
    expect(new Set(codes).size).toBeGreaterThanOrEqual(4);

    const stored = await row('SELECT code_hash FROM mfa_codes WHERE user_id = ? ORDER BY id DESC LIMIT 1', [Number(user.id)]);
    // bcryptjs writes the $2b$ variant of the same algorithm PHP writes as $2y$.
    expect(stored.code_hash).toMatch(/^\$2[aby]\$\d\d\$/);
    expect(stored.code_hash).not.toContain(codes[codes.length - 1]);
  });

  it('c-crypto-1 an upload name is a generated uuid, never the client name', async () => {
    // A client name is never a path: only an accepted part is stored, and the
    // stored name is this app's own uuid.
    for (const filename of ['../../etc/passwd.png', 'shell.php.png', 'photo.png.png', 'photo.exe']) {
      expect(uploads.inspect({ buffer: PNG, filename, mimeType: 'image/png' }).ok).toBe(false);
    }

    const first = uploads.store({ buffer: PNG, filename: 'photo.png', mimeType: 'image/png' });
    const second = uploads.store({ buffer: PNG, filename: 'photo.png', mimeType: 'image/png' });

    for (const name of [first, second]) expect(name).toMatch(/^[0-9a-f-]{36}\.png$/);
    expect(first).not.toBe(second);
  });

  it('c-crypto-1 password hashing is bcryptjs at cost 10 or more, and salts differ', async () => {
    expect(passwords.BCRYPT_COST).toBeGreaterThanOrEqual(10);

    const a = await passwords.hash('Passw0rdLong1');
    const b = await passwords.hash('Passw0rdLong1');

    expect(a).toMatch(/^\$2[aby]\$\d\d\$/);
    expect(a).not.toBe(b);
    expect(await passwords.verify('Passw0rdLong1', a)).toBe(true);
    expect(await passwords.verify('Passw0rdLong2', a)).toBe(false);
  });

  it('c-crypto-1 the timing equaliser is a real bcrypt string of the same cost', async () => {
    expect(passwords.TIMING_EQUALIZER_HASH).toMatch(/^\$2y\$\d\d\$/);
    // Verifying against it must be a normal, non-shortcutting operation.
    expect(await passwords.verify('anything', passwords.TIMING_EQUALIZER_HASH)).toBe(false);
  });
});
