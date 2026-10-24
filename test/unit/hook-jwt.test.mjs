// C-JWT-1 proof file (docs/03): pinned algorithm, real secret, short expiry,
// single use.

import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import jwt from 'jsonwebtoken';

import { root } from '../../src/db/admin.js';
import { count } from '../helpers/db.mjs';
import { setKeys, restore } from '../helpers/env.mjs';
import {
  INVALID_TOKEN,
  JWT_ALGORITHMS,
  JWT_MAX_AGE_SECONDS,
  consume,
  decode,
  issue,
  isConsumed,
  resetLink,
  resetSecretCache,
  signingSecret,
  verifyActive,
} from '../../src/security/jwt.js';

const SECRET = 'a-generated-signing-key-of-thirty-two-plus-bytes-0123456789';

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

beforeAll(async () => {
  resetSecretCache();
});

beforeEach(async () => {
  setKeys({ JWT_SECRET: SECRET, APP_URL: 'http://localhost:8088' });
  resetSecretCache();
  await execute('DELETE FROM jwt_claims');
});

afterEach(() => {
  restore();
  resetSecretCache();
});

async function execute(sql, params = []) {
  const mod = await import('../../src/db/connection.js');
  return mod.execute(sql, params);
}

describe('signed tokens (C-JWT-1)', () => {
  it('issues and verifies a token for its purpose', async () => {
    const { token, jti, maxAgeSeconds } = issue({ sub: '7', purpose: 'password_reset' });

    expect(maxAgeSeconds).toBe(JWT_MAX_AGE_SECONDS);
    expect(JWT_MAX_AGE_SECONDS).toBe(900);

    const checked = await consume(token, 'password_reset');
    expect(checked.ok).toBe(true);
    expect(checked.payload.sub).toBe('7');
    expect(checked.payload.jti).toBe(jti);
    expect(checked.payload.iss).toBe('theboard');
  });

  it('a token is only good for the purpose it was minted for', async () => {
    const { token } = issue({ sub: '7', purpose: 'password_reset' });

    expect((await consume(token, 'remember_me')).message).toBe(INVALID_TOKEN);
    expect(() => issue({ sub: '7', purpose: 'session' })).toThrow(/Unknown token purpose/);
  });

  it('c-jwt-1 refuses an alg:none token', async () => {
    const { token } = issue({ sub: '7', purpose: 'password_reset' });
    const [, payload] = token.split('.');
    const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${payload}.`;

    expect(await consume(unsigned, 'password_reset')).toEqual({ ok: false, message: INVALID_TOKEN });
    expect(decode(unsigned, 'password_reset').ok).toBe(false);
  });

  it('c-jwt-1 refuses an algorithm substitution in the header', async () => {
    const { token } = issue({ sub: '7', purpose: 'password_reset' });
    const [, payload] = token.split('.');
    const spoofed = `${b64({ alg: 'RS256', typ: 'JWT' })}.${payload}.${token.split('.')[2]}`;

    expect(decode(spoofed, 'password_reset').ok).toBe(false);
    expect((await consume(spoofed, 'password_reset')).ok).toBe(false);

    // The verify call lists one algorithm, and it is HS256.
    expect(JWT_ALGORITHMS).toEqual(['HS256']);
  });

  it('c-jwt-1 refuses a token signed with a different key', async () => {
    const payload = { sub: '7', purpose: 'password_reset', iss: 'theboard', jti: 'deadbeef' };
    const forged = jwt.sign(payload, 'the-wrong-key-but-long-enough-to-be-plausible-321', {
      algorithm: 'HS256',
      expiresIn: 600,
    });

    expect(decode(forged, 'password_reset').ok).toBe(false);
    expect((await consume(forged, 'password_reset')).ok).toBe(false);
  });

  it('c-jwt-1 refuses an expired token', async () => {
    // Minted already-expired: the same shape the library produces for a token
    // whose 15 minutes have run out.
    const expired = jwt.sign(
      { sub: '7', purpose: 'password_reset', iss: 'theboard', jti: 'expired-claim' },
      SECRET,
      { algorithm: 'HS256', expiresIn: -60 },
    );

    expect(decode(expired, 'password_reset').ok).toBe(false);
    expect((await consume(expired, 'password_reset')).ok).toBe(false);
    expect(issue({ sub: '7', purpose: 'password_reset', maxAgeSeconds: 'junk' }).maxAgeSeconds).toBe(900);
  });

  it('c-jwt-1 the lifetime can be shortened but never lengthened', () => {
    expect(issue({ sub: '7', purpose: 'remember_me', maxAgeSeconds: 60 }).maxAgeSeconds).toBe(60);
    expect(issue({ sub: '7', purpose: 'remember_me', maxAgeSeconds: 10 * 24 * 3600 }).maxAgeSeconds).toBe(900);

    const { token } = issue({ sub: '7', purpose: 'remember_me', maxAgeSeconds: 10 * 24 * 3600 });
    expect(jwt.decode(token).exp - jwt.decode(token).iat).toBe(900);
  });

  it('c-jwt-1 a spent token is refused, however valid its signature is', async () => {
    const { token, jti } = issue({ sub: '7', purpose: 'password_reset' });

    expect(await consume(token, 'password_reset')).toMatchObject({ ok: true });
    expect(await isConsumed(jti)).toBe(true);
    expect(await consume(token, 'password_reset')).toEqual({ ok: false, message: INVALID_TOKEN });
    expect(await consume(token, 'password_reset')).toEqual({ ok: false, message: INVALID_TOKEN });
    expect(await count('SELECT COUNT(*) FROM jwt_claims')).toBe(1);
  });

  it('c-jwt-1 two simultaneous replays: exactly one wins', async () => {
    const { token } = issue({ sub: '7', purpose: 'password_reset' });
    const results = await Promise.all([consume(token, 'password_reset'), consume(token, 'password_reset')]);

    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(await count('SELECT COUNT(*) FROM jwt_claims')).toBe(1);
  });

  it('remember-me tokens stay usable until they expire', async () => {
    const { token } = issue({ sub: '7', purpose: 'remember_me' });

    expect((await verifyActive(token, 'remember_me')).ok).toBe(true);
    expect((await verifyActive(token, 'remember_me')).ok).toBe(true);
    // A consumed reset token is not usable through this path either.
    const reset = issue({ sub: '7', purpose: 'password_reset' });
    await consume(reset.token, 'password_reset');
    expect((await verifyActive(reset.token, 'password_reset')).ok).toBe(false);
  });

  it('c-crypto-1 the key is long, random, file-backed and never hardcoded', () => {
    const secret = signingSecret();
    expect(Buffer.byteLength(secret, 'utf8')).toBeGreaterThanOrEqual(32);
    expect(secret).toBe(SECRET);

    setKeys({ JWT_SECRET: 'short' });
    resetSecretCache();
    expect(() => signingSecret()).toThrow(/at least 32 bytes/);
    restore();
    resetSecretCache();

    setKeys({ JWT_SECRET: '' });
    resetSecretCache();
    // No env key: a key is generated once into var/secret.key, at 0600.
    const path = join(root(), 'var', 'secret.key');
    const existed = existsSync(path);
    const generated = signingSecret();
    expect(Buffer.byteLength(generated, 'utf8')).toBeGreaterThanOrEqual(64);
    expect(existsSync(path)).toBe(true);
    if (!existed) rmSync(path, { force: true });
    restore();
    resetSecretCache();
  });

  it('the reset link is built from APP_URL, never from the request', () => {
    expect(resetLink('tok en')).toBe('http://localhost:8088/reset-password?token=tok%20en');

    setKeys({ APP_URL: 'https://board.example.com/' });
    expect(resetLink('t')).toBe('https://board.example.com/reset-password?token=t');
    restore();
  });
});
