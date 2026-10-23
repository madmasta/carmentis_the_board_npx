// Port of tests/Integration/AuthTest.php.
//
// The PHP cases call Auth::attemptLogin directly, so the Node cases call the
// ported function with a fabricated context (test/helpers/users.mjs#fakeContext).
// The same flow over HTTP — cookies, CSRF, redirects — is exercised by the route
// level proofs in test/security/controls.test.mjs.

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll } from '../helpers/db.mjs';
import { fakeContext, makeUser } from '../helpers/users.mjs';
import { attemptLogin } from '../../src/auth/login.js';
import { setClockForTests } from '../../src/lib/clock.js';
import * as users from '../../src/repositories/user.repository.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

afterEach(() => {
  setClockForTests(null);
});

describe('auth', () => {
  it('testLoginSucceedsWithCorrectCredentials', async () => {
    const user = await makeUser('alice', 'alice@test.example', 'CorrectHorse1');
    const ctx = fakeContext();

    const result = await attemptLogin(ctx, 'alice@test.example', 'CorrectHorse1', '127.0.0.1');

    expect(result.status).toBe('ok');
    expect(Number(result.user.id)).toBe(Number(user.id));
  });

  it('testLoginRejectsWrongPassword', async () => {
    await makeUser('bob', 'bob@test.example', 'CorrectHorse1');

    const result = await attemptLogin(fakeContext(), 'bob@test.example', 'WrongPassword1', '10.0.0.1');

    expect(result.status).toBe('invalid');
  });

  it('testLoginIsCaseInsensitiveOnEmail', async () => {
    await makeUser('carol', 'Carol@TEST.example', 'Password12345');

    const result = await attemptLogin(fakeContext(), 'carol@test.example', 'Password12345', '10.0.0.2');

    expect(result.status).toBe('ok');
  });

  it('testUnknownAccountDoesNotLeakExistence', async () => {
    const result = await attemptLogin(fakeContext(), 'ghost@test.example', 'Whatever123x', '10.0.0.3');

    expect(result.status).toBe('invalid');
  });

  it('testBannedAccountIsRejected', async () => {
    const user = await makeUser('mallory', 'mallory@test.example', 'BannedBut1');
    await users.setBanned(Number(user.id), true, 'spam');

    const result = await attemptLogin(fakeContext(), 'mallory@test.example', 'BannedBut1', '10.0.0.4');

    expect(result.status).toBe('banned');
  });

  it('testBannedAccountWithWrongPasswordLooksLikeInvalidLogin', async () => {
    const user = await makeUser('eve', 'eve@test.example', 'RealPassword1');
    await users.setBanned(Number(user.id), true, null);

    const result = await attemptLogin(fakeContext(), 'eve@test.example', 'TotallyWrong', '10.0.0.5');

    // Wrong password + banned → generic invalid, no information leak.
    expect(result.status).toBe('invalid');
  });

  it('testLoginThrottleAfterRepeatedFailures', async () => {
    await makeUser('frank', 'frank@test.example', 'RealPassword1');

    for (let i = 0; i < 5; i++) {
      const result = await attemptLogin(fakeContext(), 'frank@test.example', `BadPassword${i}`, '10.0.0.9');
      expect(result.status).toBe('invalid');
    }

    // Even the CORRECT password is now rejected.
    const result = await attemptLogin(fakeContext(), 'frank@test.example', 'RealPassword1', '10.0.0.9');
    expect(result.status).toBe('throttled');
  });

  it('testThrottleIsPerEmailAndIp', async () => {
    await makeUser('grace', 'grace@test.example', 'RealPassword2');
    await makeUser('grace2', 'grace2@test.example', 'RealPassword2');

    for (let i = 0; i < 5; i++) {
      await attemptLogin(fakeContext(), 'grace@test.example', 'BadGuess1', '10.0.1.1');
    }

    // A different email AND a different IP shares nothing with those failures.
    const other = await attemptLogin(fakeContext(), 'grace2@test.example', 'RealPassword2', '10.0.1.2');
    expect(other.status).toBe('ok');
  });

  it('testFailuresExpireAfterWindow', async () => {
    await makeUser('heidi', 'heidi@test.example', 'RealPassword3');

    for (let i = 0; i < 5; i++) {
      await users.recordAttempt('heidi@test.example', '10.0.2.1', false);
    }

    // Age the attempts out of the window by moving the clock, not by rewriting
    // rows behind the application's back (docs/04 section 2).
    const base = Date.now();
    setClockForTests(() => new Date(base + 16 * 60_000));

    const result = await attemptLogin(fakeContext(), 'heidi@test.example', 'RealPassword3', '10.0.2.1');
    expect(result.status).toBe('ok');
  });

  it('testSuccessfulLoginResetsNothingButRecordsSuccess', async () => {
    await makeUser('ivan', 'ivan@test.example', 'RealPassword4');
    await attemptLogin(fakeContext(), 'ivan@test.example', 'RealPassword4', '10.0.3.1');

    expect(await users.recentFailureCount('ivan@test.example', '10.0.2.2', 15)).toBe(0);
  });

  it('testEmptyCredentialsRejected', async () => {
    expect((await attemptLogin(fakeContext(), '', 'x', '1.2.3.4')).status).toBe('invalid');
    expect((await attemptLogin(fakeContext(), 'a@b.c', '', '1.2.3.4')).status).toBe('invalid');
  });
});
