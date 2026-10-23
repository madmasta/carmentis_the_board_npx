// Port of tests/Integration/LoginThrottleTest.php — the development kill switch
// for brute-force throttling (docs/03 C-AUTH-3).

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll } from '../helpers/db.mjs';
import { fakeContext, makeUser } from '../helpers/users.mjs';
import { attemptLogin } from '../../src/auth/login.js';
import {
  ENV_FLAG,
  STATUS_DISABLED,
  STATUS_ENFORCED,
  STATUS_REFUSED,
  bannerText,
  isDisabled,
  status,
  warningBlock,
} from '../../src/security/login-throttle.js';
import * as users from '../../src/repositories/user.repository.js';

async function burnAttempts(email, ip, n) {
  for (let i = 0; i < n; i++) await users.recordAttempt(email, ip, false);
}

function setFlag(flag, debug) {
  process.env[ENV_FLAG] = flag;
  process.env.APP_DEBUG = debug;
}

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

afterEach(() => {
  // Back to the suite baseline (docs/04 section 2, item 6).
  process.env[ENV_FLAG] = '0';
  process.env.APP_DEBUG = '0';
});

describe('login throttle kill switch', () => {
  it('testThrottleIsEnforcedByDefault', async () => {
    await makeUser('tina', 'tina@test.example', 'RealPassword1');
    await burnAttempts('tina@test.example', '10.9.0.1', 5);

    expect(status()).toBe(STATUS_ENFORCED);
    const result = await attemptLogin(fakeContext(), 'tina@test.example', 'RealPassword1', '10.9.0.1');
    expect(result.status).toBe('throttled');
  });

  it('testFlagDisablesThrottleWhenDebugIsOn', async () => {
    setFlag('1', '1');
    await makeUser('umar', 'umar@test.example', 'RealPassword1');
    await burnAttempts('umar@test.example', '10.9.0.2', 50);

    expect(status()).toBe(STATUS_DISABLED);
    expect(isDisabled()).toBe(true);
    const result = await attemptLogin(fakeContext(), 'umar@test.example', 'RealPassword1', '10.9.0.2');
    expect(result.status).toBe('ok');
  });

  it('testDisabledThrottleStillRejectsWrongPasswords', async () => {
    setFlag('1', '1');
    await makeUser('vera', 'vera@test.example', 'RealPassword1');
    await burnAttempts('vera@test.example', '10.9.0.3', 50);

    // No lockout, but the password still has to be right.
    const result = await attemptLogin(fakeContext(), 'vera@test.example', 'WrongPassword1', '10.9.0.3');
    expect(result.status).toBe('invalid');
  });

  it('testFailedAttemptsAreStillRecordedWhileDisabled', async () => {
    setFlag('1', '1');
    await makeUser('wes', 'wes@test.example', 'RealPassword1');

    await attemptLogin(fakeContext(), 'wes@test.example', 'WrongPassword1', '10.9.0.4');

    // The audit trail survives even though it no longer gates anything.
    expect(await users.recentFailureCount('wes@test.example', '10.9.0.4', 15)).toBe(1);
  });

  it('testFlagIsRefusedWhenDebugIsOff', async () => {
    setFlag('1', '0');
    await makeUser('xena', 'xena@test.example', 'RealPassword1');
    await burnAttempts('xena@test.example', '10.9.0.5', 5);

    expect(status()).toBe(STATUS_REFUSED);
    expect(isDisabled()).toBe(false);
    const result = await attemptLogin(fakeContext(), 'xena@test.example', 'RealPassword1', '10.9.0.5');
    expect(result.status).toBe('throttled');
  });

  it('testRefusalIsNotSilent', () => {
    setFlag('1', '0');
    const banner = bannerText();

    expect(banner).not.toBeNull();
    expect(banner).toContain('IGNORED');
    expect(warningBlock()).not.toBeNull();
  });

  it('testBannerWarnsWhileDisabledAndIsSilentWhenEnforced', () => {
    setFlag('1', '1');
    const banner = bannerText();
    expect(banner).not.toBeNull();
    expect(banner).toContain('DISABLED');

    setFlag('0', '1');
    expect(bannerText()).toBeNull();
    expect(warningBlock()).toBeNull();
  });
});
