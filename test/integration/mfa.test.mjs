// Port of tests/Integration/MfaTest.php.
//
// The PHP case expired a code by rewriting `expires_at`; the Node case moves the
// app clock forward instead (docs/04 section 2), which also proves the TTL logic
// is real rather than a row update.

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { row, truncateAll } from '../helpers/db.mjs';
import { makeUser } from '../helpers/users.mjs';
import * as mfa from '../../src/security/mfa.js';
import { setClockForTests } from '../../src/lib/clock.js';
import { verify as verifyHash } from '../../src/security/passwords.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

afterEach(() => {
  setClockForTests(null);
});

describe('mfa', () => {
  it('testIssuedCodeIsSixDigits', async () => {
    const user = await makeUser('mfa-user');
    const code = await mfa.issueCode(Number(user.id));

    expect(code).toMatch(/^\d{6}$/);
  });

  it('testCodeIsStoredHashedNotPlaintext', async () => {
    const user = await makeUser('mfa-hash');
    const code = await mfa.issueCode(Number(user.id));

    const stored = await row('SELECT code_hash FROM mfa_codes ORDER BY id DESC LIMIT 1');
    expect(stored.code_hash).not.toBe(code);
    expect(await verifyHash(code, String(stored.code_hash))).toBe(true);
  });

  it('testCorrectCodeVerifies', async () => {
    const user = await makeUser('mfa-ok');
    const code = await mfa.issueCode(Number(user.id));

    expect(await mfa.verify(Number(user.id), code)).toEqual([]);
  });

  it('testCodeIsSingleUse', async () => {
    const user = await makeUser('mfa-single');
    const code = await mfa.issueCode(Number(user.id));

    expect(await mfa.verify(Number(user.id), code)).toEqual([]);
    expect(await mfa.verify(Number(user.id), code)).not.toEqual([]);
  });

  it('testWrongCodeIsRejected', async () => {
    const user = await makeUser('mfa-wrong');
    await mfa.issueCode(Number(user.id));

    await mfa.verify(Number(user.id), '000000');
    const code = await mfa.issueCode(Number(user.id)); // also invalidates the previous one
    const wrong = code === '123456' ? '654321' : '123456';

    expect(await mfa.verify(Number(user.id), wrong)).not.toEqual([]);
    expect(await mfa.verify(Number(user.id), code)).toEqual([]);
  });

  it('testNonNumericInputRejected', async () => {
    const user = await makeUser('mfa-shape');
    await mfa.issueCode(Number(user.id));

    for (const submitted of ['abc', '12345', '', "12'456"]) {
      expect(await mfa.verify(Number(user.id), submitted)).not.toEqual([]);
    }
  });

  it('testMaxAttemptsLocksCode', async () => {
    const user = await makeUser('mfa-attempts');
    const code = await mfa.issueCode(Number(user.id));
    const wrong = code === '111111' ? '222222' : '111111';

    for (let i = 0; i < 5; i++) await mfa.verify(Number(user.id), wrong);

    // The correct code must now be rejected: too many attempts.
    expect(await mfa.verify(Number(user.id), code)).not.toEqual([]);
  });

  it('testExpiredCodeIsRejected', async () => {
    const user = await makeUser('mfa-expired');
    const code = await mfa.issueCode(Number(user.id));

    const issuedAt = Date.now();
    setClockForTests(() => new Date(issuedAt + (mfa.ttlMinutes() + 1) * 60_000));

    const result = await mfa.verify(Number(user.id), code);
    expect(result).not.toEqual([]);
    expect(result[0].toLowerCase()).toContain('expired');
  });

  it('testNewIssueInvalidatesPreviousCode', async () => {
    const user = await makeUser('mfa-invalidate');
    const first = await mfa.issueCode(Number(user.id));
    const second = await mfa.issueCode(Number(user.id));

    // First code no longer works…
    if (first !== second) {
      expect(await mfa.verify(Number(user.id), first)).not.toEqual([]);
    }
    // …second one does
    expect(await mfa.verify(Number(user.id), second)).toEqual([]);
  });

  it('testCodeTiedToCorrectUser', async () => {
    const userA = await makeUser('mfa-a');
    const userB = await makeUser('mfa-b');
    const codeA = await mfa.issueCode(Number(userA.id));

    if (Number(userA.id) !== Number(userB.id)) {
      expect(await mfa.verify(Number(userB.id), codeA)).not.toEqual([]);
    }
  });
});
