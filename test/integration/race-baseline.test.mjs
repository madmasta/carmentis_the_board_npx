// C-RACE-1 — one-shot invariants under concurrency (docs/03).
//
// `race_condition` removes the row lock and widens the window; these cases are
// what it must break. They assert counts, never elapsed time, so they are not
// timing tests wearing a security name.

import { beforeEach, describe, expect, it } from 'vitest';
import { count, row, truncateAll } from '../helpers/db.mjs';
import { agent, csrfToken, loginAs, postForm } from '../helpers/http.mjs';
import { clear, lastCode, messages } from '../helpers/mailbox.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import * as users from '../../src/repositories/user.repository.js';
import * as votes from '../../src/repositories/vote.repository.js';
import { verify as verifyPassword } from '../../src/security/passwords.js';

const CONCURRENCY = 20;
// Voting twice removes a vote, so a serialized replay of an even number of
// identical votes ends with none. An odd count has a single determinate end
// state, which is what the invariant below asserts.
const ODD_CONCURRENCY = 21;

beforeEach(async () => {
  await truncateAll();
  clear();
});

describe('c-race-1 single-use resources', () => {
  it('c-race-1 twenty parallel OTP replays leave exactly one winner', async () => {
    const user = await makeUser('race-mfa', 'race-mfa@test.example', 'RacePass1234');
    await users.setMfaEnabled(Number(user.id), true);

    const http = await agent();
    await loginAs(http, 'race-mfa@test.example', 'RacePass1234');

    const code = await lastCode('race-mfa@test.example');
    expect(code).toMatch(/^\d{6}$/);
    const token = await csrfToken(http, '/mfa');

    const responses = await Promise.all(
      Array.from({ length: CONCURRENCY }, () => http.post('/mfa').type('form').send({ csrf_token: token, code })),
    );

    const accepted = responses.filter((res) => res.status === 303 && res.headers.location === '/');
    expect(accepted).toHaveLength(1);
    expect(responses.filter((res) => res.status !== 303 || res.headers.location !== '/')).toHaveLength(CONCURRENCY - 1);

    // The row is spent exactly once, and no second challenge was minted.
    expect(await count('SELECT COUNT(*) FROM mfa_codes WHERE used_at IS NOT NULL')).toBe(1);
    expect(await count('SELECT COUNT(*) FROM mfa_codes WHERE used_at IS NULL')).toBe(0);
  });

  it('c-race-1-vote twenty parallel votes from one user leave one vote row and score 1', async () => {
    const owner = await makeUser('race-owner', 'race-owner@test.example', 'RacePass1234');
    const voter = await makeUser('race-voter', 'race-voter@test.example', 'RacePass1234');
    const boardId = Number((await makeBoard('Race Board', true, Number(owner.id))).id);
    const postId = Number(await makeThread(boardId, Number(owner.id), 'Race thread', 'body'));

    const http = await agent();
    await loginAs(http, 'race-voter@test.example', 'RacePass1234');
    const token = await csrfToken(http, `/thread/${postId}`);

    const responses = await Promise.all(
      Array.from({ length: ODD_CONCURRENCY }, () => http.post('/vote').type('form').send({ csrf_token: token, post_id: String(postId), value: '1' })),
    );
    expect(responses.map((res) => res.status), JSON.stringify(responses.map((r) => r.status))).toEqual(Array(ODD_CONCURRENCY).fill(303));

    expect(await count('SELECT COUNT(*) FROM votes WHERE post_id = ? AND user_id = ?', [postId, Number(voter.id)])).toBe(1);
    expect(await votes.score(postId)).toBe(1);
  });

  it('c-race-1-vote concurrent voters each get their own row', async () => {
    const owner = await makeUser('race-owner2', 'race-owner2@test.example', 'RacePass1234');
    const boardId = Number((await makeBoard('Race Board 2', true, Number(owner.id))).id);
    const postId = Number(await makeThread(boardId, Number(owner.id), 'Race thread 2', 'body'));

    const emails = [];
    for (let i = 0; i < 6; i += 1) {
      const email = `race-fan${i}@test.example`;
      await makeUser(`race_fan${i}`, email, 'RacePass1234');
      emails.push(email);
    }

    const attempts = await Promise.all(
      emails.map(async (email) => {
        const http = await agent();
        await loginAs(http, email, 'RacePass1234');
        const token = await csrfToken(http, `/thread/${postId}`);
        return http.post('/vote').type('form').send({ csrf_token: token, post_id: String(postId), value: '1' });
      }),
    );

    expect(attempts.map((res) => res.status), JSON.stringify(attempts.map((r) => r.status))).toEqual(Array(6).fill(303));
    expect(await count('SELECT COUNT(*) FROM votes WHERE post_id = ?', [postId])).toBe(6);
    expect(await votes.score(postId)).toBe(6);
  });

  it('c-race-1-token a reset token replayed in parallel changes the password once', async () => {
    await makeUser('race-reset', 'race-reset@test.example', 'RacePass1234');

    const http = await agent();
    await postForm(http, '/forgot-password', { email: 'race-reset@test.example' }, '/forgot-password');
    const token = /\/reset-password\?token=([A-Za-z0-9._-]+)/.exec(messages().at(-1).body)[1];

    const results = await Promise.all(
      Array.from({ length: 8 }, () => postForm(http, '/reset-password', { token, password: 'RotatedPass123', password_confirm: 'RotatedPass123' }, '/reset-password')),
    );

    const spent = await count('SELECT COUNT(*) FROM jwt_claims');
    expect(spent).toBe(1);
    expect(results.filter((res) => res.status === 303)).toHaveLength(1);

    const check = await row('SELECT password_hash FROM users WHERE email = ?', ['race-reset@test.example']);
    expect(await verifyPassword('RotatedPass123', check.password_hash)).toBe(true);
  });
});
