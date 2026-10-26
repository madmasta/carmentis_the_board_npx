// C-SESS-1 and C-SESS-2 — cookie discipline and store hygiene (docs/03).
//
// `session_management` downgrades one of these two; the case names carry the
// slug so a branch skips exactly what it broke.

import { beforeEach, describe, expect, it } from 'vitest';
import { count, row, rows, truncateAll } from '../helpers/db.mjs';
import { fakeReq, fakeRes } from '../helpers/ctx.mjs';
import { agent, csrfToken, loginAs, sessionIdFrom } from '../helpers/http.mjs';
import { makeUser } from '../helpers/users.mjs';
import * as store from '../../src/session/store.js';

/** The JSON column arrives parsed here and as text there; accept both. */
function payloadOf(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function cookieLines(res) {
  const value = res.getHeader?.('set-cookie') ?? [];
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

beforeEach(async () => {
  await truncateAll();
});

describe('cookie and session-id discipline (C-SESS-1)', () => {
  it('the session cookie carries the pinned attributes and nothing else', async () => {
    const req = fakeReq({ cookies: {} });
    const res = fakeRes();

    const session = await store.start(req, res);
    await store.save(session, res);

    const cookie = cookieLines(res).find((line) => line.startsWith('theboard_session='));
    expect(cookie).toBeDefined();
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).not.toContain('Domain');
    expect(cookie).not.toContain('Max-Age'); // session-scoped
    expect(cookie.split(';')[0]).toMatch(/^theboard_session=[0-9a-f]{32}$/);
  });

  it('Secure is added only for an https socket', async () => {
    const plain = fakeRes();
    const secure = fakeRes();
    await store.save(await store.start(fakeReq({ cookies: {} }), plain), plain, { https: false });
    await store.save(await store.start(fakeReq({ cookies: {} }), secure), secure, { https: true });

    expect(cookieLines(plain).join()).not.toContain('Secure');
    expect(cookieLines(secure).join()).toContain('Secure');
  });

  it('ids are 128 bits of entropy and never repeat', async () => {
    const ids = new Set();
    for (let i = 0; i < 10; i += 1) {
      const res = fakeRes();
      const session = await store.start(fakeReq({ cookies: {} }), res);
      expect(session.id).toMatch(/^[0-9a-f]{32}$/);
      ids.add(session.id);
    }
    expect(ids.size).toBe(10);
  });

  it('c-sess-1 an unknown presented id is never adopted', async () => {
    const forged = 'a'.repeat(32);
    const res = fakeRes();

    const session = await store.start(fakeReq({ cookies: { theboard_session: forged } }), res);
    expect(session.id).not.toBe(forged);
    expect(await count('SELECT COUNT(*) FROM sessions WHERE id = ?', [forged])).toBe(0);
    expect(cookieLines(res).at(-1)).toContain(session.id);
  });

  it('c-sess-1 a malformed presented id is ignored, not looked up', async () => {
    for (const forged of ['../../etc/passwd', "a' OR 1=1--", 'short', 'A'.repeat(32)]) {
      const res = fakeRes();
      const session = await store.start(fakeReq({ cookies: { theboard_session: forged } }), res);
      expect(session.id).toMatch(/^[0-9a-f]{32}$/);
    }

    // Nothing was adopted: every row this created carries a generated id.
    const stored = await rows('SELECT id FROM sessions');
    for (const record of stored) expect(record.id).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe('session regeneration and store hygiene', () => {
  it('c-sess-2 regenerate issues a new id and deletes the old row', async () => {
    const res = fakeRes();
    const session = await store.start(fakeReq({ cookies: {} }), res);
    const before = session.id;

    await store.regenerate(session, res);

    expect(session.id).not.toBe(before);
    expect(await count('SELECT COUNT(*) FROM sessions WHERE id = ?', [before])).toBe(0);
    expect(await count('SELECT COUNT(*) FROM sessions WHERE id = ?', [session.id])).toBe(1);
    expect(cookieLines(res).at(-1)).toContain(session.id);
  });

  it('c-sess-2 the id rotates at login and the pre-login row is gone', async () => {
    await makeUser('sess-user', 'sess-user@test.example', 'Passw0rdLong1');
    const http = await agent();

    const anonId = sessionIdFrom(await http.get('/login'));
    await loginAs(http, 'sess-user@test.example', 'Passw0rdLong1');
    const authId = sessionIdFrom(await http.get('/profile'));

    expect(authId).not.toBe(anonId);
    expect(await count('SELECT COUNT(*) FROM sessions WHERE id = ?', [anonId])).toBe(0);
    const stored = await row('SELECT user_id, data FROM sessions WHERE id = ?', [authId]);
    expect(Number(stored.user_id)).toBeGreaterThan(0);
    expect(payloadOf(stored.data).auth_user_id).toBe(Number(stored.user_id));
  });

  it('c-sess-2 logout clears authentication and mints a fresh anonymous id', async () => {
    await makeUser('sess-out', 'sess-out@test.example', 'Passw0rdLong1');
    const http = await agent();
    await loginAs(http, 'sess-out@test.example', 'Passw0rdLong1');
    const authId = sessionIdFrom(await http.get('/profile'));

    const token = await csrfToken(http, '/profile');
    const out = await http.post('/logout').type('form').send({ csrf_token: token });
    expect(out.status).toBe(303);

    const afterId = sessionIdFrom(out);
    expect(afterId).not.toBe(authId);
    expect(await count('SELECT COUNT(*) FROM sessions WHERE id = ?', [authId])).toBe(0);

    expect((await http.get('/profile')).status).toBe(303);
  });

  it('expired rows are swept by ordinary traffic', async () => {
    await row('SELECT 1');
    await truncateAll();
    // An expired session row, written the way the store writes them.
    await row("INSERT INTO sessions (id, data, expires_at) VALUES ('ffffffffffffffffffffffffffffffff', '{}', '2000-01-01 00:00:00')");
    expect(await count('SELECT COUNT(*) FROM sessions')).toBe(1);

    const res = fakeRes();
    await store.start(fakeReq({ cookies: {} }), res);

    expect(await count('SELECT COUNT(*) FROM sessions WHERE id = ?', ['ffffffffffffffffffffffffffffffff'])).toBe(0);
  });

  it('the session payload stays server-side; the cookie holds only the id', async () => {
    await makeUser('sess-body', 'sess-body@test.example', 'Passw0rdLong1');
    const http = await agent();
    const login = await loginAs(http, 'sess-body@test.example', 'Passw0rdLong1');

    const cookie = (login.headers['set-cookie'] ?? []).map(String).join('\n');
    expect(cookie).not.toContain('sess-body');
    expect(cookie).not.toContain('auth_user_id');

    const stored = await rows('SELECT data FROM sessions');
    expect(stored.length).toBeGreaterThan(0);
    expect(stored.some((s) => 'auth_user_id' in payloadOf(s.data))).toBe(true);
  });
});
