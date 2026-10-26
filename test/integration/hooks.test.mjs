// Hook route behaviour (docs/02 section 7 failure contract, docs/04 section 3).
//
// These are the strings and statuses the spec pins; an exploit test on a vuln
// branch asserts that its own payload changes exactly one of them.

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { count, row, truncateAll } from '../helpers/db.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import { agent, csrfToken, loginAs, postForm } from '../helpers/http.mjs';
import { clearMailLog, readMailLog } from '../../src/mail/mailer.js';
import * as boards from '../../src/repositories/board.repository.js';
import * as users from '../../src/repositories/user.repository.js';

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x09]);
const SVG = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'utf8');

let admin;
let pleb;
let boardId;
let threadId;

/** The rendered table, so the navigation (which shows the logged-in name) is not part of the assertion. */
function bodyOf(html) {
  const start = html.indexOf('<tbody>');
  const end = html.indexOf('</table>', start);
  return start === -1 || end === -1 ? '' : html.slice(start, end);
}

/** Only the messages addressed to `to`, so a shared mail log cannot leak between cases. */
function mailTo(to) {
  // Records are separated by a line that is exactly four dashes; the 40-dash line
  // inside a record is a header rule, not a separator.
  return readMailLog()
    .split('\n----\n')
    .filter((entry) => entry.includes(`TO: ${to}`))
    .join('\n');
}

async function signIn() {
  const http = await agent();
  await loginAs(http, 'hook-admin@test.example', 'AdminPass123');
  return http;
}

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
  clearMailLog();
  admin = await makeUser('hook-admin', 'hook-admin@test.example', 'AdminPass123', 'admin');
  pleb = await makeUser('hook-pleb', 'hook-pleb@test.example', 'PlebPass123');
  boardId = Number((await makeBoard('Hook Board', true, Number(admin.id))).id);
  threadId = await makeThread(boardId, Number(admin.id), 'Hook thread', 'body with [b]markup[/b] and <script>alert(1)</script>');
});

describe('avatar upload (POST /profile/avatar, GET /avatar/:id)', () => {
  it('c-upload-1 accepts a real png and serves it back with a fixed content type', async () => {
    const http = await signIn();
    const token = await csrfToken(http, '/profile');

    const res = await http.post('/profile/avatar').field('csrf_token', token).attach('avatar', PNG, 'me.png');
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/profile');
    expect((await http.get('/profile')).text).toMatch(/Avatar updated\./);

    const stored = String((await users.findById(Number(admin.id))).avatar_path);
    expect(stored).toMatch(/^[0-9a-f-]{36}\.png$/);

    const image = await http.get(`/avatar/${admin.id}`);
    expect(image.status).toBe(200);
    expect(image.headers['content-type']).toBe('image/png');
    expect(image.headers['x-content-type-options']).toBe('nosniff');
    expect(image.headers['content-disposition']).toBe(`inline; filename="${stored}"`);
  });

  it('c-upload-1 refuses an svg with the pinned message', async () => {
    const http = await signIn();
    const token = await csrfToken(http, '/profile');

    const res = await http.post('/profile/avatar').field('csrf_token', token).attach('avatar', SVG, 'icon.svg');
    expect(res.status).toBe(400);
    expect(res.text).toContain('Unsupported file type. Allowed: image/png, image/jpeg, image/gif, image/webp.');
    expect((await users.findById(Number(admin.id))).avatar_path).toBeNull();
  });

  it('c-upload-1 an oversized part is refused before the handler runs', async () => {
    const http = await signIn();
    const token = await csrfToken(http, '/profile');
    const big = Buffer.concat([PNG.subarray(0, 8), Buffer.alloc(2 * 1024 * 1024 + 1024, 0x42)]);

    const res = await http.post('/profile/avatar').field('csrf_token', token).attach('avatar', big, 'big.png');
    expect(res.status).toBe(400);
    expect(res.text).toContain('File is too large');
  });

  it('a user with no avatar is a 404, and so is any other name', async () => {
    const http = await signIn();

    expect((await http.get(`/avatar/${pleb.id}`)).status).toBe(404);

    for (const file of ['../../etc/passwd', 'no-such-name.png', '../src/server.js']) {
      expect((await http.get(`/attachment?file=${encodeURIComponent(file)}`)).status).toBe(404);
    }
  });

  it('c-upload-1 GET /attachment serves a stored upload by its generated name', async () => {
    const http = await signIn();
    const token = await csrfToken(http, '/profile');
    await http.post('/profile/avatar').field('csrf_token', token).attach('avatar', PNG, 'me.png');
    const stored = String((await users.findById(Number(admin.id))).avatar_path);

    const res = await http.get(`/attachment?file=${encodeURIComponent(stored)}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('image/png');
  });
});

describe('link preview (POST /preview)', () => {
  it('c-ssrf-1 refuses a loopback address with the pinned message', async () => {
    const http = await signIn();

    for (const url of ['http://127.0.0.1:8088/admin/users', 'http://localhost/', 'http://169.254.169.254/latest/meta-data/']) {
      const res = await postForm(http, '/preview', { url }, '/profile');
      expect(res.status).toBe(400);
      expect(res.text).toContain('That is not a previewable address.');
    }
  });

  it('c-ssrf-1 refuses a non-http scheme', async () => {
    const http = await signIn();
    const res = await postForm(http, '/preview', { url: 'file:///etc/passwd' }, '/profile');
    expect(res.status).toBe(400);
  });
});

  // C-XSS-2 over HTTP: the preview screen echoes what the caller posted, and the echo
  // is escaped. `vuln/xss_reflected` renders that same echo through `|safe`, which is
  // why this case carries the slug (docs/04 §6).
  it('c-xss-2 the preview form echoes the submitted url as text', async () => {
    const http = await signIn();
    // A parseable address that does not resolve: the preview screen re-renders with the
    // submitted value echoed back. The BLOCKED path answers a plain error page, which
    // echoes nothing, so the payload has to be shaped like an ordinary dead link.
    // No spaces: parseTarget refuses any whitespace in the value, and HTML accepts `/`
    // where an attribute separator is wanted — which is what keeps the payload a URL.
    const probe = 'http://preview.invalid/"><img/src=x/onerror=preview-probe><input/value=';

    const res = await postForm(http, '/preview', { url: probe }, '/profile');
    expect(res.status).toBe(200);
    expect(res.text).toContain('&quot;&gt;&lt;img');
    expect(res.text).not.toContain('<img/src=x');
    expect(res.text).not.toContain('<input/value=');
  });

describe('xml export and import', () => {
  it('exports the app envelope for a board', async () => {
    const http = await signIn();
    const res = await http.get(`/board/${boardId}/export.xml`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/xml');
    expect(res.text).toContain('schema="theboard-board-export/1"');
    expect(res.text).toContain('Hook thread');
    // The message body is escaped: a stored script tag is text, not markup.
    expect(res.text).not.toContain('<script>alert(1)</script>');
  });

  it('a board the requester cannot see is a 404, not a 403', async () => {
    const closed = await boards.create('Closed', '', false, Number(admin.id));
    const outsider = await makeUser('hook-out', 'hook-out@test.example', 'OutPass123');
    const http = await agent();
    await loginAs(http, 'hook-out@test.example', 'OutPass123');

    expect((await http.get(`/board/${closed}/export.xml`)).status).toBe(404);
    // CSRF is checked first (docs/02 section 2), then the route's guard. Importing is
    // an admin capability on `main`, so the answer here is the role answer; a branch
    // that removes that guard answers with the board answer (404) instead, and this
    // case deliberately does not pin which of the two the caller sees — the
    // board-existence property is pinned on the export route above.
    expect([403, 404]).toContain((await postForm(http, `/board/${closed}/import`, { xml: '<x/>' }, '/profile')).status);

    // Importing is an admin capability, so for this caller the role answer comes
    // before the board question; the board-existence property (404 rather than 403)
    // is proved on the export route above, which every member may call.
    void outsider;
  });

  it('imports its own envelope back into the board', async () => {
    const http = await signIn();
    const xml = (await http.get(`/board/${boardId}/export.xml`)).text;

    const res = await postForm(http, `/board/${boardId}/import`, { xml }, `/board/${boardId}`);
    expect(res.status).toBe(303);
    // The board had one thread; the import adds a copy of it.
    expect(await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId])).toBe(2);
    expect((await http.get(`/board/${boardId}`)).text).toMatch(/Imported 1 thread\(s\) and 0 replie\(s\)\./);
  });

  it('c-xml-1 refuses a document with an external entity declaration', async () => {
    const http = await signIn();
    const payload = `<?xml version="1.0"?><!DOCTYPE board-export [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><board-export schema="theboard-board-export/1" board_id="${boardId}"><thread title="pwned"><post>&x;</post></thread></board-export>`;

    const res = await postForm(http, `/board/${boardId}/import`, { xml: payload }, `/board/${boardId}`);
    expect(res.status).toBe(400);
    expect(res.text).toContain('That file could not be imported.');
    expect(await count('SELECT COUNT(*) FROM posts WHERE title = ?', ['pwned'])).toBe(0);
  });

  it('refuses another app or another board', async () => {
    const http = await signIn();

    const foreign = `<board-export schema="other/1" board_id="${boardId}"><thread title="foreign"><post>x</post></thread></board-export>`;
    expect((await postForm(http, `/board/${boardId}/import`, { xml: foreign }, `/board/${boardId}`)).text).toContain(
      'That file could not be imported.',
    );

    const mismatched = `<board-export schema="theboard-board-export/1" board_id="${boardId + 99}"><thread title="elsewhere"><post>x</post></thread></board-export>`;
    const res = await postForm(http, `/board/${boardId}/import`, { xml: mismatched }, `/board/${boardId}`);
    expect(res.status).toBe(400);
    expect(await count('SELECT COUNT(*) FROM posts WHERE title = ?', ['elsewhere'])).toBe(0);
  });

  it('imported text is stored as text and rendered by the markup filter', async () => {
    const http = await signIn();
    const payload = `<board-export schema="theboard-board-export/1" board_id="${boardId}"><thread title="round trip"><post>[b]bold[/b] &lt;script&gt;alert(1)&lt;/script&gt;</post></thread></board-export>`;

    expect((await postForm(http, `/board/${boardId}/import`, { xml: payload }, `/board/${boardId}`)).status).toBe(303);
    const page = await http.get(`/board/${boardId}`);
    expect(page.text).toContain('round trip');
    expect(page.text).not.toContain('<script>alert(1)</script>');
  });
});

describe('staff directory (GET /directory, POST /directory/search)', () => {
  it('filters by token and never by SQL text', async () => {
    const http = await signIn();

    const page = await http.get('/directory?q=username:hook-pleb');
    const table = bodyOf(page.text);
    expect(page.status).toBe(200);
    expect(table).toContain('hook-pleb');
    expect(table).not.toContain('hook-admin');

    const injection = await http.get(`/directory?q=${encodeURIComponent("hook-pleb' OR '1'='1")}`);
    expect(injection.status).toBe(200);
    expect(injection.text).toContain('Nobody matches that filter');
  });

  it('the role filter is a bound value', async () => {
    const http = await signIn();
    const page = await http.get('/directory?role=admin');
    expect(bodyOf(page.text)).toContain('hook-admin');
    expect(bodyOf(page.text)).not.toContain('hook-pleb');

    const junk = await http.get(`/directory?role=${encodeURIComponent("admin' OR 1=1--")}`);
    expect(junk.text).toContain('Unknown role filter.');
  });

  // The slug marks what this case proves: C-XPATH-1 is the "input never reaches the
  // expression text" rule, and `vuln/xpath_injection` declares it away (docs/04 §6).
  it('c-xpath-1 the saved search shows the expression it built, with the value bound', async () => {
    const http = await signIn();
    const res = await postForm(http, '/directory/search', { q: 'role:user username:hook' }, '/directory');

    expect(res.status).toBe(200);
    expect(res.text).toContain('/directory/user[contains(@role, $v0) and contains(@username, $v1)]');
    expect(bodyOf(res.text)).toContain('hook-pleb');
    expect(bodyOf(res.text)).not.toContain('hook-admin');

    // An XPath metacharacter in the value is a plain substring test.
    const hostile = await postForm(http, '/directory/search', { q: "username:hook')or(@role=" }, '/directory');
    expect(bodyOf(hostile.text)).toBe('');
  });

  // The advanced search (`mode=filter`) is the path whose escaping rule C-DIR-1 pins;
  // `vuln/ldap_injection` declares that rule away, so this case carries the slug.
  it('c-dir-1 filter mode keeps the caller’s brackets out of the filter grammar', async () => {
    const http = await signIn();

    const plain = await http.get('/directory?mode=filter&q=hook-pleb');
    expect(plain.status).toBe(200);
    expect(bodyOf(plain.text)).toContain('hook-pleb');
    expect(bodyOf(plain.text)).not.toContain('hook-admin');

    for (const term of ['*)|(username=*)(x=*)', '*)|(email=*)']) {
      const breakout = await http.get(`/directory?mode=filter&q=${encodeURIComponent(term)}`);
      expect(breakout.status).toBe(200);
      expect(breakout.text).toContain('Nobody matches that filter');
      expect(bodyOf(breakout.text), `${term} must be matched as text`).toBe('');
    }

    // The bare term searches both text fields, which is how the injected `(email=*)`
    // arm would have worked had the brackets been allowed to mean anything.
    const byEmail = await http.get('/directory?mode=filter&q=' + encodeURIComponent('hook-pleb@test.example'));
    expect(bodyOf(byEmail.text)).toContain('hook-pleb');
  });
});

  // C-DIR-2 over HTTP: a criteria document may name a projected field and hold a
  // scalar value, and nothing more. `vuln/nosql_injection` removes the scalar rule,
  // which is what lets an operator leaf reach the document matcher.
  it('c-dir-2 a criteria document with an operator leaf never reaches the matcher', async () => {
    const http = await signIn();

    const bad = await postForm(
      http,
      '/directory/match',
      { criteria: '{"username":{"$ne":"x"},"role":{"$ne":"impossible"}}' },
      '/directory',
    );
    expect(bad.status).toBe(200);
    expect(bad.text).toContain('Directory criteria values must be scalars.');
    expect(bodyOf(bad.text), 'the operator leaf must not select rows').toBe('');

    for (const leaf of ['{"username":{"$regex":"^h"}}', '{"username":{"$exists":true}}', '{"role":{"$in":["admin"]}}']) {
      const probe = await postForm(http, '/directory/match', { criteria: leaf }, '/directory');
      expect(bodyOf(probe.text), `${leaf} must not select rows`).toBe('');
      expect(probe.text).toContain('must be scalars');
    }
  });

  // Not slugged: the field allowlist, the JSON shape rules and the CSRF guard all
  // survive `vuln/nosql_injection`, so this case must stay green on that branch too.
  it('a criteria document names a projected field and compares as text', async () => {
    const http = await signIn();

    const scalar = await postForm(http, '/directory/match', { criteria: '{"username":"hook-pleb"}' }, '/directory');
    expect(scalar.status).toBe(200);
    expect(bodyOf(scalar.text)).toContain('hook-pleb');
    expect(bodyOf(scalar.text)).not.toContain('hook-admin');

    const unknownField = await postForm(http, '/directory/match', { criteria: '{"password_hash":"x"}' }, '/directory');
    expect(unknownField.text).toContain('Unknown criteria field: password_hash');
    expect(unknownField.text).not.toContain('$2y$');
    expect(unknownField.text).not.toContain('$2b$');

    const malformed = await postForm(http, '/directory/match', { criteria: 'not json' }, '/directory');
    expect(malformed.text).toContain('Directory criteria must be a JSON object.');

    const anon = await agent();
    const tokenless = await anon.post('/directory/match').type('form').send({ criteria: '{"username":"hook-pleb"}' });
    expect(tokenless.status).toBe(400); // the CSRF check runs before the login redirect
  });

describe('board snapshot (GET /admin/boards/:id/snapshot.json, POST …/restore)', () => {
  it('exports a snapshot an admin can read back', async () => {
    const http = await signIn();
    const res = await http.get(`/admin/boards/${boardId}/snapshot.json`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/json');
    const parsed = JSON.parse(res.text);
    expect(parsed.schema).toBe('theboard-snapshot/1');
    expect(parsed.board_id).toBe(boardId);
    expect(parsed.records.map((r) => r.type)).toEqual(['board', 'post']);
  });

  it('c-acl-2 a non-admin is refused before the snapshot is read', async () => {
    const http = await agent();
    await loginAs(http, 'hook-pleb@test.example', 'PlebPass123');

    expect((await http.get(`/admin/boards/${boardId}/snapshot.json`)).status).toBe(403);
    expect((await postForm(http, `/admin/boards/${boardId}/restore`, { snapshot: '{}' }, '/profile')).status).toBe(403);
  });

  it('refuses a snapshot from another board with 409', async () => {
    const http = await signIn();
    const other = await boards.create('Other', '', true, Number(admin.id));
    const foreign = await http.get(`/admin/boards/${other}/snapshot.json`);

    const res = await postForm(http, `/admin/boards/${boardId}/restore`, { snapshot: foreign.text }, `/admin/boards/${boardId}`);
    expect(res.status).toBe(409);
    expect(res.text).toContain('That snapshot does not fit this board.');
  });

  it('restores in one step and reports what it wrote', async () => {
    const http = await signIn();
    const snap = (await http.get(`/admin/boards/${boardId}/snapshot.json`)).text;
    await makeThread(boardId, Number(admin.id), 'Extra', 'to be removed by the restore');
    expect(await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId])).toBe(2);

    const res = await postForm(http, `/admin/boards/${boardId}/restore`, { snapshot: snap }, `/admin/boards/${boardId}`);
    expect(res.status).toBe(303);
    expect(await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId])).toBe(1);
    expect((await http.get(`/admin/boards/${boardId}`)).text).toMatch(/Snapshot restored: 1 post\(s\), 0 vote\(s\)\./);
  });

  it('a snapshot with an unexpected field is refused, not applied', async () => {
    const http = await signIn();
    const snap = JSON.parse((await http.get(`/admin/boards/${boardId}/snapshot.json`)).text);
    snap.records[0].role = 'admin';

    const res = await postForm(http, `/admin/boards/${boardId}/restore`, { snapshot: JSON.stringify(snap) }, `/admin/boards/${boardId}`);
    expect(res.status).toBe(400);
    expect(res.text).toContain('unexpected field');
  });
});

describe('thread export (GET /thread/:id/export)', () => {
  it('serves markdown and plain text from the allowlist', async () => {
    const http = await signIn();

    const md = await http.get(`/thread/${threadId}/export?format=md`);
    expect(md.status).toBe(200);
    expect(md.headers['content-type']).toContain('text/markdown');
    expect(md.headers['content-disposition']).toBe(`attachment; filename="thread-${threadId}.md"`);
    expect(md.text).toContain('# Hook thread');
    expect(md.text).not.toContain('<script>');

    const txt = await http.get(`/thread/${threadId}/export?format=txt`);
    expect(txt.headers['content-type']).toContain('text/plain');
  });

  it('c-cmd-1 an out-of-allowlist format is refused', async () => {
    const http = await signIn();

    for (const format of ['html', 'md;id', '$(id)', '| id']) {
      const res = await http.get(`/thread/${threadId}/export?format=${encodeURIComponent(format)}`);
      expect(res.status).toBe(400);
      expect(res.text).toContain('Unknown export format.');
    }
  });

  it('a thread on a board the requester cannot see is a 404', async () => {
    const closed = await boards.create('Quiet', '', false, Number(admin.id));
    const hidden = await makeThread(closed, Number(admin.id), 'Hidden thread', 'body');
    const http = await agent();
    await loginAs(http, 'hook-pleb@test.example', 'PlebPass123');

    expect((await http.get(`/thread/${hidden}/export?format=md`)).status).toBe(404);
  });
});

describe('password reset and remember-me', () => {
  it('answers the same for a known and an unknown address', async () => {
    const http = await agent();

    const unknown = await postForm(http, '/forgot-password', { email: 'nobody@test.example' }, '/forgot-password');
    expect(unknown.status).toBe(200);
    expect(unknown.text).toContain('If that address has an account, a reset link is on its way.');
    expect(readMailLog()).not.toContain('TO: nobody@test.example');

    const known = await postForm(http, '/forgot-password', { email: 'hook-pleb@test.example' }, '/forgot-password');
    expect(known.text).toContain('If that address has an account, a reset link is on its way.');
    expect(mailTo('hook-pleb@test.example')).toMatch(/\/reset-password\?token=/);
  });

  it('a reset token works once', async () => {
    const http = await agent();
    await postForm(http, '/forgot-password', { email: 'hook-pleb@test.example' }, '/forgot-password');

    const link = /\/reset-password\?token=([A-Za-z0-9._-]+)/.exec(mailTo('hook-pleb@test.example'));
    expect(link).not.toBeNull();

    const bad = await postForm(http, '/reset-password', { token: 'not-a-token', password: 'FreshPass123', password_confirm: 'FreshPass123' }, '/reset-password');
    expect(bad.status).toBe(200);
    expect(bad.text).toContain('That reset link is no longer valid.');

    const good = await postForm(http, '/reset-password', { token: link[1], password: 'FreshPass123', password_confirm: 'FreshPass123' }, '/reset-password');
    expect(good.status).toBe(303);
    expect(good.headers.location).toBe('/login');

    const replay = await postForm(http, '/reset-password', { token: link[1], password: 'AnotherPass123', password_confirm: 'AnotherPass123' }, '/reset-password');
    expect(replay.status).toBe(200);
    expect(replay.text).toContain('That reset link is no longer valid.');

    const after = await agent();
    await loginAs(after, 'hook-pleb@test.example', 'FreshPass123');
    expect((await after.get('/profile')).status).toBe(200);
  });

  it('c-auth-2 a short password on the reset form is rejected by the same validator', async () => {
    const http = await agent();
    await postForm(http, '/forgot-password', { email: 'hook-pleb@test.example' }, '/forgot-password');
    const token = /\/reset-password\?token=([A-Za-z0-9._-]+)/.exec(mailTo('hook-pleb@test.example'))[1];

    const res = await postForm(http, '/reset-password', { token, password: 'short', password_confirm: 'short' }, '/reset-password');
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe(`/reset-password?token=${token}`);
    expect((await http.get(res.headers.location)).text).toMatch(/Password must be at least \d+ characters long\./);
    expect((await row('SELECT COUNT(*) AS n FROM users WHERE email = ?', ['hook-pleb@test.example'])).n).toBe(1);
  });

  it('remember-me opens a session for a fresh agent, and the token alone is not an identity', async () => {
    const http = await agent();
    const token = await csrfToken(http, '/login');
    const login = await http
      .post('/login')
      .type('form')
      .send({ csrf_token: token, email: 'hook-pleb@test.example', password: 'PlebPass123', remember: '1' });
    expect(login.status).toBe(303);

    const cookies = (login.headers['set-cookie'] ?? []).map(String);
    const remember = cookies.find((line) => line.startsWith('theboard_remember='));
    expect(remember).toBeDefined();
    expect(remember).toContain('HttpOnly');
    expect(remember).toContain('SameSite=Lax');
    expect(remember).toMatch(/Max-Age=900/);

    const fresh = await agent();
    const value = remember.split(';')[0];
    const page = await fresh.get('/profile').set('Cookie', value);
    expect(page.status).toBe(200);
    expect(page.text).toContain('hook-pleb');

    // A forged cookie for the same route is refused: no signature, no session.
    const forged = await agent();
    const forgedPage = await forged.get('/profile').set('Cookie', 'theboard_remember=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.');
    expect(forgedPage.status).toBe(303);
    expect(forgedPage.headers.location).toBe('/login');
  });
});
