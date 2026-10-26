// Fixture parity — the ten content invariants in docs/02 section 6.
//
// This file is the machine-checkable form of "the Node fixture reproduces the
// PHP fixture". A seed script change that breaks one of these rows fails here.

import { beforeAll, describe, expect, it } from 'vitest';
import { count, row, rows, truncateAll } from '../helpers/db.mjs';
import { personaEmail, seedFixtures } from '../helpers/fixtures.mjs';
import { TEST_DOMAIN, TEST_PASSWORD } from '../../scripts/seed-test-data.mjs';
import { FixtureAlreadySeededError, seedTestData } from '../../scripts/seed-test-data.mjs';
import { verify as verifyPassword } from '../../src/security/passwords.js';
import { render as renderMarkup } from '../../src/security/markup.js';
import * as boards from '../../src/repositories/board.repository.js';
import * as posts from '../../src/repositories/post.repository.js';
import * as votes from '../../src/repositories/vote.repository.js';

let boardIds = {};

beforeAll(async () => {
  // These invariants count whole tables, so the file starts from a known state
  // rather than whatever the suites before it left behind.
  await truncateAll();
  await seedFixtures();

  const found = await rows('SELECT id, name FROM boards ORDER BY id');
  for (const board of found) boardIds[board.name] = Number(board.id);
});

describe('fixture invariants (docs/02 section 6)', () => {
  it('1. exactly ten persona accounts, all sharing the fixture password', async () => {
    const personas = await rows(`SELECT id, username, password_hash FROM users WHERE email LIKE '%@${TEST_DOMAIN}' ORDER BY id`);

    expect(personas).toHaveLength(10);
    expect(personas.map((u) => u.username)).toEqual([
      'owner_olivia',
      'mod_marcus',
      'regular_rita',
      'insider_ian',
      'outsider_olly',
      'mfa_mia',
      'banned_bob',
      'lurker_lena',
      'prolific_pete',
      'troll_tom',
    ]);

    for (const persona of personas) {
      expect(await verifyPassword(TEST_PASSWORD, persona.password_hash)).toBe(true);
    }
  });

  it('2. six boards, one soft-deleted, and the deleted board appears in no listing', async () => {
    expect(await count('SELECT COUNT(*) FROM boards')).toBe(6);
    expect(await count('SELECT COUNT(*) FROM boards WHERE deleted_at IS NOT NULL')).toBe(1);

    const names = (await rows('SELECT name FROM boards WHERE deleted_at IS NOT NULL')).map((b) => b.name);
    expect(names).toEqual(['Archive']);

    // No listing — admin or not — shows it.
    const owner = await row('SELECT id, role FROM users WHERE username = ?', ['owner_olivia']);
    const outsider = await row('SELECT id, role FROM users WHERE username = ?', ['outsider_olly']);
    for (const user of [owner, outsider]) {
      const listed = await boards.listForUser(user);
      expect(listed.map((b) => b.name)).not.toContain('Archive');
    }
  });

  it('c-xss-1 3. the sanitizer probe stores raw markup and renders as inert text', async () => {
    const probe = await row('SELECT body FROM posts WHERE title = ?', ['Rendering probe (should be inert)']);
    expect(probe).not.toBeNull();

    // Stored verbatim: the filter sanitises on render, never on write.
    expect(probe.body).toContain("<script>alert('xss')</script>");
    expect(probe.body).toContain('<img src=x onerror=alert(1)>');
    expect(probe.body).toContain('[url]javascript:alert(1)[/url]');
    expect(probe.body).toContain('[url]data:text/html,<script>alert(1)</script>[/url]');
    expect(probe.body).toContain('[url="onmouseover=alert(1)]attribute probe[/url]');

    const html = renderMarkup(probe.body);
    // Nothing live survives: no element from the probe, and no dangerous URL.
    expect(html).not.toMatch(/<(script|img|iframe|svg|object)/i);
    expect(html).not.toMatch(/href="(javascript|data):/i);
    expect(html).not.toMatch(/<a[^>]*on[a-z]+=/i);
    // The probes are still legible to a human reader, as escaped text.
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('4. one thread at +4, one reply at +2 and one reply with a negative score', async () => {
    const hot = await row('SELECT id FROM posts WHERE title = ?', ['Which board layout do you prefer?']);
    expect(await votes.score(Number(hot.id))).toBe(4);

    const replies = await posts.listReplies(Number(hot.id));
    const scores = {};
    for (const reply of replies) scores[reply.body] = await votes.score(Number(reply.id));

    expect(scores['Flat. Threaded gets unreadable past depth three.']).toBe(2);
    expect(scores['Both are bad. Use a mailing list.']).toBe(-4);
  });

  it('5. one thread carries an edited_at timestamp', async () => {
    const edited = await rows('SELECT id, title FROM posts WHERE edited_at IS NOT NULL');
    expect(edited.map((p) => p.title)).toEqual(['Post that has been edited']);
  });

  it('6. one soft-deleted thread, and a thread with a deleted reply next to a survivor', async () => {
    const deletedThreads = await rows('SELECT id, title FROM posts WHERE deleted_at IS NOT NULL AND parent_id IS NULL');
    expect(deletedThreads.map((p) => p.title)).toEqual(['Thread removed by a moderator']);

    const keeper = await row('SELECT id FROM posts WHERE title = ?', ['Thread by a banned author']);
    const all = await rows('SELECT body, deleted_at FROM posts WHERE parent_id = ? ORDER BY id', [Number(keeper.id)]);
    expect(all.filter((p) => p.deleted_at !== null).map((p) => p.body)).toEqual(['Reply that a moderator soft-deleted.']);
    expect(all.filter((p) => p.deleted_at === null).map((p) => p.body)).toEqual(['Reply that survives next to a deleted sibling.']);

    // The reader-facing listing hides the deleted one.
    const visible = await posts.listReplies(Number(keeper.id));
    expect(visible).toHaveLength(1);
  });

  it('7. a post by a banned author is visible', async () => {
    const general = boardIds.General;
    const titles = (await posts.listThreads(general, 1, 100)).map((t) => t.title);
    expect(titles).toContain('Thread by a banned author');

    const banned = await row('SELECT id, is_banned FROM users WHERE username = ?', ['banned_bob']);
    expect(Number(banned.is_banned)).toBe(1);
  });

  it('8. General has 22 live threads, so page 2 exists and is non-empty', async () => {
    const general = boardIds.General;
    expect(await posts.countThreads(general)).toBe(22);

    const page1 = await posts.listThreads(general, 1);
    const page2 = await posts.listThreads(general, 2);
    expect(page1).toHaveLength(20);
    expect(page2).toHaveLength(2);
    expect(new Set([...page1, ...page2].map((t) => t.id)).size).toBe(22);
  });

  it('9. login_attempts holds three failures and one success for regular_rita', async () => {
    const email = personaEmail('regular');
    expect(await count('SELECT COUNT(*) FROM login_attempts WHERE email = ? AND success = 0', [email])).toBe(3);
    expect(await count('SELECT COUNT(*) FROM login_attempts WHERE email = ? AND success = 1', [email])).toBe(1);
  });

  it('10. re-seeding without a reset refuses to run', async () => {
    let failure = null;
    try {
      await seedTestData();
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(FixtureAlreadySeededError);
    expect(failure.message).toMatch(/already present/);
    expect(failure.message).toMatch(/db:reset/);
  });
});

describe('fixture access shape', () => {
  it('only the two MFA personas have MFA enabled', async () => {
    const enabled = await rows('SELECT username FROM users WHERE mfa_enabled = 1 ORDER BY username');
    expect(enabled.map((u) => u.username)).toEqual(['mfa_mia', 'mod_marcus']);
  });

  it('Staff Room grants insider and mfa; the revoked grant is gone; Vault has none', async () => {
    const staff = await boards.accessList(boardIds['Staff Room']);
    expect(staff.map((g) => g.username).sort()).toEqual(['insider_ian', 'mfa_mia']);

    expect(await boards.accessList(boardIds.Vault)).toEqual([]);

    const insider = await row('SELECT id FROM users WHERE username = ?', ['insider_ian']);
    const outsider = await row('SELECT id FROM users WHERE username = ?', ['outsider_olly']);
    const staffBoard = await boards.find(boardIds['Staff Room']);
    expect(await boards.userCanAccess(insider, staffBoard)).toBe(true);
    expect(await boards.userCanAccess(outsider, staffBoard)).toBe(false);
  });

  it('the seeded Archive grant survives its board being soft-deleted', async () => {
    const archive = await row('SELECT id FROM boards WHERE name = ?', ['Archive']);
    const grants = await boards.accessList(Number(archive.id));
    expect(grants.map((g) => g.username)).toEqual(['regular_rita']);
  });
});
