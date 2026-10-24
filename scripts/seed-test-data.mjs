#!/usr/bin/env node
// Seed a repeatable set of test data — port of bin/seed-test-data.php.
//
// The fixture contract lives in docs/02 section 6; the ten content invariants
// there are asserted by test/integration/fixture-invariants.test.mjs, so a
// change here that breaks one of them fails the test suite.
//
// NOTE ON "ROLES": the schema has two — users.role is ENUM('user','admin') and
// every check is a role test. The ten seeded accounts are ACCESS PERSONAS built
// from the state the app actually models: role x is_banned x mfa_enabled x board
// grants x content history.
//
// It refuses to run against a database that already holds personas, so it can
// never half-duplicate data.

import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { load } from '../src/config/env.js';
import { close, query } from '../src/db/connection.js';
import { root } from '../src/db/admin.js';
import * as boards from '../src/repositories/board.repository.js';
import * as posts from '../src/repositories/post.repository.js';
import * as users from '../src/repositories/user.repository.js';
import * as votes from '../src/repositories/vote.repository.js';

export const TEST_PASSWORD = 'TestPass123';
export const TEST_DOMAIN = 'test.theboard.local';

/** Shared persona table: [key, username, email local part, admin, banned, mfa, what it exercises]. */
export const PERSONAS = [
  ['owner', 'owner_olivia', 'owner', true, false, false, 'Admin who owns/creates the boards'],
  ['mod', 'mod_marcus', 'mod', true, false, true, 'Second admin, NOT in ADMIN_EMAILS, MFA on'],
  ['regular', 'regular_rita', 'regular', false, false, false, 'Plain user, open boards only'],
  ['insider', 'insider_ian', 'insider', false, false, false, 'Plain user with an explicit restricted grant'],
  ['outsider', 'outsider_olly', 'outsider', false, false, false, 'Plain user with no grants (404s on restricted)'],
  ['mfa', 'mfa_mia', 'mfa', false, false, true, 'MFA login (OTP lands in var/log/mail.log)'],
  ['banned', 'banned_bob', 'banned', false, true, false, 'Banned user whose posts stay visible'],
  ['lurker', 'lurker_lena', 'lurker', false, false, false, 'Zero posts, zero votes (empty profile state)'],
  ['prolific', 'prolific_pete', 'prolific', false, false, false, 'Author of 20+ threads (drives pagination)'],
  ['troll', 'troll_tom', 'troll', false, false, false, 'Downvoter whose posts get soft-deleted'],
];

/** Backdate a post so thread ordering and pagination are deterministic. */
async function backdate(postId, minutesAgo) {
  await query('UPDATE posts SET created_at = NOW() - INTERVAL ? MINUTE WHERE id = ?', [minutesAgo, postId]);
}

async function thread(boardId, authorId, title, body, minutesAgo) {
  const created = await posts.createThread(boardId, authorId, title, body);
  if (created.postId === null) {
    throw new Error(`Failed to create thread '${title}': ${created.errors.join(' ')}`);
  }
  await backdate(created.postId, minutesAgo);
  return created.postId;
}

async function reply(threadId, authorId, body, minutesAgo) {
  const created = await posts.createReply(threadId, authorId, body);
  if (created.postId === null) {
    throw new Error(`Failed to create reply: ${created.errors.join(' ')}`);
  }
  await backdate(created.postId, minutesAgo);
  return created.postId;
}

/**
 * Seed the fixture. Returns the persona id map.
 * Throws FixtureAlreadySeededError when personas are present — reset first.
 */
export class FixtureAlreadySeededError extends Error {}

export async function seedTestData() {
  const hits = await query(`SELECT COUNT(*) AS n FROM users WHERE email LIKE '%@${TEST_DOMAIN}'`);
  const already = Number(hits[0].n);

  if (already > 0) {
    throw new FixtureAlreadySeededError(
      `Test data is already present (${already} personas found). Run npm run db:reset -- --force to wipe and reseed.`,
    );
  }

  // ---------------------------------------------------------------- personas --
  const ids = {};
  for (const [key, username, local, isAdmin, banned, mfa] of PERSONAS) {
    const user = await users.create(username, `${local}@${TEST_DOMAIN}`, TEST_PASSWORD);
    const id = Number(user.id);
    ids[key] = id;

    // users.create() only grants admin to ADMIN_EMAILS addresses, so seeded
    // admins are promoted directly — which also covers the "admin that is not in
    // .env" case that ensureAdminRolesFromEnv() never touches.
    if (isAdmin) await query(`UPDATE users SET role = 'admin' WHERE id = ?`, [id]);
    if (mfa) await users.setMfaEnabled(id, true);
    if (banned) await users.setBanned(id, true, 'Repeated spam in General (seeded test ban)');
  }

  // ------------------------------------------------------------------ boards --
  const boardIds = {};
  boardIds.announce = Number(await boards.create('Announcements', 'Notices for everyone. Open to every active user.', true, ids.owner));
  boardIds.general = Number(await boards.create('General', 'Busy open board - more than one page of threads.', true, ids.owner));
  boardIds.staff = Number(await boards.create('Staff Room', 'Restricted. Admins plus explicitly granted users.', false, ids.owner));
  boardIds.vault = Number(await boards.create('Vault', 'Restricted with zero grants - only admins can see it.', false, ids.owner));
  boardIds.empty = Number(await boards.create('Empty Board', 'Open board with no threads at all.', true, ids.owner));
  boardIds.archive = Number(await boards.create('Archive', 'Soft-deleted board - must not appear in any listing.', true, ids.owner));

  await boards.grantAccess(boardIds.staff, ids.insider, ids.owner);
  await boards.grantAccess(boardIds.staff, ids.mfa, ids.owner);
  // Granted and then revoked again, so the revoke path leaves a trace too.
  await boards.grantAccess(boardIds.staff, ids.regular, ids.owner);
  await boards.revokeAccess(boardIds.staff, ids.regular);
  // A grant on a board that is soft-deleted anyway.
  await boards.grantAccess(boardIds.archive, ids.regular, ids.owner);

  // ----------------------------------------------------------------- content --
  const welcome = await thread(
    boardIds.announce,
    ids.owner,
    'Welcome to The Board',
    `This board is seeded test data.\n\nEvery seeded account uses the password [b]${TEST_PASSWORD}[/b].`,
    5000,
  );
  await reply(welcome, ids.regular, 'Good to be here.', 4900);
  await reply(welcome, ids.insider, 'Same. Testing replies.', 4880);

  await thread(
    boardIds.announce,
    ids.owner,
    'Markup showcase',
    '[b]bold[/b], [i]italic[/i], [u]underline[/u]\n'
      + 'A bare link: [url]https://example.com[/url]\n'
      + 'A labelled link: [url=https://example.com/docs]the docs[/url]\n'
      + 'An image: [img]https://example.com/logo.png[/img]\n'
      + 'Unclosed tag on purpose: [b]still fine',
    4800,
  );

  // Sanitizer probes — these MUST render as inert text, never as live markup.
  const xss = await thread(
    boardIds.general,
    ids.troll,
    'Rendering probe (should be inert)',
    "<script>alert('xss')</script>\n"
      + '<img src=x onerror=alert(1)>\n'
      + '[url]javascript:alert(1)[/url]\n'
      + '[url]data:text/html,<script>alert(1)</script>[/url]\n'
      + '[url="onmouseover=alert(1)]attribute probe[/url]',
    4700,
  );
  await reply(xss, ids.regular, 'Renders as plain text here, which is the point.', 4600);

  const hot = await thread(
    boardIds.general,
    ids.regular,
    'Which board layout do you prefer?',
    'Flat replies or threaded? This one carries the vote spread.',
    4500,
  );
  for (const voter of ['insider', 'outsider', 'mfa', 'lurker', 'prolific']) await votes.vote(hot, ids[voter], 1);
  await votes.vote(hot, ids.troll, -1);

  const reply1 = await reply(hot, ids.prolific, 'Flat. Threaded gets unreadable past depth three.', 4400);
  await votes.vote(reply1, ids.regular, 1);
  await votes.vote(reply1, ids.insider, 1);

  // A net-negative post, so negative scores are represented too.
  const sunk = await reply(hot, ids.troll, 'Both are bad. Use a mailing list.', 4300);
  for (const voter of ['regular', 'insider', 'mfa', 'prolific']) await votes.vote(sunk, ids[voter], -1);

  // An edited post (edited_at is set).
  const edited = await thread(boardIds.general, ids.insider, 'Post that has been edited', 'Original body.', 4200);
  await posts.editPost(edited, ids.insider, false, 'Edited body - edited_at should now be set.');

  // A soft-deleted thread and a soft-deleted reply, both moderated by an admin.
  const removed = await thread(
    boardIds.general,
    ids.troll,
    'Thread removed by a moderator',
    'This thread is soft-deleted; it must not appear in listings.',
    4100,
  );
  await posts.deletePost(removed, ids.mod);

  const keeper = await thread(
    boardIds.general,
    ids.banned,
    'Thread by a banned author',
    'The author is banned, but the post itself stays visible.',
    4000,
  );
  const deletedReply = await reply(keeper, ids.troll, 'Reply that a moderator soft-deleted.', 3900);
  await posts.deletePost(deletedReply, ids.mod);
  await reply(keeper, ids.regular, 'Reply that survives next to a deleted sibling.', 3800);

  // Bulk threads to push General past THREADS_PER_PAGE (20).
  for (let i = 1; i <= 18; i += 1) {
    const filler = await thread(
      boardIds.general,
      ids.prolific,
      `Filler thread ${String(i).padStart(2, '0')}`,
      `Body of filler thread ${i}. Seeded to exercise pagination and sorting.`,
      3700 - i * 30,
    );
    if (i % 4 === 0) await reply(filler, ids.regular, `Reply on filler ${i}.`, 3690 - i * 30);
    if (i % 3 === 0) await votes.vote(filler, ids.insider, 1);
  }

  // Restricted-board content: only admins plus insider/mfa should ever see this.
  const staffThread = await thread(
    boardIds.staff,
    ids.owner,
    'Restricted: staff-only thread',
    'If you can read this as outsider_olly, board access control is broken.',
    2000,
  );
  await reply(staffThread, ids.insider, 'Confirmed visible to a granted user.', 1900);
  await reply(staffThread, ids.mod, 'And to admins.', 1800);

  await thread(boardIds.vault, ids.owner, 'Vault: admin-only thread', 'The Vault has zero grants, so only admins can reach this.', 1700);

  // Content on the board that is then soft-deleted (must stay unreachable).
  await thread(boardIds.archive, ids.owner, 'Thread on the archived board', 'The board is soft-deleted, so this must be unreachable.', 1600);
  await boards.softDelete(boardIds.archive, ids.owner);

  // Failed login history, so the throttle counters have something to read.
  for (let n = 1; n <= 3; n += 1) await users.recordAttempt(`regular@${TEST_DOMAIN}`, `203.0.113.${n}`, false);
  await users.recordAttempt(`regular@${TEST_DOMAIN}`, '203.0.113.1', true);

  return { ids, boardIds };
}

/** Count rows for the closing report (and for the test's own summary). */
export async function fixtureCounts() {
  const one = async (sql) => Number(Object.values((await query(sql))[0])[0]);

  return {
    users: await one('SELECT COUNT(*) FROM users'),
    boards: await one('SELECT COUNT(*) FROM boards'),
    deletedBoards: await one('SELECT COUNT(*) FROM boards WHERE deleted_at IS NOT NULL'),
    posts: await one('SELECT COUNT(*) FROM posts'),
    deletedPosts: await one('SELECT COUNT(*) FROM posts WHERE deleted_at IS NOT NULL'),
    votes: await one('SELECT COUNT(*) FROM votes'),
    loginAttempts: await one('SELECT COUNT(*) FROM login_attempts'),
  };
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  if (existsSync(`${root()}/.env`)) load(`${root()}/.env`);

  try {
    await seedTestData();
  } catch (error) {
    if (error instanceof FixtureAlreadySeededError) {
      console.error(`${error.message}`);
      await close();
      process.exit(1);
    }
    throw error;
  }

  const counts = await fixtureCounts();
  console.log('\nTest data seeded.\n');
  console.log(
    `  users ${counts.users} | boards ${counts.boards} (${counts.deletedBoards} soft-deleted)`
      + ` | posts ${counts.posts} (${counts.deletedPosts} soft-deleted) | votes ${counts.votes}\n`,
  );
  console.log(`  Password for every persona below: ${TEST_PASSWORD}\n`);
  for (const [, username, local, , , , note] of PERSONAS) {
    console.log(`  ${username.padEnd(14)} ${`${local}@${TEST_DOMAIN}`.padEnd(32)} ${note}`);
  }
  console.log('\n  Admins from .env (ADMIN_EMAILS) are seeded separately by scripts/seed-admins.mjs.');
  await close();
}
