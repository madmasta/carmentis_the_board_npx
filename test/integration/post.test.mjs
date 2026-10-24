// Port of tests/Integration/PostTest.php.
//
// `createThread`/`createReply` return `{ postId, errors }` instead of PHP's
// `int|false` plus an `&$errors` out-parameter (docs/07 section 10).

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll } from '../helpers/db.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import * as posts from '../../src/repositories/post.repository.js';
import * as votes from '../../src/repositories/vote.repository.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

describe('posts', () => {
  it('testCreateThreadReturnsIdAndPersists', async () => {
    const user = await makeUser();
    const board = await makeBoard('General', true);

    const { postId } = await posts.createThread(Number(board.id), Number(user.id), 'Hello', 'World');

    expect(postId).toBeGreaterThan(0);
    const thread = await posts.getThread(postId);
    expect(thread).not.toBeNull();
    expect(thread.title).toBe('Hello');
    expect(thread.body).toBe('World');
  });

  it('testThreadValidationRejectsBadInput', async () => {
    const user = await makeUser();
    const board = await makeBoard('General', true);

    const emptyTitle = await posts.createThread(Number(board.id), Number(user.id), '', 'body');
    expect(emptyTitle.postId).toBeNull();
    expect(emptyTitle.errors).not.toEqual([]);

    const tooLong = await posts.createThread(Number(board.id), Number(user.id), 'Title', 'x'.repeat(10001));
    expect(tooLong.postId).toBeNull();
    expect(tooLong.errors).not.toEqual([]);
  });

  it('testReplyBelongsToThread', async () => {
    const user = await makeUser();
    const board = await makeBoard('General', true);
    const threadId = await makeThread(Number(board.id), Number(user.id));

    const { postId: replyId } = await posts.createReply(threadId, Number(user.id), 'A reply');
    expect(replyId).toBeGreaterThan(0);

    const reply = await posts.find(replyId);
    expect(Number(reply.parent_id)).toBe(threadId);
    expect(Number(reply.board_id)).toBe(Number(board.id));
    expect(reply.title).toBeNull();

    expect(await posts.listReplies(threadId)).toHaveLength(1);
  });

  it('testCannotReplyToDeletedThread', async () => {
    const user = await makeUser();
    const board = await makeBoard('General', true);
    const threadId = await makeThread(Number(board.id), Number(user.id));
    await posts.deletePost(threadId, Number(user.id));

    const result = await posts.createReply(threadId, Number(user.id), 'late reply');
    expect(result.postId).toBeNull();
    expect(result.errors).toEqual(['Thread not found.']);
  });

  it('testListThreadsContainsScoreAndReplyCount', async () => {
    const user = await makeUser();
    const voter = await makeUser('voter');
    const board = await makeBoard('General', true);
    const threadId = await makeThread(Number(board.id), Number(user.id), 'T1');
    const otherId = await makeThread(Number(board.id), Number(user.id), 'T2');

    await posts.createReply(threadId, Number(voter.id), 'reply here');
    await votes.vote(threadId, Number(voter.id), 1);

    const threads = await posts.listThreads(Number(board.id));
    const byId = new Map(threads.map((thread) => [Number(thread.id), thread]));

    expect(threads).toHaveLength(2);
    expect(Number(byId.get(threadId).reply_count)).toBe(1);
    expect(Number(byId.get(threadId).score)).toBe(1);
    expect(Number(byId.get(otherId).reply_count)).toBe(0);
    expect(Number(byId.get(otherId).score)).toBe(0);
  });

  it('testThreadsArePaginatedNewestFirst', async () => {
    const user = await makeUser();
    const board = await makeBoard('Paging', true);
    let lastId = 0;
    for (let i = 1; i <= 25; i++) {
      lastId = await makeThread(Number(board.id), Number(user.id), `Thread ${i}`);
    }

    const page1 = await posts.listThreads(Number(board.id), 1);
    const page2 = await posts.listThreads(Number(board.id), 2);

    expect(page1).toHaveLength(20);
    expect(page2).toHaveLength(5);
    expect(Number(page1[0].id)).toBe(lastId);
    expect(await posts.countThreads(Number(board.id))).toBe(25);
  }, 30_000);

  it('testAuthorCanEditOwnPost', async () => {
    const user = await makeUser();
    const board = await makeBoard('Edit', true);
    const threadId = await makeThread(Number(board.id), Number(user.id));

    expect(await posts.editPost(threadId, Number(user.id), false, 'edited body')).toBe(true);

    const thread = await posts.getThread(threadId);
    expect(thread.body).toBe('edited body');
    expect(thread.edited_at).not.toBeNull();
  });

  it('testNonAuthorCannotEditOthersPost', async () => {
    const author = await makeUser('author');
    const stranger = await makeUser('stranger');
    const board = await makeBoard('Edit', true);
    const threadId = await makeThread(Number(board.id), Number(author.id));

    expect(await posts.editPost(threadId, Number(stranger.id), false, 'hijacked')).toBe(false);
    expect((await posts.getThread(threadId)).body).toBe('World');
  });

  it('testAdminCanEditAnyPost', async () => {
    const author = await makeUser('author');
    const admin = await makeUser('mod', null, 'CorrectHorse1', 'admin');
    const board = await makeBoard('Edit', true);
    const threadId = await makeThread(Number(board.id), Number(author.id));

    expect(await posts.editPost(threadId, Number(admin.id), true, 'moderated body')).toBe(true);
    expect((await posts.getThread(threadId)).body).toBe('moderated body');
  });

  it('testEditRejectsEmptyBody', async () => {
    const user = await makeUser();
    const board = await makeBoard('Edit', true);
    const threadId = await makeThread(Number(board.id), Number(user.id));

    expect(await posts.editPost(threadId, Number(user.id), false, '   ')).toBe(false);
  });

  it('testSoftDeleteHidesThreadFromAllListings', async () => {
    const user = await makeUser();
    const admin = await makeUser('admin', null, 'CorrectHorse1', 'admin');
    const boardId = Number((await makeBoard('Del', true)).id);
    const threadId = await makeThread(boardId, Number(user.id));
    await posts.createReply(threadId, Number(user.id), 'a reply');

    expect(await posts.deletePost(threadId, Number(admin.id))).toBe(true);

    expect(await posts.getThread(threadId)).toBeNull();
    expect(await posts.find(threadId)).toBeNull();
    expect(await posts.listThreads(boardId)).toEqual([]);
  });

  it('testDoubleDeleteIsIdempotentFalse', async () => {
    const user = await makeUser();
    const boardId = Number((await makeBoard('Del', true)).id);
    const threadId = await makeThread(boardId, Number(user.id));

    expect(await posts.deletePost(threadId, Number(user.id))).toBe(true);
    expect(await posts.deletePost(threadId, Number(user.id))).toBe(false);
  });

  it('testModerationFeedListsRecentPosts', async () => {
    const user = await makeUser();
    const board = await makeBoard('Feed', true);
    const t1 = await makeThread(Number(board.id), Number(user.id), 'T1');
    const t2 = await makeThread(Number(board.id), Number(user.id), 'T2');
    await posts.deletePost(t1, Number(user.id));

    const ids = (await posts.recentPosts(10)).map((post) => Number(post.id));

    expect(ids).toContain(t2);
    expect(ids).not.toContain(t1); // deleted posts are not in the default feed
  });

  it('testListByAuthor', async () => {
    const user = await makeUser();
    const other = await makeUser('other');
    const boardId = Number((await makeBoard('Mine', true)).id);
    await makeThread(boardId, Number(user.id), 'Mine 1');
    await makeThread(boardId, Number(other.id), 'Other 1');

    const mine = await posts.listByAuthor(Number(user.id));
    expect(mine).toHaveLength(1);
    expect(mine[0].title).toBe('Mine 1');
  });
});
