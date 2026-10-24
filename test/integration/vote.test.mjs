// Port of tests/Integration/VoteTest.php (docs/02 B24, docs/03 C-RACE-1).

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

async function boardWithThread(authorId) {
  const boardId = Number((await makeBoard('V', true)).id);
  return makeThread(boardId, authorId);
}

describe('votes', () => {
  it('testUpvoteAddsScore', async () => {
    const user = await makeUser();
    const threadId = await boardWithThread(Number(user.id));

    const result = await votes.vote(threadId, Number(user.id), 1);

    expect(result.action).toBe('added');
    expect(result.score).toBe(1);
    expect(await votes.score(threadId)).toBe(1);
  });

  it('testDownvoteAddsNegativeScore', async () => {
    const user = await makeUser();
    const threadId = await boardWithThread(Number(user.id));

    const result = await votes.vote(threadId, Number(user.id), -1);

    expect(result.score).toBe(-1);
  });

  it('testSameVoteTwiceTogglesOff', async () => {
    const user = await makeUser();
    const threadId = await boardWithThread(Number(user.id));

    await votes.vote(threadId, Number(user.id), 1);
    const result = await votes.vote(threadId, Number(user.id), 1);

    expect(result.action).toBe('removed');
    expect(result.score).toBe(0);
  });

  it('testOppositeVoteSwitches', async () => {
    const user = await makeUser();
    const threadId = await boardWithThread(Number(user.id));

    await votes.vote(threadId, Number(user.id), 1);
    const result = await votes.vote(threadId, Number(user.id), -1);

    expect(result.action).toBe('switched');
    expect(result.score).toBe(-1);
    expect((await votes.userVote(threadId, Number(user.id))).value).toBe(-1);
  });

  it('testMultipleUsersAggregate', async () => {
    const author = await makeUser();
    const threadId = await boardWithThread(Number(author.id));
    const u1 = await makeUser('u1');
    const u2 = await makeUser('u2');
    const u3 = await makeUser('u3');

    await votes.vote(threadId, Number(u1.id), 1);
    await votes.vote(threadId, Number(u2.id), 1);
    await votes.vote(threadId, Number(u3.id), -1);

    expect(await votes.score(threadId)).toBe(1);
  });

  it('testUserVoteReturnsNullWhenNotVoted', async () => {
    const user = await makeUser();
    const threadId = await boardWithThread(Number(user.id));

    expect(await votes.userVote(threadId, Number(user.id))).toBeNull();
  });

  it('testVotesArePerPostAndPerUser', async () => {
    const user = await makeUser();
    const other = await makeUser('other');
    const boardId = Number((await makeBoard('V', true)).id);
    const t1 = await makeThread(boardId, Number(user.id));
    const t2 = await makeThread(boardId, Number(user.id));

    await votes.vote(t1, Number(user.id), 1);
    await votes.vote(t1, Number(other.id), 1);
    await votes.vote(t2, Number(user.id), 1);

    expect(await votes.score(t1)).toBe(2);
    expect(await votes.score(t2)).toBe(1);
  });

  it('testInvalidValueThrows', async () => {
    const user = await makeUser();
    const threadId = await boardWithThread(Number(user.id));

    await expect(votes.vote(threadId, Number(user.id), 5)).rejects.toThrow('Vote value must be 1 or -1');
  });

  it('testVotesOnRepliesWork', async () => {
    const user = await makeUser();
    const boardId = Number((await makeBoard('V', true)).id);
    const threadId = await makeThread(boardId, Number(user.id));
    const { postId: replyId } = await posts.createReply(threadId, Number(user.id), 'reply body');

    await votes.vote(replyId, Number(user.id), 1);
    expect(await votes.score(replyId)).toBe(1);
  });
});
