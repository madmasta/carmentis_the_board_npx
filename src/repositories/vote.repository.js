// Post voting — port of src/VoteRepository.php (docs/02 B19, docs/03 C-RACE-1).
//
// One vote per (post, user), enforced by the composite primary key. Voting the
// same way twice removes the vote; the other way switches it.
//
// C-RACE-1: the read-decide-write sequence runs inside a transaction with the
// vote row locked (`SELECT … FOR UPDATE`; with no row yet, InnoDB gap-locks the
// primary-key range), so N simultaneous votes on one post cannot interleave and
// double-apply. `vuln/race_condition` removes the lock and inserts the 350 ms
// seam — the proof asserts counts, never timing (docs/04 section 9).

import { query, transaction, forUpdate } from '../db/connection.js';
import { now, sqlDateTime } from '../lib/clock.js';

export class InvalidVoteError extends Error {
  constructor(message = 'Vote value must be 1 or -1') {
    super(message);
    this.name = 'InvalidVoteError';
  }
}

const SELECT_VOTE = 'SELECT value FROM votes WHERE post_id = ? AND user_id = ?';
const SELECT_SCORE = 'SELECT COALESCE(SUM(value), 0) AS score FROM votes WHERE post_id = ?';

export async function vote(postId, userId, value) {
  if (value !== 1 && value !== -1) throw new InvalidVoteError();

  const action = await transaction(async (conn) => {
    const row = await forUpdate(conn, SELECT_VOTE, [postId, userId]);

    if (row === null) {
      await conn.query('INSERT INTO votes (post_id, user_id, value) VALUES (?, ?, ?)', [
        postId,
        userId,
        value,
      ]);
      return 'added';
    }

    if (Number(row.value) === value) {
      // Toggle off.
      await conn.query('DELETE FROM votes WHERE post_id = ? AND user_id = ?', [postId, userId]);
      return 'removed';
    }

    await conn.query('UPDATE votes SET value = ?, updated_at = ? WHERE post_id = ? AND user_id = ?', [
      value,
      sqlDateTime(now()),
      postId,
      userId,
    ]);
    return 'switched';
  });

  return { action, score: await score(postId) };
}

export async function score(postId) {
  const rows = await query(SELECT_SCORE, [postId]);
  return Number(rows[0]?.score ?? 0);
}

/** The user's current vote on a post, or null. */
export async function userVote(postId, userId) {
  const rows = await query(SELECT_VOTE, [postId, userId]);
  if (rows.length === 0) return null;
  return { value: Number(rows[0].value) };
}
