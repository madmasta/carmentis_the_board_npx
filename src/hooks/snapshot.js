// Board snapshot and restore (docs/02 section 7, docs/03 C-JSON-1, C-RACE-1).
//
// A snapshot is plain JSON — no type tags that dispatch code, no reviver, no
// `Function`, no `vm`. Reading it back is a validation problem, not a
// deserialization problem:
//
//   * `JSON.parse` is called without a reviver, and the result is checked against
//     an explicit schema before one row is touched: envelope keys, `schema`
//     version, `board_id`, and then every record against a fixed field list with
//     a declared type, length or range per field;
//   * a key that is not on the field list is an error — that is also what stops
//     `__proto__` and `constructor` from reaching an object merge;
//   * `type` is a whitelist of three names; nothing is looked up by name;
//   * the write happens in one transaction: either the whole board comes back or
//     nothing changes (C-RACE-1 — two restores cannot interleave, the transaction
//     holds the board's rows for its duration).

import { query, transaction } from '../db/connection.js';
import { sqlDateTime } from '../lib/clock.js';

export const SNAPSHOT_SCHEMA = 'theboard-snapshot/1';
export const SNAPSHOT_MISMATCH = 'That snapshot does not fit this board.';
export const SNAPSHOT_UNREADABLE = 'That snapshot could not be read.';

const ENVELOPE_KEYS = ['schema', 'board_id', 'exported_at', 'records'];

/** Explicit field schemas: the only keys accepted, and what each must be. */
const RECORD_SCHEMAS = {
  board: {
    name: { type: 'string', min: 1, max: 100 },
    description: { type: 'string', min: 0, max: 500 },
    default_access: { type: 'flag' },
  },
  post: {
    id: { type: 'int', min: 1 },
    board_id: { type: 'int', min: 1 },
    parent_id: { type: 'intOrNull', min: 1 },
    author_id: { type: 'int', min: 1 },
    title: { type: 'stringOrNull', min: 1, max: 200 },
    body: { type: 'string', min: 1, max: 10000 },
    created_at: { type: 'datetime' },
  },
  vote: {
    post_id: { type: 'int', min: 1 },
    user_id: { type: 'int', min: 1 },
    value: { type: 'vote' },
  },
};

export class SnapshotError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'SnapshotError';
    this.status = status;
  }
}

const DATETIME = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;

function checkValue(path, value, rule, errors) {
  if (rule.type === 'string') {
    if (typeof value !== 'string') return errors.push(`${path}: expected text`);
    if (value.length < rule.min || value.length > rule.max) return errors.push(`${path}: length out of range`);
    return undefined;
  }
  if (rule.type === 'stringOrNull') {
    if (value === null) return undefined;
    return checkValue(path, value, { type: 'string', min: rule.min, max: rule.max }, errors);
  }
  if (rule.type === 'int' || rule.type === 'intOrNull') {
    if (value === null && rule.type === 'intOrNull') return undefined;
    if (typeof value !== 'number' || !Number.isInteger(value)) return errors.push(`${path}: expected an integer`);
    if (value < rule.min) return errors.push(`${path}: out of range`);
    return undefined;
  }
  if (rule.type === 'flag') {
    if (value !== 0 && value !== 1) return errors.push(`${path}: expected 0 or 1`);
    return undefined;
  }
  if (rule.type === 'vote') {
    if (value !== 1 && value !== -1) return errors.push(`${path}: expected 1 or -1`);
    return undefined;
  }
  if (rule.type === 'datetime') {
    if (typeof value !== 'string' || !DATETIME.test(value)) return errors.push(`${path}: expected a timestamp`);
    return undefined;
  }
  return errors.push(`${path}: unknown rule`);
}

/** Keys must be plain identifiers — this is what keeps `__proto__` out. */
function assertPlainKey(key, path, errors) {
  if (!/^[a-z_][a-z0-9_]*$/i.test(String(key))) errors.push(`${path}: illegal key ${JSON.stringify(key)}`);
}

function validateRecord(record, index, boardId, errors) {
  const path = `records[${index}]`;
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    errors.push(`${path}: expected an object`);
    return;
  }

  const type = record.type;
  const schema = Object.hasOwn(RECORD_SCHEMAS, type) ? RECORD_SCHEMAS[type] : null;
  if (schema === null) {
    errors.push(`${path}: unknown record type`);
    return;
  }

  for (const key of Object.keys(record)) {
    assertPlainKey(key, path, errors);
    if (key !== 'type' && !Object.hasOwn(schema, key)) errors.push(`${path}: unexpected field ${key}`);
  }

  for (const [field, rule] of Object.entries(schema)) {
    if (!Object.hasOwn(record, field)) {
      errors.push(`${path}.${field}: missing`);
      continue;
    }
    checkValue(`${path}.${field}`, record[field], rule, errors);
  }

  if (type === 'post' && typeof record.board_id === 'number' && record.board_id !== boardId) {
    errors.push(`${path}: belongs to another board`);
  }
}

/**
 * Parse and validate. Returns `{ ok: true, snapshot }` or
 * `{ ok: false, status, message }` — 409 when the snapshot is well formed but
 * belongs to a different board or an older schema.
 */
export function readSnapshot(text, boardId) {
  let parsed;
  try {
    // No reviver. Anything a reviver could build is refused below anyway.
    parsed = JSON.parse(String(text ?? ''));
  } catch {
    return { ok: false, status: 400, message: SNAPSHOT_UNREADABLE };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, status: 400, message: SNAPSHOT_UNREADABLE };
  }

  for (const key of Object.keys(parsed)) assertPlainKeyAllowed(key);
  for (const key of ENVELOPE_KEYS) {
    if (!Object.hasOwn(parsed, key)) return { ok: false, status: 409, message: SNAPSHOT_MISMATCH };
  }
  for (const key of Object.keys(parsed)) {
    if (!ENVELOPE_KEYS.includes(key)) return { ok: false, status: 409, message: SNAPSHOT_MISMATCH };
  }

  if (parsed.schema !== SNAPSHOT_SCHEMA || Number(parsed.board_id) !== Number(boardId)) {
    return { ok: false, status: 409, message: SNAPSHOT_MISMATCH };
  }
  if (!Array.isArray(parsed.records) || parsed.records.length > 5000) {
    return { ok: false, status: 400, message: SNAPSHOT_UNREADABLE };
  }
  if (typeof parsed.exported_at !== 'string' || !DATETIME.test(parsed.exported_at)) {
    return { ok: false, status: 409, message: SNAPSHOT_MISMATCH };
  }

  const errors = [];
  parsed.records.forEach((record, index) => validateRecord(record, index, Number(boardId), errors));
  if (errors.length > 0) return { ok: false, status: 400, message: `Snapshot is not valid: ${errors.slice(0, 5).join('; ')}` };

  return { ok: true, snapshot: parsed };
}

function assertPlainKeyAllowed(key) {
  if (!/^[a-z_][a-z0-9_]*$/i.test(String(key))) throw new SnapshotError(SNAPSHOT_UNREADABLE);
}

/** Build the snapshot for a board (plain data, in a fixed key order). */
export async function snapshot(boardId) {
  const boardRows = await query(
    'SELECT id, name, description, default_access FROM boards WHERE id = ? AND deleted_at IS NULL',
    [boardId],
  );
  if (boardRows.length === 0) return null;
  const board = boardRows[0];

  const posts = await query(
    `SELECT id, board_id, parent_id, author_id, title, body, created_at
       FROM posts
      WHERE board_id = ? AND deleted_at IS NULL
      ORDER BY id ASC`,
    [boardId],
  );

  const votes = await query(
    `SELECT v.post_id, v.user_id, v.value
       FROM votes v
       JOIN posts p ON p.id = v.post_id
      WHERE p.board_id = ?
      ORDER BY v.post_id ASC, v.user_id ASC`,
    [boardId],
  );

  return {
    schema: SNAPSHOT_SCHEMA,
    board_id: Number(board.id),
    exported_at: sqlDateTime(new Date()),
    records: [
      {
        type: 'board',
        name: String(board.name),
        description: String(board.description ?? ''),
        default_access: Number(board.default_access),
      },
      ...posts.map((post) => ({
        type: 'post',
        id: Number(post.id),
        board_id: Number(post.board_id),
        parent_id: post.parent_id === null ? null : Number(post.parent_id),
        author_id: Number(post.author_id),
        title: post.title === null ? null : String(post.title),
        body: String(post.body),
        created_at: String(post.created_at),
      })),
      ...votes.map((vote) => ({
        type: 'vote',
        post_id: Number(vote.post_id),
        user_id: Number(vote.user_id),
        value: Number(vote.value),
      })),
    ],
  };
}

/**
 * Apply a validated snapshot in one transaction: board settings, then the
 * board's posts and votes replaced by the snapshot's rows.
 */
export async function restore(boardId, validated) {
  const records = validated.records;
  const boardRecord = records.find((record) => record.type === 'board');
  const postRecords = records.filter((record) => record.type === 'post');
  const voteRecords = records.filter((record) => record.type === 'vote');

  return transaction(async (conn) => {
    await conn.execute(
      'UPDATE boards SET name = ?, description = ?, default_access = ? WHERE id = ? AND deleted_at IS NULL',
      [boardRecord.name, boardRecord.description, boardRecord.default_access, boardId],
    );

    await conn.execute(
      'DELETE FROM votes WHERE post_id IN (SELECT id FROM posts WHERE board_id = ?)',
      [boardId],
    );
    await conn.execute('DELETE FROM posts WHERE board_id = ?', [boardId]);

    for (const post of postRecords) {
      await conn.execute(
        `INSERT INTO posts (id, board_id, parent_id, author_id, title, body, created_at, edited_at, deleted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
        [post.id, post.board_id, post.parent_id, post.author_id, post.title, post.body, post.created_at],
      );
    }

    for (const vote of voteRecords) {
      await conn.execute('INSERT INTO votes (post_id, user_id, value) VALUES (?, ?, ?)', [
        vote.post_id,
        vote.user_id,
        vote.value,
      ]);
    }

    return { posts: postRecords.length, votes: voteRecords.length };
  });
}
