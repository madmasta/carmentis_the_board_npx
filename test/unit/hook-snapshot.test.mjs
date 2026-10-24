// C-JSON-1 proof file (docs/03): the snapshot is data, restore is validation,
// and the write is one transaction.

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { count, row, truncateAll } from '../helpers/db.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import { SNAPSHOT_MISMATCH, SNAPSHOT_SCHEMA, SNAPSHOT_UNREADABLE, readSnapshot, restore, snapshot } from '../../src/hooks/snapshot.js';
import * as votes from '../../src/repositories/vote.repository.js';

let admin;
let boardId;
let threadId;

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
  admin = await makeUser('snap-admin', null, 'CorrectHorse1', 'admin');
  boardId = Number((await makeBoard('Snap', 'a board', true, Number(admin.id))).id);
  threadId = await makeThread(boardId, Number(admin.id), 'Title', 'Body');
  await votes.vote(threadId, Number(admin.id), 1);
});

const envelope = (overrides = {}, records = undefined) =>
  JSON.stringify({
    schema: SNAPSHOT_SCHEMA,
    board_id: boardId,
    exported_at: '2024-05-05 10:00:00',
    records: records ?? [
      { type: 'board', name: 'Snap', description: 'a board', default_access: 1 },
      {
        type: 'post',
        id: threadId,
        board_id: boardId,
        parent_id: null,
        author_id: Number(admin.id),
        title: 'Title',
        body: 'Body',
        created_at: '2024-05-05 10:00:00',
      },
      { type: 'vote', post_id: threadId, user_id: Number(admin.id), value: 1 },
    ],
    ...overrides,
  });

describe('board snapshot restore (C-JSON-1)', () => {
  it('a snapshot is plain data', async () => {
    const snap = await snapshot(boardId);

    expect(Object.keys(snap)).toEqual(['schema', 'board_id', 'exported_at', 'records']);
    expect(snap.schema).toBe(SNAPSHOT_SCHEMA);
    expect(snap.records.map((r) => r.type)).toEqual(['board', 'post', 'vote']);
    // Round-trips through JSON with no reviver and still validates.
    expect(readSnapshot(JSON.stringify(snap), boardId).ok).toBe(true);
  });

  it('a snapshot of a missing board is null', async () => {
    expect(await snapshot(999999)).toBeNull();
  });

  it('refuses to read something that is not a snapshot', () => {
    expect(readSnapshot('not json', boardId)).toEqual({ ok: false, status: 400, message: SNAPSHOT_UNREADABLE });
    expect(readSnapshot('[]', boardId)).toEqual({ ok: false, status: 400, message: SNAPSHOT_UNREADABLE });
    expect(readSnapshot('null', boardId)).toEqual({ ok: false, status: 400, message: SNAPSHOT_UNREADABLE });
    expect(readSnapshot('', boardId)).toEqual({ ok: false, status: 400, message: SNAPSHOT_UNREADABLE });
  });

  it('refuses a snapshot from another board or another schema version', () => {
    expect(readSnapshot(envelope({ board_id: boardId + 1 }), boardId)).toEqual({
      ok: false,
      status: 409,
      message: SNAPSHOT_MISMATCH,
    });
    expect(readSnapshot(envelope({ schema: 'theboard-snapshot/0' }), boardId)).toEqual({
      ok: false,
      status: 409,
      message: SNAPSHOT_MISMATCH,
    });
    expect(readSnapshot(envelope({ exported_at: 'yesterday' }), boardId)).toEqual({
      ok: false,
      status: 409,
      message: SNAPSHOT_MISMATCH,
    });
    // A missing envelope key is a mismatch, not a partial read.
    const missing = JSON.parse(envelope());
    delete missing.records;
    expect(readSnapshot(JSON.stringify(missing), boardId).status).toBe(409);
    // An extra envelope key is not accepted either.
    expect(readSnapshot(JSON.stringify({ ...JSON.parse(envelope()), extra: 1 }), boardId).status).toBe(409);
  });

  it('validates every record against its field list', () => {
    const cases = [
      [{ type: 'widget' }, /unknown record type/],
      [{ type: 'board', name: 'x', description: '', default_access: 1, evil: 'x' }, /unexpected field/],
      [{ type: 'board', name: '', description: '', default_access: 1 }, /length out of range/],
      [{ type: 'board', name: 'x', description: 'y'.repeat(501), default_access: 1 }, /length out of range/],
      [{ type: 'board', name: 'x', description: '', default_access: 'yes' }, /expected 0 or 1/],
      [{ type: 'post', id: 0, board_id: boardId, parent_id: null, author_id: 1, title: null, body: 'x', created_at: '2024-01-01 00:00:00' }, /out of range/],
      [{ type: 'post', id: 1, board_id: boardId + 7, parent_id: null, author_id: 1, title: null, body: 'x', created_at: '2024-01-01 00:00:00' }, /another board/],
      [{ type: 'post', id: 1, board_id: boardId, parent_id: null, author_id: 1, title: null, body: '', created_at: '2024-01-01 00:00:00' }, /length out of range/],
      [{ type: 'post', id: 1, board_id: boardId, parent_id: null, author_id: 1, title: null, body: 'x', created_at: 'nope' }, /expected a timestamp/],
      [{ type: 'vote', post_id: 1, user_id: 1, value: 5 }, /expected 1 or -1/],
      [{ type: 'vote', post_id: 1, user_id: 1 }, /missing/],
    ];

    for (const [record, pattern] of cases) {
      const result = readSnapshot(envelope({}, [record]), boardId);
      expect(result.ok).toBe(false);
      expect(result.status).toBe(400);
      expect(result.message).toMatch(pattern);
    }
  });

  it('a __proto__ or constructor key never reaches an object', () => {
    const proto = '{"schema":"theboard-snapshot/1","board_id":' + boardId + ',"exported_at":"2024-05-05 10:00:00","records":[{"type":"board","name":"x","description":"","default_access":1,"__proto__":{"polluted":true}}]}';
    const result = readSnapshot(proto, boardId);
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/illegal key|unexpected field/);
    expect({}.polluted).toBeUndefined();

    for (const key of ['__proto__', 'constructor', 'prototype', 'a b']) {
      expect(readSnapshot(envelope({}, [{ type: 'board', name: 'x', description: '', default_access: 1, [key]: 1 }]), boardId).ok).toBe(false);
    }
  });

  it('restore replaces the board contents in one transaction', async () => {
    const snap = await snapshot(boardId);
    const second = await makeThread(boardId, Number(admin.id), 'Second', 'body 2');
    await votes.vote(second, Number(admin.id), -1);
    expect(await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId])).toBe(2);

    const read = readSnapshot(JSON.stringify(snap), boardId);
    expect(read.ok).toBe(true);
    expect(await restore(boardId, read.snapshot)).toEqual({ posts: 1, votes: 1 });

    expect(await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId])).toBe(1);
    expect(await count('SELECT COUNT(*) FROM votes')).toBe(1);
    expect((await row('SELECT title FROM posts WHERE id = ?', [threadId])).title).toBe('Title');
  });

  it('a restore that fails halfway leaves the board untouched', async () => {
    const snap = await snapshot(boardId);
    const before = await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId]);

    // Author 999999 does not exist: the foreign key fails on the second insert,
    // after the first post has already been written inside the transaction.
    const extra = {
      ...snap.records[1],
      id: snap.records[1].id + 1000,
      author_id: 999999,
    };
    const mutated = { ...snap, records: [...snap.records, extra] };

    await expect(restore(boardId, mutated)).rejects.toThrow();
    expect(await count('SELECT COUNT(*) FROM posts WHERE board_id = ?', [boardId])).toBe(before);
    expect((await row('SELECT title FROM posts WHERE id = ?', [threadId])).title).toBe('Title');
  });

  it('no code is built from a snapshot: type tags are data only', async () => {
    const sneaky = envelope({}, [
      { type: 'constructor', name: 'x', description: '', default_access: 1 },
      { type: 'Function', name: 'x', description: '', default_access: 1 },
    ]);
    const result = readSnapshot(sneaky, boardId);
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/unknown record type/);
  });
});
