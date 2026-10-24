// C-DIR-1 / C-DIR-2 proof file (docs/03): the tokenizer, the bound parameters,
// and the fixed five-column projection.

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll, row } from '../helpers/db.mjs';
import { makeUser } from '../helpers/users.mjs';
import { FilterError, PROJECTION, buildFilter, list, tokenize } from '../../src/hooks/directory.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

describe('staff directory filter (C-DIR-1, C-DIR-2)', () => {
  it('testTokensBecomeFieldOpValue', () => {
    expect(tokenize('role:admin joined>=2024-01-01 alice')).toEqual([
      { field: 'role', op: ':', value: 'admin' },
      { field: 'joined', op: '>=', value: '2024-01-01' },
      { field: 'username', op: '~', value: 'alice' },
    ]);
  });

  it('c-dir-1 every token value is a bound parameter, never SQL text', () => {
    const { where, params } = buildFilter("role:admin username:o'brien joined>='1' OR 1=1--");

    expect(where.length).toBeGreaterThanOrEqual(3);
    expect(params.length).toBe(where.length);
    for (const fragment of where) {
      expect(fragment).toContain('?');
      // No token text, quote or comment marker ever reaches the SQL fragment.
      expect(fragment).not.toMatch(/[';]/);
      expect(fragment).not.toContain('--');
    }
    // Values ride in the parameter array, escaped for LIKE where they are used
    // as a substring match.
    expect(params).toContain('%admin%');
    expect(params).toContain("%o'brien%");
    expect(params).toContain("'1'");
    expect(params.some((value) => String(value).includes('1=1'))).toBe(true);
  });

  it('c-dir-1 an apostrophe in a token changes no result set', async () => {
    await makeUser('alice');
    await makeUser("bob's");

    const plain = await list('alice');
    const quoted = await list("alice'");
    const injection = await list("alice' OR '1'='1");
    const commented = await list('alice; --');

    expect(plain.map((u) => u.username)).toEqual(['alice']);
    expect(quoted).toEqual([]);
    expect(injection).toEqual([]);
    expect(commented).toEqual([]);
  });

  it('c-dir-1 rejects a field that is not on the allowlist', () => {
    expect(() => buildFilter('password:hunter2')).toThrow(FilterError);
    expect(() => buildFilter('password:hunter2')).toThrow(/Unknown filter field/);
    expect(() => buildFilter('role~admin')).not.toThrow();
    // A qualified column name is not a field: it degrades to a username search,
    // it does not reach the SQL as a column reference.
    expect(buildFilter('u.role=x').where).toEqual(['u.username LIKE ?']);
  });

  it('c-dir-1 the role parameter is limited to the two known roles', () => {
    expect(() => buildFilter('', 'administrator')).toThrow(/Unknown role filter/);
    expect(() => buildFilter('', "user' OR 1=1--")).toThrow(/Unknown role filter/);
    expect(buildFilter('', 'admin').where).toEqual(['u.role = ?']);
  });

  it('c-dir-2 rejects a value that is not a primitive string', () => {
    for (const value of [
      { $ne: null },
      { $gt: '' },
      { $regex: '.*' },
      { $where: 'sleep(5)' },
      ['alice'],
      42,
      null,
      undefined,
      true,
      () => 'alice',
    ]) {
      expect(() => buildFilter(value)).toThrow(/plain text/);
      expect(() => tokenize(value)).toThrow(/plain text/);
    }
  });

  it('c-dir-2 an operator object never reaches the query', async () => {
    await makeUser('alice');
    await makeUser('bob');

    // The route reads one flat string; anything else is refused before a query.
    await expect(list({ $ne: '' })).rejects.toThrow(/plain text/);
    await expect(list('alice', { role: 'admin' })).rejects.toThrow(/plain text/);
    expect((await list('')).map((u) => u.username)).toEqual(['alice', 'bob']);
  });

  it('the projection is exactly the five documented columns', async () => {
    await makeUser('alice');
    const rows = await list('alice');

    expect(PROJECTION).toEqual(['id', 'username', 'role', 'created_at', 'post_count']);
    expect(Object.keys(rows[0]).sort()).toEqual([...PROJECTION].sort());
    expect(rows[0]).not.toHaveProperty('password_hash');
    expect(rows[0]).not.toHaveProperty('email');
  });

  it('LIKE wildcards in a term are escaped, not honoured', async () => {
    await makeUser('alice');
    await makeUser('bob');

    expect(await list('%')).toEqual([]);
    expect(await list('a_b')).toEqual([]);
  });
});
