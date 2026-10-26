// C-DIR-1 / C-DIR-2 proof file (docs/03): the tokenizer, the bound parameters,
// and the fixed five-column projection.

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll, row } from '../helpers/db.mjs';
import { makeUser } from '../helpers/users.mjs';
import {
  FilterError,
  PROJECTION,
  buildFilter,
  escapeLdap,
  evalFilter,
  list,
  parseFilter,
  matchDirectory,
  parseCriteria,
  renderFilter,
  searchDocs,
  tokenize,
} from '../../src/hooks/directory.js';

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

  // The slug is what makes the branch contract work: this is C-SQL-3's LIKE-escape
  // rule seen through the directory, and `vuln/sqli` declares that control away, so
  // the case name has to say so (docs/03 skip granularity, docs/04 §6).
  it('c-sql-3 LIKE wildcards in a token are escaped, not honoured', async () => {
    await makeUser('alice');
    await makeUser('bob');

    expect(await list('%')).toEqual([]);
    expect(await list('a_b')).toEqual([]);
  });
});

// The advanced search — `GET /directory?mode=filter`, docs/02 §7 — is the path where
// C-DIR-1's escaping rule does the work: the filter text is rendered from tokenizer
// tokens, every attribute name comes from the allowlist, and every value is escaped,
// so a caller's `(`, `)`, `|`, `&` or `*` stays data inside one assertion. That rule
// is what `vuln/ldap_injection` declares away, so the cases proving it carry the
// control slug (docs/03 skip granularity, docs/04 §6).
describe('directory advanced filter (C-DIR-1, C-DIR-2)', () => {
  const docs = [
    {
      id: 1,
      username: 'owner_olivia',
      email: 'owner.olivia@example.invalid',
      role: 'admin',
      created_at: '2024-01-02 00:00:00',
      post_count: 4,
    },
    {
      id: 2,
      username: 'regular_rita',
      email: 'regular.rita@example.invalid',
      role: 'user',
      created_at: '2024-03-04 00:00:00',
      post_count: 1,
    },
    {
      id: 3,
      username: 'banned_bob',
      email: 'banned.bob@example.invalid',
      role: 'user',
      created_at: '2024-05-06 00:00:00',
      post_count: 0,
    },
  ];

  it('c-dir-1 the filter text is rendered from tokens and the attribute allowlist', () => {
    expect(renderFilter('olivia')).toBe('(|(username=*olivia*)(email=*olivia*))');
    expect(renderFilter('role:admin')).toBe('(role=*admin*)');
    expect(renderFilter('role=admin')).toBe('(role=admin)');
    expect(renderFilter('role!=admin')).toBe('(!(role=admin))');
    expect(renderFilter('olivia role:admin')).toBe('(&(|(username=*olivia*)(email=*olivia*))(role=*admin*))');
  });

  it('c-dir-1 every value placed in the filter is escaped', () => {
    const BS = String.fromCharCode(92); // a backslash, spelled without one
    const expected = (body) => `(|(username=*${body}*)(email=*${body}*))`;
    const STAR = BS + '2a', RP = BS + '29', PIPE = BS + '7c', LP = BS + '28', AMP = BS + '26', BSL = BS + '5c';

    expect(escapeLdap('*)|(x=*')).toBe(STAR + RP + PIPE + LP + 'x=' + STAR);
    expect(escapeLdap('a&b')).toBe('a' + AMP + 'b');
    expect(escapeLdap('a' + BS + 'f')).toBe('a' + BSL + 'f');

    // The whole renderer path: the breakout term is escaped inside both assertions, so the
    // filter the evaluator sees is the filter the renderer wrote, not the caller's.
    expect(renderFilter('*)|(username=*)(x=*')).toBe(
      expected(STAR + RP + PIPE + LP + 'username=' + STAR + RP + LP + 'x=' + STAR),
    );
  });

  // The one-character version of the same rule: `*` is the grammar's wildcard, and
  // on this path the caller's `*` reaches the evaluator escaped, so it is data.
  // `vuln/ldap_injection` removes the escaping, and this becomes a match-all search.
  // C-DIR-2, document half: the criteria parser is the trust boundary between a
  // request and the operator grammar in the matcher.
  it('c-dir-2 a criteria document with an operator leaf is refused', () => {
    expect(() => parseCriteria('{"username":{"$ne":"x"}}')).toThrow('must be scalars');
    expect(() => parseCriteria('{"role":{"$in":["admin","user"]}}')).toThrow('must be scalars');
    expect(() => parseCriteria('{"username":{"$exists":true}}')).toThrow('must be scalars');
  });

  // Kept on the branch on purpose: the field allowlist is the other half of C-DIR-2,
  // and `vuln/nosql_injection` removes only the scalar-leaf rule — so this case is
  // not slugged and stays green there.
  it('a criteria document may only name a projected field', () => {
    expect(() => parseCriteria('{"password_hash":"x"}')).toThrow('Unknown criteria field');
    expect(() => parseCriteria('{"id":"1"}')).toThrow('Unknown criteria field');
    expect(() => parseCriteria('not json')).toThrow('must be a JSON object');
    expect(() => parseCriteria('[]')).toThrow('must be a JSON object');
  });

  it('a stored criteria document compares with the operator grammar', () => {
    const docs = [
      { username: 'alice', role: 'user', created_at: '2024-01-01', post_count: 5 },
      { username: 'bob', role: 'admin', created_at: '2023-06-01', post_count: 0 },
    ];
    // Scalar leaves contain; operator leaves compare. Both go through one matcher.
    expect(matchDirectory(docs, [{ field: 'role', value: 'adm' }]).map((d) => d.username)).toEqual(['bob']);
    expect(matchDirectory(docs, [{ field: 'username', value: { $ne: 'nobody' } }])).toHaveLength(2);
    expect(matchDirectory(docs, [{ field: 'username', value: { $regex: '^b' } }]).map((d) => d.username)).toEqual(['bob']);
    expect(matchDirectory(docs, [{ field: 'post_count', value: { $gte: '1' } }]).map((d) => d.username)).toEqual(['alice']);
    expect(matchDirectory(docs, [{ field: 'username', value: { $bogus: 1 } }])).toEqual([]);
  });

  it('c-dir-1 a wildcard term stays literal in filter mode', async () => {
    expect((await searchDocs(docs, '*')).users).toEqual([]);
    expect((await searchDocs(docs, 'role:*')).users).toEqual([]);
    expect((await searchDocs(docs, 'o*i')).users).toEqual([]);
  });

  it('c-dir-1 a filter breakout is matched as text and finds nobody', () => {
    const hits = (term) => docs.filter((doc) => evalFilter(renderFilter(term), doc)).map((doc) => doc.username);

    expect(hits('*)|(username=*)(x=*')).toEqual([]);
    expect(hits('*)|(email=*)')).toEqual([]);
    expect(hits('olivia')) // the same grammar, used honestly
      .toEqual(['owner_olivia']);
  });

  it('the advanced search returns the users the filter asks for, in five columns', async () => {
    const byName = await searchDocs(docs, 'olivia');
    expect(byName.users.map((user) => user.username)).toEqual(['owner_olivia']);
    expect(Object.keys(byName.users[0]).sort()).toEqual([...PROJECTION].sort());
    expect(byName.users[0]).not.toHaveProperty('email');
    expect(byName.users[0]).not.toHaveProperty('password_hash');

    const byRole = await searchDocs(docs, 'role:admin');
    expect(byRole.users.map((user) => user.username)).toEqual(['owner_olivia']);

    const combined = await searchDocs(docs, 'bob role:user');
    expect(combined.users.map((user) => user.username)).toEqual(['banned_bob']);
  });

  it('the filter grammar is parsed to a tree, and junk is refused', () => {
    expect(() => parseFilter('username=1')).toThrow(/Invalid filter expression/);
    expect(() => parseFilter('(|(a=1)(b=2')).toThrow(/Invalid filter expression/);
    expect(() => parseFilter('(username=x)(role=user)')).toThrow(/Invalid filter expression/);
    expect(() => renderFilter('nickname:zz')).toThrow(/Unknown filter field: nickname/);
    expect(() => renderFilter('posts>2')).toThrow(/not available in filter mode/);
  });

  it('c-dir-2 a term that is not a primitive never reaches the renderer', () => {
    expect(() => renderFilter({ ne: 'x' })).toThrow(/plain text/);
    expect(() => renderFilter(['olivia'])).toThrow(/plain text/);
  });
});
