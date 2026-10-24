// C-XPATH-1 / C-DIR-2 proof file (docs/03): the expression is built from an AST
// of allowlisted fields and operators, and values are bound as variables.

import { describe, expect, it } from 'vitest';
import { XPathBuildError, buildAst, compile, directoryDocument, search } from '../../src/hooks/xpath.js';

const ROWS = [
  { id: 1, username: 'alice', role: 'admin', created_at: '2024-01-05 10:00:00', post_count: 3 },
  { id: 2, username: 'bob', role: 'user', created_at: '2024-06-05 10:00:00', post_count: 0 },
  { id: 3, username: 'carol', role: 'user', created_at: '2024-07-05 10:00:00', post_count: 7 },
];

const names = (result) => result.users.map((u) => u.username);

describe('saved xpath search (C-XPATH-1)', () => {
  it('an AST node carries field, op and value', () => {
    expect(buildAst('role:admin posts>2')).toEqual([
      { field: 'role', op: ':', value: 'admin' },
      { field: 'posts', op: '>', value: '2' },
    ]);
  });

  it('c-xpath-1 the expression never contains user input', () => {
    const hostile = "') or 1=1 or contains(@username,'x";
    const { expression, variables } = compile([{ field: 'username', op: '~', value: hostile }]);

    expect(expression).toBe('/directory/user[contains(@username, $v0)]');
    expect(expression).not.toContain(hostile);
    expect(expression).not.toContain("'");
    expect(variables).toEqual({ v0: hostile });
  });

  it('c-xpath-1 a hostile value is matched literally, never as syntax', () => {
    // No spaces: a space would be a token separator, not part of the value.
    for (const value of [`")or(true`, '*', '//*', '@role=', 'admin][', '][@role=', "';--"]){
      const result = search(ROWS, `username:${value}`);
      // Every one of these is a plain substring test against three usernames.
      expect(names(result)).toEqual([]);
      expect(result.expression).toBe('/directory/user[contains(@username, $v0)]');
      expect(result.variables.v0).toBe(value);
    }
  });

  it('c-xpath-1 fields and operators come from the allowlist', () => {
    expect(() => compile([{ field: 'password_hash', op: '=', value: 'x' }])).toThrow(XPathBuildError);
    expect(() => compile([{ field: '@role', op: '=', value: 'x' }])).toThrow(/Unknown filter field/);
    expect(() => compile([{ field: 'joined', op: '>=', value: '2024-01-01' }])).toThrow(/cannot be used on joined/);
    expect(() => compile([{ field: 'role', op: '~', value: 'ad' }])).not.toThrow();
    expect(() => compile([{ field: 'posts', op: '>=', value: '2' }])).not.toThrow();
  });

  it('numeric comparisons work on the numeric field only', () => {
    expect(names(search(ROWS, 'posts>2'))).toEqual(['alice', 'carol']);
    expect(names(search(ROWS, 'posts>=7'))).toEqual(['carol']);
    expect(names(search(ROWS, 'posts=0'))).toEqual(['bob']);
    expect(() => compile([{ field: 'posts', op: '=', value: 'lots' }])).toThrow(/must be a number/);
  });

  it('several tokens combine with and', () => {
    const result = search(ROWS, 'role:user bob');
    expect(names(result)).toEqual(['bob']);
    expect(result.expression).toBe('/directory/user[contains(@role, $v0) and contains(@username, $v1)]');
  });

  it('c-dir-2 a filter value that is not a primitive is refused', () => {
    for (const value of [{ $ne: null }, { $regex: '.*' }, ['admin'], 7, true, null, undefined]) {
      expect(() => compile([{ field: 'role', op: '=', value }])).toThrow(/plain text/);
    }
    expect(() => buildAst({ $ne: 'admin' })).toThrow(/plain text/);
  });

  it('the document is built by the app, and the search projects five columns', () => {
    const doc = directoryDocument(ROWS);
    expect(doc.documentElement.nodeName).toBe('directory');

    const result = search(ROWS, 'role:user');
    expect(names(result)).toEqual(['bob', 'carol']);
    expect(Object.keys(result.users[0]).sort()).toEqual(['created_at', 'id', 'post_count', 'role', 'username']);
  });
});
