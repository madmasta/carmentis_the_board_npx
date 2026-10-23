// M1 unit coverage for the ordered router (docs/03 C-ACL-4 proof case
// `guard-required`).

import { describe, it, expect } from 'vitest';
import { RouteTableError, buildTable, intParam, match } from '../../src/http/router.js';

const noop = () => {};

const table = buildTable([
  { method: 'GET', path: '/', guard: 'anon', handler: noop },
  { method: 'GET', path: '/admin', guard: 'anon', handler: noop },
  { method: 'GET', path: '/board/:id', guard: 'login', handler: noop },
  { method: 'GET', path: '/post/:id', guard: 'login', handler: noop },
  { method: 'GET', path: '/post/:id/edit', guard: 'login', handler: noop },
  { method: 'POST', path: '/post/:id/delete', guard: 'admin', handler: noop },
  { method: 'ANY', path: '/health', guard: 'anon', handler: noop },
]);

describe('route table', () => {
  it('guard-required: refuses to build a table with an undeclared guard', () => {
    expect(() => buildTable([{ method: 'POST', path: '/x', handler: noop }])).toThrow(RouteTableError);
    expect(() => buildTable([{ method: 'POST', path: '/x', guard: 'maybe', handler: noop }])).toThrow(
      RouteTableError,
    );
    expect(() => buildTable([{ method: 'POST', path: '/x', guard: 'login' }])).toThrow(RouteTableError);
  });

  it('rejects duplicate method+path pairs and unknown methods', () => {
    expect(() =>
      buildTable([
        { method: 'GET', path: '/a', guard: 'anon', handler: noop },
        { method: 'GET', path: '/a', guard: 'anon', handler: noop },
      ]),
    ).toThrow(RouteTableError);
    expect(() => buildTable([{ method: 'PATCH', path: '/a', guard: 'anon', handler: noop }])).toThrow(
      RouteTableError,
    );
  });

  it('matches the exact segment count, so /post/:id never eats /post/:id/edit', () => {
    expect(match(table, 'GET', '/post/12/edit').entry.path).toBe('/post/:id/edit');
    expect(match(table, 'GET', '/post/12').entry.path).toBe('/post/:id');
  });

  it('requires digits for :id, mirroring the PHP ctype_digit guard', () => {
    expect(match(table, 'GET', '/board/abc')).toBeNull();
    expect(match(table, 'GET', '/board/7')).toEqual({
      entry: expect.objectContaining({ path: '/board/:id' }),
      params: { id: '7' },
    });
  });

  it('treats the root path as the empty segment list', () => {
    expect(match(table, 'GET', '/').entry.path).toBe('/');
  });

  it('ANY matches every verb, and unmatched paths return null', () => {
    expect(match(table, 'POST', '/health').entry.path).toBe('/health');
    expect(match(table, 'DELETE', '/nope')).toBeNull();
  });

  it('trailing slashes are stripped before matching', () => {
    expect(match(table, 'GET', '/admin/').entry.path).toBe('/admin');
  });

  it('intParam only accepts digit strings', () => {
    expect(intParam({ id: '42' }, 'id')).toBe(42);
    expect(intParam({ id: '4a' }, 'id')).toBeNull();
    expect(intParam({}, 'id')).toBeNull();
  });
});
