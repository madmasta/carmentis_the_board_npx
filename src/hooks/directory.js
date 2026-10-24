// Staff directory filter (docs/02 section 7, docs/03 C-DIR-1, C-DIR-2).
//
// The route is one `SELECT` over `users` whose projection is exactly five
// columns — id, username, role, created_at, post_count — so whatever a filter
// does, it can only change which rows match, never which columns come back.
//
// A filter string is split into tokens; each token becomes
// `{ field, op, value }` where `field` must be on the allowlist and `op` comes
// from a fixed set. The value is *never* written into the SQL text: it is pushed
// into `params` and bound by the driver (C-DIR-1). A value that is not a
// primitive string is rejected before a query, a filter string or a document
// predicate is built, so no operator object (`$ne`, `$gt`, `$regex`, `$where`) is
// ever interpreted (C-DIR-2) — the same rule the XPath search inherits.
//
// Every SQL fragment in this file is a literal. `docs/03` C-SQL-1's scan fails a
// `${` or a `+` used to build a fragment anywhere under `src/hooks/`, so the
// field/operator allowlist below is spelled out rather than composed: 32 lines
// of table is what makes "the identifier list is fixed" auditable by eye and by
// the gate.

import { query } from '../db/connection.js';
import { escapeLike } from '../repositories/user.repository.js';

export const FILTER_FIELDS = new Map([
  ['username', 'u.username'],
  ['email', 'u.email'],
  ['role', 'u.role'],
  ['joined', 'u.created_at'],
]);

export const FILTER_OPS = new Map([
  ['~', 'LIKE'],
  [':', 'LIKE'],
  ['=', '='],
  ['!=', '!='],
  ['<', '<'],
  ['<=', '<='],
  ['>', '>'],
  ['>=', '>='],
]);

/** The projection is fixed here; nothing a filter produces can widen it. */
export const PROJECTION = ['id', 'username', 'role', 'created_at', 'post_count'];

/** The statement skeleton; the WHERE clauses are appended from the table below. */
export const SELECT_USERS =
  'SELECT u.id, u.username, u.role, u.created_at, ' +
  '(SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id AND p.deleted_at IS NULL) AS post_count ' +
  'FROM users u';

const LIKE_OPS = ['~', ':'];

/** field -> op -> complete literal fragment. No composition anywhere. */
const FILTER_SQL = new Map([
  [
    'username',
    new Map([
      ['~', 'u.username LIKE ?'],
      [':', 'u.username LIKE ?'],
      ['=', 'u.username = ?'],
      ['!=', 'u.username != ?'],
      ['<', 'u.username < ?'],
      ['<=', 'u.username <= ?'],
      ['>', 'u.username > ?'],
      ['>=', 'u.username >= ?'],
    ]),
  ],
  [
    'email',
    new Map([
      ['~', 'u.email LIKE ?'],
      [':', 'u.email LIKE ?'],
      ['=', 'u.email = ?'],
      ['!=', 'u.email != ?'],
      ['<', 'u.email < ?'],
      ['<=', 'u.email <= ?'],
      ['>', 'u.email > ?'],
      ['>=', 'u.email >= ?'],
    ]),
  ],
  [
    'role',
    new Map([
      ['~', 'u.role LIKE ?'],
      [':', 'u.role LIKE ?'],
      ['=', 'u.role = ?'],
      ['!=', 'u.role != ?'],
      ['<', 'u.role < ?'],
      ['<=', 'u.role <= ?'],
      ['>', 'u.role > ?'],
      ['>=', 'u.role >= ?'],
    ]),
  ],
  [
    'joined',
    new Map([
      ['~', 'u.created_at LIKE ?'],
      [':', 'u.created_at LIKE ?'],
      ['=', 'u.created_at = ?'],
      ['!=', 'u.created_at != ?'],
      ['<', 'u.created_at < ?'],
      ['<=', 'u.created_at <= ?'],
      ['>', 'u.created_at > ?'],
      ['>=', 'u.created_at >= ?'],
    ]),
  ],
]);

export class FilterError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FilterError';
  }
}

/** C-DIR-2: only a primitive string is a value. No object, array, number, null. */
function assertPrimitive(value) {
  if (typeof value !== 'string') throw new FilterError('Filter values must be plain text.');
  if (value.includes('\u0000')) throw new FilterError('Filter values must be plain text.');
}

/** `field:alice`, `joined>=2024-01-01`, or a bare word meaning username-like. */
export function tokenize(raw) {
  assertPrimitive(raw);
  const tokens = String(raw)
    .split(/[\s,]+/)
    .filter((token) => token !== '' && token.toLowerCase() !== 'and');

  const parsed = [];
  for (const token of tokens) {
    const match = /^([A-Za-z_][\w-]*)(~|:|!=|<=|>=|=|<|>)(.*)$/.exec(token);
    if (match === null) {
      parsed.push({ field: 'username', op: '~', value: token });
      continue;
    }
    const [, field, op, value] = match;
    parsed.push({ field, op, value });
  }
  return parsed;
}

/**
 * The WHERE fragments and the bound parameters. Every fragment comes out of
 * `FILTER_SQL` — a literal this module wrote — and every value goes into
 * `params` for the driver to bind.
 */
export function buildFilter(raw, role = '') {
  const where = [];
  const params = [];

  assertPrimitive(raw);
  assertPrimitive(role);

  if (role !== '') {
    if (role !== 'admin' && role !== 'user') throw new FilterError('Unknown role filter.');
    where.push('u.role = ?');
    params.push(role);
  }

  for (const token of tokenize(raw)) {
    const byOp = FILTER_SQL.get(token.field.toLowerCase());
    if (byOp === undefined) throw new FilterError(`Unknown filter field: ${token.field}`);

    const fragment = byOp.get(token.op);
    if (fragment === undefined) throw new FilterError(`Unknown filter operator: ${token.op}`);
    if (token.value === '') throw new FilterError('Filter values may not be empty.');

    where.push(fragment);
    params.push(LIKE_OPS.includes(token.op) ? `%${escapeLike(token.value)}%` : token.value);
  }

  return { where, params };
}

/** The directory listing: five columns, always. */
export async function list(raw = '', role = '', { limit = 100 } = {}) {
  const { where, params } = buildFilter(raw, role);
  const capped = Math.min(Math.max(Number.parseInt(String(limit), 10) || 100, 1), 500);

  const parts = [SELECT_USERS];
  if (where.length > 0) {
    parts.push('WHERE');
    parts.push(where.join(' AND '));
  }
  parts.push('ORDER BY u.username ASC');
  parts.push('LIMIT ?');

  const rowsOut = await query(parts.join(' '), [...params, capped]);
  return rowsOut.map((row) => Object.fromEntries(PROJECTION.map((key) => [key, row[key]])));
}
