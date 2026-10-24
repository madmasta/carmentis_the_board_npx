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
export const SELECT_USERS = `SELECT u.id, u.username, u.role, u.created_at,
       (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id AND p.deleted_at IS NULL) AS post_count
   FROM users u`;

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

// ---------------------------------------------------------------------------
// Advanced search: one filter string, evaluated in-process
//
// `GET /directory?mode=filter&q=…` reads the term as filter syntax instead of free
// text. The string is LDAP-shaped (docs/07 section 6: this port runs no directory
// server, so the app parses and evaluates its own filter grammar). C-DIR-1 governs
// this path in a specific way: every attribute name comes from the allowlist below,
// every operator comes from the tokenizer, and every value is escaped with the
// RFC 4515 rules in `escapeLdap` before it is rendered. A caller-supplied `(`, `)`,
// `|`, `&` or `*` is therefore data inside an assertion, never a separator, and the
// filter the caller asked for is the filter the evaluator sees.
// ---------------------------------------------------------------------------

/** RFC 4515 escaping: one pass through a map, so a backslash cannot double-escape. */
export const LDAP_ESCAPES = new Map([
  ['\\', '\\5c'],
  ['(', '\\28'],
  [')', '\\29'],
  ['*', '\\2a'],
  ['|', '\\7c'],
  ['&', '\\26'],
  ['\u0000', '\\00'],
]);

export function escapeLdap(value) {
  return String(value).replace(/[\\()*|&\u0000]/g, (character) => LDAP_ESCAPES.get(character));
}

/** Un-escaping, used by the evaluator when it reads an assertion value. */
function unescapeLdap(value) {
  return value.replace(/\\([0-9a-fA-F]{2}|.)/g, (_match, code) =>
    /^[0-9a-fA-F]{2}$/.test(code) ? String.fromCharCode(Number.parseInt(code, 16)) : code,
  );
}

/** Filter field name -> document attribute. Anything else is refused (C-DIR-1). */
const FILTER_ATTRIBUTES = new Map([
  ['username', 'username'],
  ['email', 'email'],
  ['role', 'role'],
  ['joined', 'created_at'],
  ['posts', 'post_count'],
]);

/** A term with no field in front of it — and the username field itself — searches the two text fields. */
const BARE_ATTRIBUTES = ['username', 'email'];

/** Attributes an assertion may address on a directory document. Never a secret column. */
const DOC_ATTRIBUTES = new Set(['id', 'username', 'email', 'role', 'created_at', 'post_count']);

export const INVALID_FILTER = 'Invalid filter expression.';

/** The filter text for one token: attribute from the allowlist, operator from the tokenizer, value escaped. */
function filterComponent(token) {
  const attribute = FILTER_ATTRIBUTES.get(token.field.toLowerCase());
  if (attribute === undefined) throw new FilterError(`Unknown filter field: ${token.field}`);
  if (token.value === '') throw new FilterError('Filter values may not be empty.');

  const value = escapeLdap(token.value);
  if (attribute === 'username' || attribute === 'email') {
    const fields = attribute === 'username' ? BARE_ATTRIBUTES : ['email'];
    return `(|${fields.map((field) => `(${field}=*${value}*)`).join('')})`;
  }

  switch (token.op) {
    case '~':
    case ':':
      return `(${attribute}=*${value}*)`;
    case '=':
      return `(${attribute}=${value})`;
    case '!=':
      return `(!(${attribute}=${value}))`;
    // LDAP filters have no ordering operators, and this grammar does not invent
    // any: an ordering token is a free-text-mode thing.
    case '<':
    case '<=':
    case '>':
    case '>=':
      throw new FilterError(`Operator ${token.op} is not available in filter mode.`);
    default:
      throw new FilterError(`Unknown filter operator: ${token.op}`);
  }
}

/**
 * C-DIR-1 for the advanced path: the filter text is rendered from tokenizer
 * tokens, never from the raw term. An empty term is an assertion that matches
 * nothing — "no filter means everyone" belongs to `mode=list`, not to filter mode.
 */
export function renderFilter(raw) {
  const tokens = tokenize(raw);
  if (tokens.length === 0) return '(!(username=))';
  return tokens.length === 1 ? filterComponent(tokens[0]) : `(&${tokens.map(filterComponent).join('')})`;
}

/**
 * Parse the filter grammar: `(&…)`, `(|…)`, `(!…)`, `(attr=value)`, `(attr~=value)`.
 * The result is a tree of assertion nodes; nothing in it is executed.
 */
export function parseFilter(text) {
  const source = String(text ?? '');
  let at = 0;

  const peek = () => source[at];

  /** The raw (still escaped) assertion value, up to the closing bracket. */
  function readValue() {
    const start = at;
    let depth = 0;
    while (at < source.length) {
      const character = source[at];
      if (character === '\\') {
        at += /^[0-9a-fA-F]{2}/.test(source.slice(at + 1, at + 3)) ? 3 : 2;
        continue;
      }
      if (character === '(') depth += 1;
      if (character === ')') {
        if (depth === 0) break;
        depth -= 1;
      }
      at += 1;
    }
    return source.slice(start, at);
  }

  function readAttribute() {
    const start = at;
    while (at < source.length && /[A-Za-z0-9_.-]/.test(source[at])) at += 1;
    return source.slice(start, at);
  }

  function readNode() {
    if (peek() !== '(') throw new FilterError(INVALID_FILTER);
    at += 1;
    let node;
    if (peek() === '&') {
      at += 1;
      const parts = [];
      while (peek() !== ')') parts.push(readNode());
      node = { kind: 'and', parts };
    } else if (peek() === '|') {
      at += 1;
      const parts = [];
      while (peek() !== ')') parts.push(readNode());
      node = { kind: 'or', parts };
    } else if (peek() === '!') {
      at += 1;
      node = { kind: 'not', part: readNode() };
    } else {
      const attribute = readAttribute();
      if (peek() !== '=') throw new FilterError(INVALID_FILTER);
      at += 1;
      const extensible = peek() === '~';
      if (extensible) at += 1;
      // The raw slice decides the assertion kind: an unescaped `*` is the grammar's
      // own wildcard marker, and the renderer only ever adds those around an escaped
      // value. A caller's own `*` reaches this point escaped, so it can never turn
      // into a wildcard of its own (C-DIR-1).
      const raw = readValue();
      // `raw` keeps the grammar's own structure (which `*` were written unescaped);
      // `value` is what an equality assertion compares against. Keeping both matters:
      // an escaped `a` is a literal star in the data, never a wildcard.
      node = {
        kind: extensible || raw.includes('*') ? 'substring' : 'equal',
        attribute,
        raw,
        value: unescapeLdap(raw),
      };
    }
    if (peek() !== ')') throw new FilterError(INVALID_FILTER);
    at += 1;
    return node;
  }

  const root = readNode();
  if (at !== source.length) throw new FilterError(INVALID_FILTER);
  return root;
}

function assertionMatches(node, doc) {
  // An assertion against an attribute the directory does not carry simply does not
  // match: an injected component can aim at a column that exists, never widen the
  // projection.
  if (!DOC_ATTRIBUTES.has(node.attribute)) return false;
  const actual = String(doc[node.attribute] ?? '');

  if (node.kind === 'equal') return actual.toLowerCase() === node.value.toLowerCase();

  // The segments come from the raw text, so only the wildcard markers the grammar
  // itself carries widen the match; each segment is then un-escaped and quoted as text.
  const pattern = node.raw
    .split('*')
    .map((part) => unescapeLdap(part).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  const head = node.raw.startsWith('*') ? '' : '^';
  const tail = node.raw.endsWith('*') ? '' : '$';
  return new RegExp(`${head}${pattern}${tail}`, 'i').test(actual);
}

function evalNode(node, doc) {
  switch (node.kind) {
    case 'and':
      return node.parts.every((part) => evalNode(part, doc));
    case 'or':
      return node.parts.some((part) => evalNode(part, doc));
    case 'not':
      return !evalNode(node.part, doc);
    default:
      return assertionMatches(node, doc);
  }
}

/** Evaluate one filter string against one directory document. */
export function evalFilter(text, doc) {
  return evalNode(parseFilter(text), doc);
}

/**
 * The directory documents the advanced search evaluates: the five listing columns
 * plus the second text field the bare-term disjunction addresses.
 */
export async function directoryDocs({ limit = 500 } = {}) {
  const capped = Math.min(Math.max(Number.parseInt(String(limit), 10) || 500, 1), 500);
  const rows = await query(
    `SELECT u.id, u.username, u.email, u.role, u.created_at,
            (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id AND p.deleted_at IS NULL) AS post_count
       FROM users u ORDER BY u.username ASC LIMIT ?`,
    [capped],
  );
  return rows.map((row) => ({
    id: Number(row.id),
    username: row.username,
    email: row.email,
    role: row.role,
    created_at: row.created_at,
    post_count: Number(row.post_count),
  }));
}

/**
 * The advanced search: render the filter from the term (C-DIR-1), evaluate it over
 * the documents, and project the same five columns the SQL listing projects. A
 * filter that does not parse raises `FilterError`, which the directory handler
 * reports on the page as a filter error — as it does for any filter it refused.
 */
export async function searchDocs(docs, raw) {
  const filter = renderFilter(raw);
  const tree = parseFilter(filter);
  return {
    filter,
    users: docs
      .filter((doc) => evalNode(tree, doc))
      .map((doc) => Object.fromEntries(PROJECTION.map((key) => [key, doc[key]]))),
  };
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
