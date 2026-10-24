// Saved XPath search (docs/02 section 7, docs/03 C-XPATH-1, C-DIR-2).
//
// The search runs against an in-memory export document built by this app, not
// against the database. The security shape mirrors the SQL side:
//
//   * the request is parsed into an AST of `{ field, op, value }` nodes;
//   * `field` and `op` are looked up in fixed allowlists and become XPath
//     fragments that this file wrote — a field name can never be supplied by the
//     caller;
//   * `value` never enters the expression string. It is handed to the evaluator
//     as an XPath variable (`$username`, `$role`, …) and bound by the library;
//   * a value that is not a primitive string/number/boolean is rejected before
//     an expression, a predicate or a query is built (C-DIR-2), so the operator
//     objects that show up in NoSQL injections (`$ne`, `$regex`) have no meaning
//     here.

import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';
import { FILTER_OPS, tokenize } from './directory.js';

/**
 * Field → attribute, and the operators that field accepts. XPath 1.0 compares
 * strings with `=` and `!=` only; ordering needs numbers, so `posts` is the one
 * numeric field and the others never get an ordering operator.
 */
export const XPATH_FIELDS = new Map([
  ['username', { attribute: '@username', ops: ['~', ':', '=', '!='] }],
  ['role', { attribute: '@role', ops: ['~', ':', '=', '!='] }],
  ['joined', { attribute: '@created', ops: [':', '='] }],
  ['posts', { attribute: '@post_count', ops: ['=', '!=', '<', '<=', '>', '>='], numeric: true }],
]);

export class XPathBuildError extends Error {
  constructor(message) {
    super(message);
    this.name = 'XPathBuildError';
  }
}

/** C-DIR-2 for the document side: primitives only. */
function assertPrimitive(value) {
  const type = typeof value;
  if (type !== 'string' && type !== 'number' && type !== 'boolean') {
    throw new XPathBuildError('Filter values must be plain text.');
  }
  if (type === 'string' && value.includes('\u0000')) throw new XPathBuildError('Filter values must be plain text.');
}

/** Tokens (the same tokenizer the directory uses) become AST nodes. */
export function buildAst(raw) {
  return tokenize(raw).map((token) => ({ field: token.field.toLowerCase(), op: token.op, value: token.value }));
}

function predicateFor(node, index) {
  const field = XPATH_FIELDS.get(node.field);
  if (field === undefined) throw new XPathBuildError(`Unknown filter field: ${node.field}`);

  const op = FILTER_OPS.get(node.op);
  if (op === undefined) throw new XPathBuildError(`Unknown filter operator: ${node.op}`);
  if (!field.ops.includes(node.op)) {
    throw new XPathBuildError(`Operator ${node.op} cannot be used on ${node.field}`);
  }

  // One variable per node: the value is bound, never spliced.
  const name = `v${index}`;
  if (op === 'LIKE') return { text: `contains(${field.attribute}, $${name})`, name, numeric: field.numeric === true };
  if (field.numeric === true) {
    return { text: `number(${field.attribute}) ${op} number($${name})`, name, numeric: true };
  }
  return { text: `${field.attribute} ${op} $${name}`, name, numeric: field.numeric === true };
}

/**
 * Compile the AST. The returned expression is built entirely from fragments this
 * file wrote plus `$vN` variable references; `variables` carries the values.
 */
export function compile(nodes) {
  const predicates = [];
  const variables = Object.create(null);

  nodes.forEach((node, index) => {
    assertPrimitive(node.value);
    const predicate = predicateFor(node, index);
    predicates.push(predicate.text);
    if (predicate.numeric) {
      const asNumber = Number(node.value);
      if (!Number.isFinite(asNumber)) throw new XPathBuildError('Numeric filter values must be a number.');
      variables[predicate.name] = String(asNumber);
    } else {
      // Text fields take text only: a number or a boolean would silently become a
      // different comparison than the one the directory would make in SQL.
      if (typeof node.value !== 'string') throw new XPathBuildError('Filter values must be plain text.');
      variables[predicate.name] = node.value;
    }
  });

  const where = predicates.length > 0 ? `[${predicates.join(' and ')}]` : '';
  return { expression: `/directory/user${where}`, variables };
}

/** The document the search runs against — built here, never parsed from a user. */
export function directoryDocument(rows) {
  const escape = (value) =>
    String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  const body = rows
    .map(
      (row) =>
        `<user id="${escape(row.id)}" username="${escape(row.username)}" role="${escape(row.role)}" ` +
        `created="${escape(row.created_at)}" post_count="${escape(row.post_count ?? 0)}"/>`,
    )
    .join('');

  return new DOMParser().parseFromString(`<directory>${body}</directory>`, 'text/xml');
}

/** Evaluate the compiled search and project the five directory columns. */
export function search(rows, raw) {
  const ast = buildAst(raw);
  const { expression, variables } = compile(ast);
  const doc = directoryDocument(rows);

  // `parse(...).select({ node, variables })`: the evaluator binds the variables
  // itself, so the expression string stays exactly as compile() wrote it.
  const matched = xpath.parse(expression).select({ node: doc, variables });

  return {
    expression,
    variables,
    users: matched
      .filter((node) => node?.nodeType === 1)
      .map((node) => ({
        id: Number(node.getAttribute('id')),
        username: node.getAttribute('username'),
        role: node.getAttribute('role'),
        created_at: node.getAttribute('created'),
        post_count: Number(node.getAttribute('post_count')),
      })),
  };
}
