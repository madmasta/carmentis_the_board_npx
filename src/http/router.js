// Ordered route matching (docs/01 section 1, docs/03 C-ACL-4).
//
// The PHP front controller is an if/elseif chain, so the first matching entry
// wins and the order of `src/routes.js` is load-bearing. Two consequences this
// file enforces:
//   * patterns match by exact segment count, so `/post/:id` never swallows
//     `/post/:id/edit`;
//   * a `:id` segment only matches digits (the PHP `ctype_digit` guard), so a
//     non-numeric id falls through to the 404 view instead of reaching a
//     handler with NaN.
//
// C-ACL-4: every route declares a guard; the table refuses to build otherwise.

export const GUARDS = new Set(['anon', 'login-or-anon', 'login', 'admin']);
export const METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'ANY']);

export class RouteTableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RouteTableError';
  }
}

function splitPattern(pattern) {
  const path = pattern === '/' ? '/' : pattern.replace(/\/+$/, '');
  return path === '/' ? [] : path.slice(1).split('/');
}

function compile(entry) {
  const segments = splitPattern(entry.path);
  const names = segments.filter((segment) => segment.startsWith(':')).map((segment) => segment.slice(1));
  return { ...entry, segments, names };
}

/**
 * Validate and compile the route table. Throws on a missing guard (C-ACL-4), an
 * unknown guard, a duplicate method+path, or a missing handler.
 */
export function buildTable(entries) {
  const seen = new Set();
  const table = [];

  for (const entry of entries) {
    if (typeof entry?.path !== 'string' || !entry.path.startsWith('/')) {
      throw new RouteTableError(`route without a path: ${JSON.stringify(entry)}`);
    }
    const method = String(entry.method ?? '').toUpperCase();
    if (!METHODS.has(method)) {
      throw new RouteTableError(`route ${entry.path} has an unsupported method: ${entry.method}`);
    }
    if (!GUARDS.has(entry.guard)) {
      throw new RouteTableError(`route ${method} ${entry.path} has no declared guard (C-ACL-4)`);
    }
    if (typeof entry.handler !== 'function') {
      throw new RouteTableError(`route ${method} ${entry.path} has no handler`);
    }
    const key = `${method} ${entry.path}`;
    if (seen.has(key)) throw new RouteTableError(`duplicate route: ${key}`);
    seen.add(key);
    table.push(Object.freeze(compile({ csrf: method !== 'GET' && method !== 'ANY', ...entry, method })));
  }

  return Object.freeze(table);
}

/** First matching route, PHP order. Returns { entry, params } or null. */
export function match(table, method, path) {
  const request = path === '/' ? [] : path.replace(/\/+$/, '').slice(1).split('/');

  for (const entry of table) {
    if (entry.method !== 'ANY' && entry.method !== method) continue;
    if (entry.segments.length !== request.length) continue;

    const params = {};
    let matched = true;
    for (let index = 0; index < entry.segments.length; index++) {
      const pattern = entry.segments[index];
      const value = request[index];
      if (pattern.startsWith(':')) {
        if (pattern === ':id' && !/^\d+$/.test(value)) {
          matched = false;
          break;
        }
        params[pattern.slice(1)] = value;
      } else if (pattern !== value) {
        matched = false;
        break;
      }
    }
    if (matched) return { entry, params };
  }

  return null;
}

/** Integers only, as the inventory's "segment as int" note requires. */
export function intParam(params, name) {
  const raw = params?.[name];
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) return null;
  return Number(raw);
}
