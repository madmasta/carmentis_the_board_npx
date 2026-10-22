#!/usr/bin/env node
// Parity extraction tool: reads the read-only PHP reference target and
// regenerates docs/parity/*-inventory.md.
//
//   node tools/extract-parity.mjs           regenerate the inventories
//   node tools/extract-parity.mjs --check   fail (exit 1) if they differ
//
// The PHP repository is never written to. Override its location with
// --php <path> or the PHP_REPO environment variable.

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, posix, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const REPO_ROOT = join(HERE, '..');

const argv = process.argv.slice(2);
const CHECK = argv.includes('--check');
const phpFlag = argv.indexOf('--php');
const PHP_REPO =
  phpFlag !== -1 && argv[phpFlag + 1]
    ? argv[phpFlag + 1]
    : (process.env.PHP_REPO ?? join(REPO_ROOT, '..', 'carmentis_the_board'));

if (!existsSync(join(PHP_REPO, 'public', 'index.php'))) {
  console.error(`PHP reference target not found at: ${PHP_REPO}`);
  console.error('Pass --php <path> or set PHP_REPO.');
  process.exit(2);
}

const php = (rel) => readFileSync(join(PHP_REPO, rel), 'utf8');
const phpLines = (rel) => php(rel).split(/\r?\n/);

const norm = (p) => p.split(/[\\/]+/).join('/');
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();

// ---------------------------------------------------------------- routes ----

function phpFiles(dir) {
  const abs = join(PHP_REPO, dir);
  const out = [];
  for (const entry of readdirSync(abs)) {
    const full = join(abs, entry);
    if (statSync(full).isDirectory()) {
      out.push(...phpFiles(posix.join(dir, entry)));
    } else if (entry.endsWith('.php')) {
      out.push(norm(relative(PHP_REPO, full)).replaceAll('\\', '/'));
    }
  }
  return out.sort();
}

/** Extract `public function name(...) { ... }` bodies from a PHP file. */
function methodBodies(source) {
  const bodies = {};
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:public|protected|private|final)*\s*function\s+(\w+)\s*\(/.exec(lines[i]);
    if (!m) continue;
    let depth = 0;
    let started = false;
    const body = [];
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === '{') {
          depth++;
          started = true;
        } else if (ch === '}') {
          depth--;
        }
      }
      if (started) body.push(lines[j]);
      if (started && depth === 0) break;
    }
    bodies[m[1]] = body.join('\n');
  }
  return bodies;
}

function routeConditions(source) {
  const rows = [];
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const cond = /^\s*(?:\})?\s*(?:if|elseif)\s+\((.+)\)\s*\{\s*$/.exec(lines[i]);
    if (!cond) continue;
    const body = [];
    for (let j = i + 1; j < lines.length; j++) {
      if (/^\s*\}\s*(?:elseif|else)\b/.test(lines[j]) || /^\s*\}\s*$/.test(lines[j])) break;
      body.push(lines[j]);
    }
    rows.push({ condition: cond[1], body: body.join('\n') });
  }
  return rows;
}

function buildRouteRow(entry) {
  const { condition, body } = entry;
  const routeLit = /(\$route\s*===\s*'([^']*)')/.exec(condition);
  const base = routeLit ? routeLit[2] : null;
  if (base === null) return null;

  const methodMatch = /\$m\s*===\s*'(GET|POST)'/.exec(condition);
  const method = methodMatch ? methodMatch[1] : 'ANY';

  const segments = base === '' ? [] : [base];
  let openEnded = true;
  for (let i = 1; i <= 3; i++) {
    const lit = new RegExp(`\\$s\\[${i}\\]\\s*===\\s*'([^']*)'`).exec(condition);
    if (lit) {
      segments.push(lit[1]);
      continue;
    }
    const digit = new RegExp(`ctype_digit\\(\\$s\\[${i}\\]\\)`).exec(condition);
    if (digit) {
      segments.push(':id');
      continue;
    }
    const absent = new RegExp(`!isset\\(\\$s\\[${i}\\]\\)`).exec(condition);
    if (absent) {
      openEnded = false;
      break;
    }
    if (new RegExp(`isset\\(\\$s\\[${i}\\]\\)`).test(condition)) {
      segments.push(':param');
    }
  }

  const handler =
    /\(new TheBoard\\Http\\(\w+)\(\)\)\s*->\s*(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)/.exec(body) ??
    /new TheBoard\\Http\\(\w+)\(\);\s*\n\s*\$\w+->(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)/.exec(body);
  const controller = handler ? handler[1] : '';
  const action = handler ? handler[2] : '';
  const args = handler ? handler[3].trim() : '';
  if (!controller) return null;

  const controllerFile = `src/Http/${controller}.php`;
  const bodies = methodBodies(php(controllerFile));
  const actionBody = bodies[action] ?? '';

  const guard = actionBody.includes('requireAdmin()')
    ? 'admin'
    : actionBody.includes('requireLogin()')
      ? 'login'
      : actionBody.includes('currentUser()')
        ? 'login-or-anon'
        : /redirect\(\s*'\/login'/.test(actionBody)
          ? 'login'
          : 'anon';

  const csrf = /(csrf\(\)|require_csrf\(\))/.test(actionBody + body) ? 'yes' : '-';
  const pathParams = segments.filter((s) => s === ':id' || s === ':param');
  const intArgs = [...args.matchAll(/int_param\(\$s,\s*(\d+)\)/g)].map((m) => `segment ${m[1]} as int`);
  const otherArgs = args.replace(/int_param\(\$s,\s*\d+\)/g, '').replace(/,\s*$/, '').trim();
  const params = [
    pathParams.length ? pathParams.join(', ') : null,
    intArgs.length ? intArgs.join('; ') : null,
    otherArgs ? `other args: ${otherArgs}` : null,
  ].filter(Boolean);
  const flags = [
    actionBody.includes('not_found()') || body.includes('not_found()') ? '404-on-missing' : null,
    actionBody.includes('forbidden(') ? '403' : null,
    /redirect\(/.test(actionBody) ? '303-redirect' : null,
  ].filter(Boolean);

  return {
    method,
    path: '/' + segments.join('/'),
    openEnded,
    guard,
    csrf,
    handler: `${controller}::${action}`,
    params: params.length ? params.join(' | ') : '-',
    flags: flags.length ? flags.join(', ') : '-',
  };
}

function buildRouteInventory() {
  const parsed = routeConditions(php('public/index.php'));
  if (process.env.PARITY_DEBUG) {
    console.error(`conditions parsed: ${parsed.length}`);
    for (const p of parsed.slice(0, 6)) {
      console.error(`  - ${p.condition.slice(0, 70)} => body ${JSON.stringify(p.body.trim().slice(0, 80))}`);
    }
  }
  const mapped = parsed.map((p) => ({ p, r: buildRouteRow(p) }));
  if (process.env.PARITY_DEBUG) {
    for (const { p, r } of mapped.slice(0, 12)) {
      console.error(`  row: ${r ? 'ok ' + r.path : 'NULL'} <= ${p.condition.slice(0, 70)}`);
    }
  }
  const entries = mapped.map((x) => x.r).filter(Boolean);
  // The front controller dispatches on first match; keep that order.
  const header = [
    '# Route inventory (generated)',
    '',
    'Generated by `tools/extract-parity.mjs` from the read-only PHP reference target.',
    'Do not edit by hand — regenerate with `node tools/extract-parity.mjs`.',
    '',
    `Source: \`public/index.php\` dispatch chain of the PHP target.`,
    'Handler column is the PHP handler; the Node handler name is the camelCase',
    'form of the same action in `src/http/<area>.controller.js` (see `docs/01-architecture.md`).',
    '',
    '| # | Method | Path pattern | Guard | CSRF | PHP handler | Params | Behaviour flags |',
    '|---|--------|--------------|-------|------|-------------|--------|-----------------|',
  ];
  const rows = entries.map(
    (r, i) =>
      `| ${i + 1} | ${r.method} | \`${r.path}${r.openEnded ? '' : ''}\` | ${r.guard} | ${r.csrf} | \`${r.handler}\` | ${esc(r.params)} | ${r.flags} |`,
  );
  const tail = [
    '',
    `Total routes: ${entries.length}.`,
    '',
    'Notes that the generator cannot infer (and that `docs/02-feature-parity.md` pins down):',
    '- Guard precedence in the PHP target is: CSRF check first, then login/admin guard,',
    '  then board-access check. A missing board or inaccessible board is `404`, never `403`.',
    '- `POST /vote` returns `303` back to `HTTP_REFERER` only when it starts with `APP_URL`.',
    '- `GET /admin` is a bare `303` to `/admin/boards` with no controller.',
    '- `GET /post/:id` renders the *thread* view with a direct-link flag.',
    '',
  ];
  return header.concat(rows, tail).join('\n');
}

// ---------------------------------------------------------------- schema ----

const NODE_SCHEMA_DELTA = `
## Node delta (intentional, see docs/07-port-deviations.md)

The Node port adds exactly one table to the PHP schema and changes no column of
an existing table:

| Table | Columns | Indexes | Why |
|---|---|---|---|
| \`sessions\` | \`id CHAR(64) PK\`, \`user_id INT UNSIGNED NULL\` (\`FK users ON DELETE CASCADE\`), \`data JSON NOT NULL\`, \`created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\`, \`expires_at TIMESTAMP NOT NULL\` | \`idx_sessions_user(user_id)\`, \`idx_sessions_expiry(expires_at)\` | Replaces PHP native file-backed sessions; gives \`session_management\`, \`sqli\` and \`idor\` branches a database substrate to attack. |

Everything else — table names, column names, column types, enum values, foreign
keys, checks, soft-delete columns — is copied verbatim from the PHP schema so
fixtures and SQL payloads are portable between the two targets.
`;

function buildSchemaInventory() {
  const sql = php('schema.sql');
  const tables = [];
  const re = /CREATE TABLE IF NOT EXISTS (\w+)\s*\(([\s\S]*?)\)\s*ENGINE=/g;
  let m;
  while ((m = re.exec(sql))) {
    const name = m[1];
    const bodySql = m[2];
    const columns = [];
    const constraints = [];
    for (const rawLine of bodySql.split(',\n')) {
      const line = rawLine.trim().replace(/,\s*$/, '');
      if (!line) continue;
      if (/^CONSTRAINT\b/i.test(line) || /^KEY\b/i.test(line) || /^PRIMARY KEY/i.test(line)) {
        constraints.push(line.replace(/\s+/g, ' '));
      } else {
        columns.push(line.replace(/\s+/g, ' '));
      }
    }
    tables.push({ name, columns, constraints });
  }
  const out = [
    '# Schema inventory (generated)',
    '',
    'Generated by `tools/extract-parity.mjs` from `schema.sql` of the PHP target.',
    'Do not edit by hand — regenerate with `node tools/extract-parity.mjs`.',
    '',
  ];
  for (const t of tables) {
    out.push(`## \`${t.name}\``, '');
    out.push('| Column definition |', '|---|');
    for (const c of t.columns) out.push(`| \`${esc(c)}\` |`);
    out.push('');
    if (t.constraints.length) {
      out.push('Keys and constraints:', '', '```sql');
      out.push(...t.constraints.map((c) => c + ','));
      out.push('```', '');
    }
  }
  out.push(NODE_SCHEMA_DELTA.trim());
  out.push('');
  return out.join('\n');
}

// ------------------------------------------------------------------ tests ----

const nodeTestPath = (rel) => {
  const withoutExt = rel.replace(/^tests\//, '').replace(/\.php$/, '');
  const [suite, file] = withoutExt.split('/');
  const base = file.replace(/Test$/, '');
  const snake = base.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
  return `test/${suite.toLowerCase()}/${snake}.test.mjs`;
};

function buildTestInventory() {
  const files = phpFiles('tests').filter((f) => f !== 'tests/bootstrap.php');
  const out = [
    '# Test inventory (generated)',
    '',
    'Generated by `tools/extract-parity.mjs` from `tests/` of the PHP target.',
    'Do not edit by hand — regenerate with `node tools/extract-parity.mjs`.',
    '',
    'Every PHP case below must have exactly one Node counterpart: same name, same',
    'assertion intent, same fixture. A Node test with no PHP row, or a PHP row with',
    'no Node test, fails the `verify:parity` gate (see docs/04-testing-and-verification.md).',
    '',
  ];
  let total = 0;
  for (const f of files) {
    const src = php(f);
    const cases = [...src.matchAll(/^\s*public function (test\w+)\(\)/gm)].map((m) => m[1]);
    if (!cases.length) continue;
    total += cases.length;
    out.push(`## ${f} → \`${nodeTestPath(f)}\``, '');
    out.push('| PHP case | Node case (Vitest) |', '|---|---|');
    for (const c of cases) out.push(`| \`${c}\` | \`${c}\` |`);
    out.push('');
  }
  out.push(`Total PHP cases: ${total}.`, '');
  return out.join('\n');
}

// ------------------------------------------------------------------- env ----

function buildEnvInventory() {
  const lines = phpLines('.env.example');
  const rows = [];
  let pendingComment = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') {
      pendingComment = [];
      continue;
    }
    if (trimmed.startsWith('#')) {
      pendingComment.push(trimmed.replace(/^#+\s*/, ''));
      continue;
    }
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    rows.push({ key, value, comment: pendingComment[0] ?? '' });
    pendingComment = [];
  }
  return [
    '# Environment inventory (generated)',
    '',
    'Generated by `tools/extract-parity.mjs` from `.env.example` of the PHP target.',
    'Do not edit by hand — regenerate with `node tools/extract-parity.mjs`.',
    '',
    'The Node `.env.example` carries every key below verbatim. The Node port adds',
    '`PORT` and nothing else; keys are read per request (dev parity) and real',
    'environment variables override file values.',
    '',
    '| Key | Default in PHP `.env.example` | Section / comment | Node notes |',
    '|-----|---------------------------------|-------------------|----------|',
    ...rows.map((r) => `| \`${r.key}\` | \`${esc(r.value)}\` | ${esc(r.comment)} | ${envNodeNote(r.key)} |`),
    '| `PORT` | `8088` | (Node only) | HTTP listen port; matches the PHP dev server port. |',
    '',
  ].join('\n');
}

function envNodeNote(key) {
  if (key === 'DB_PORT') return 'Node compose maps the host port to 3307 so the PHP target keeps 3306.';
  if (key === 'DB_NAME') return 'Node uses `theboard_node` / `theboard_node_test`.';
  if (key === 'SESSION_NAME') return 'Cookie name for the database-backed session store.';
  if (key === 'MAIL_DRIVER') return '`log` writes `var/log/mail.log`; `smtp` uses node:smtp directly.';
  return 'Read through `src/config/env.js`, same key, same default.';
}

// -------------------------------------------------------------- templates ----

function buildTemplateInventory() {
  const templateFiles = phpFiles('templates');
  const usedViews = new Map();
  for (const f of phpFiles('src/Http').concat(['public/index.php'])) {
    const src = php(f);
    for (const m of src.matchAll(/view\(\s*'([^']+)'/g)) {
      if (!usedViews.has(m[1])) usedViews.set(m[1], new Set());
      usedViews.get(m[1]).add(f);
    }
  }
  const nunjucksPath = (name) => `templates/${name}.njk`;
  const out = [
    '# Template inventory (generated)',
    '',
    'Generated by `tools/extract-parity.mjs` from `templates/` and the view calls in',
    '`src/Http/` of the PHP target. Do not edit by hand — regenerate with',
    '`node tools/extract-parity.mjs`.',
    '',
    'Every PHP template maps to exactly one Nunjucks template with autoescape on.',
    'The rendered HTML structure and class names are identical, so the same scanner',
    'rules and the same exploit probes apply to both targets.',
    '',
    '| PHP template | Node template | Rendered by (PHP handlers) |',
    '|---|---|---|',
  ];
  for (const f of templateFiles) {
    const viewName = f.replace(/^templates\//, '').replace(/\.php$/, '');
    const handlers = usedViews.get(viewName);
    if (!handlers) continue;
    out.push(`| \`${f}\` | \`${nunjucksPath(viewName)}\` | ${[...handlers].map((h) => `\`${h}\``).join(', ')} |`);
  }
  out.push('');
  out.push('## Partial and base templates (no direct `view()` call)', '');
  out.push('| PHP template | Node template |', '|---|---|');
  for (const f of templateFiles) {
    const viewName = f.replace(/^templates\//, '').replace(/\.php$/, '');
    if (usedViews.get(viewName)) continue;
    out.push(`| \`${f}\` | \`${nunjucksPath(viewName)}\` |`);
  }
  out.push('');
  out.push('## View names rendered by handlers that have no PHP template file', '');
  const orphan = [...usedViews.entries()].filter(([name]) => !templateFiles.includes(`templates/${name}.php`));
  if (orphan.length === 0) {
    out.push('None — every `view()` call resolves to a template file.', '');
  } else {
    for (const [name, handlers] of orphan) {
      out.push(`- \`${name}\` rendered by ${[...handlers].map((h) => `\`${h}\``).join(', ')}`);
    }
    out.push('');
  }
  return out.join('\n');
}

// ------------------------------------------------------------------ main ----

const TARGETS = [
  ['docs/parity/route-inventory.md', buildRouteInventory],
  ['docs/parity/schema-inventory.md', buildSchemaInventory],
  ['docs/parity/test-inventory.md', buildTestInventory],
  ['docs/parity/env-inventory.md', buildEnvInventory],
  ['docs/parity/template-inventory.md', buildTemplateInventory],
];

let drift = 0;
for (const [rel, build] of TARGETS) {
  const content = build();
  const abs = join(REPO_ROOT, rel);
  if (CHECK) {
    if (!existsSync(abs)) {
      console.error(`MISSING  ${rel}`);
      drift++;
      continue;
    }
    if (readFileSync(abs, 'utf8').replace(/\r\n/g, '\n') !== content) {
      console.error(`DRIFT    ${rel} — regenerate with: node tools/extract-parity.mjs`);
      drift++;
      continue;
    }
    console.log(`ok       ${rel}`);
    continue;
  }
  writeFileSync(abs, content);
  console.log(`wrote    ${rel} (${content.split('\n').length} lines)`);
}

if (CHECK && drift > 0) {
  console.error(`${drift} inventory file(s) out of date against the PHP reference target at ${PHP_REPO}`);
  process.exit(1);
}
if (!CHECK) {
  console.log(`\nSource of truth: ${PHP_REPO}`);
}
