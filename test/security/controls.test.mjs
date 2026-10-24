// The control register as a test file (docs/03). Each case is named after the
// control it proves, so a vulnerability branch that declares a control skips
// exactly that case — see docs/04 section 9.
//
// Half of these are source scans. They are not style checks: on a branch whose
// diff re-introduces an interpolated WHERE fragment or a `|safe` on raw input,
// the scan is the assertion that fails while the behavioural suites still pass.

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll } from '../helpers/db.mjs';
import { agent, csrfToken, loginAs } from '../helpers/http.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import { root } from '../../src/db/admin.js';
import { routes } from '../../src/routes.js';
import { GUARDS } from '../../src/http/router.js';
import * as boards from '../../src/repositories/board.repository.js';
import * as users from '../../src/repositories/user.repository.js';
import { list as directoryList } from '../../src/hooks/directory.js';

const CSP_PINNED =
  "default-src 'self'; img-src * data:; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";

const BASELINE_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'same-origin',
  'x-permitted-cross-domain-policies': 'none',
  'cross-origin-opener-policy': 'same-origin',
};

function sourceFiles(dir) {
  const absolute = join(root(), dir);
  if (!existsSync(absolute)) return [];
  const found = [];
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    const path = join(absolute, entry.name);
    if (entry.isDirectory()) found.push(...sourceFiles(path));
    else if (entry.name.endsWith('.js')) found.push(path);
  }
  return found;
}

function relative(path) {
  return path.slice(root().length + 1).replaceAll('\\', '/');
}

/** Strip comments so a commented-out payload does not fail a scan. */
function code(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

// Uppercase SQL only: the codebase writes SQL in upper case, and a
// case-insensitive scan would flag `.join(` and the word "from" in prose.
const SQL_KEYWORDS = /\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|WHERE|ORDER BY|GROUP BY|JOIN|LIMIT|LIKE)\b/;

/** `${...}` inside a SQL-looking template literal. */
function interpolatedSql(path) {
  const hits = [];
  for (const literal of code(readFileSync(path, 'utf8')).matchAll(/`(?:[^`\\]|\\.)*`/g)) {
    const text = literal[0];
    if (SQL_KEYWORDS.test(text) && text.includes('${')) hits.push(text.slice(0, 60));
  }
  return hits;
}

/** A `+` that joins a SQL-looking string literal to something that is not a literal. */
function concatenatedSql(path) {
  const hits = [];
  const source = code(readFileSync(path, 'utf8'));
  const operandIsLiteral = (text, index) => {
    const trimmed = text.trim();
    return trimmed.startsWith("'") || trimmed.startsWith('"') || trimmed.startsWith('`');
  };

  for (const line of source.split('\n')) {
    for (const match of line.matchAll(/(['"`])((?:[^'"`\\]|\\.)*?)\1\s*\+\s*([^;]+)/g)) {
      if (!SQL_KEYWORDS.test(match[2])) continue;
      if (!operandIsLiteral(match[3], match.index)) hits.push(`${relative(path)}: ${match[0].slice(0, 70)}`);
    }
    for (const match of line.matchAll(/([^;=]+?)\s*\+\s*(['"`])((?:[^'"`\\]|\\.)*?)\2/g)) {
      if (!SQL_KEYWORDS.test(match[3])) continue;
      if (!operandIsLiteral(match[1], match.index)) hits.push(`${relative(path)}: ${match[0].slice(0, 70)}`);
    }
  }
  return hits;
}

beforeEach(async () => {
  await truncateAll();
});

describe('SQL and data layer', () => {
  it('c-sql-1 no sql fragment is built by concatenation or interpolation', () => {
    const scanned = ['src/repositories', 'src/session', 'src/hooks'];
    const offenders = [];

    for (const dir of scanned) {
      for (const file of sourceFiles(dir)) {
        offenders.push(...interpolatedSql(file).map((snippet) => `${relative(file)}: \${} in ${snippet}`));
        offenders.push(...concatenatedSql(file));
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('c-sql-1 the seeded injection payloads change no result set', async () => {
    await makeUser('sql-rita', 'sql-rita@test.example', 'Passw0rdLong1');
    const open = await makeBoard('Open Board', true);

    for (const payload of ["' OR 1=1-- -", "%' OR 1=1-- -", "'; DROP TABLE users; -- -", "1' UNION SELECT 1,2,3-- -"]) {
      expect(await users.allUsers(payload), payload).toEqual([]);
      expect(await directoryList(payload), payload).toEqual([]);
    }

    // Nothing was lost or widened while trying.
    expect((await users.allUsers('sql-rita')).map((u) => u.username)).toEqual(['sql-rita']);
    expect((await boards.listForUser({ id: 1, role: 'user' })).map((b) => b.id)).toContain(Number(open.id));
  });
});

describe('Output encoding and templates', () => {
  it('c-xss-2 templates autoescape and |safe only ever wraps the markup renderer', () => {
    const templates = readdirSync(join(root(), 'templates'), { recursive: true })
      .filter((name) => String(name).endsWith('.njk'))
      .map((name) => join(root(), 'templates', String(name)));

    const offenders = [];
    for (const file of templates) {
      for (const match of readFileSync(file, 'utf8').matchAll(/\{\{[^}]*\|\s*safe[^}]*\}\}/g)) {
        // The only sanctioned |safe is the renderer's output.
        if (!/(render|markup|post_html|body_html|thread_html)\w*(\([^)]*\))?\s*\|\s*safe/.test(match[0])) {
          offenders.push(`${relative(file)}: ${match[0]}`);
        }
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);

    const views = readFileSync(join(root(), 'src', 'views.js'), 'utf8');
    expect(views).toMatch(/autoescape:\s*true/);
  });

  it('c-xss-3 the pinned CSP is on every response shape', async () => {
    const owner = await makeUser('csp-owner', 'csp-owner@test.example', 'Passw0rdLong1', 'admin');
    const boardId = Number((await makeBoard('CSP Board', true, Number(owner.id))).id);
    const threadId = Number(await makeThread(boardId, Number(owner.id), 'CSP thread', 'body'));

    const anon = await agent();
    const login = await anon.get('/login');
    expect(login.headers['content-security-policy']).toBe(CSP_PINNED);

    const member = await agent();
    await loginAs(member, 'csp-owner@test.example', 'Passw0rdLong1');
    const home = await member.get('/');
    expect(home.headers['content-security-policy']).toBe(CSP_PINNED);

    const thread = await member.get(`/thread/${threadId}`);
    expect(thread.headers['content-security-policy']).toBe(CSP_PINNED);

    // No inline script or inline handler anywhere in the rendered page.
    expect(thread.text).not.toMatch(/<script>(?!\s*<\/script>)/);
    expect(thread.text).not.toMatch(/\son[a-z]+\s*=/i);
    expect(thread.text).not.toMatch(/href="javascript:/i);
  });

  it('c-ssti-1 no template compilation, eval, Function or vm runs on request data', () => {
    const banned = [/nunjucks\.compile\s*\(/, /eval\s*\(/, /new\s+Function\s*\(/, /vm\.(runIn|compileFunction)/, /new\s+template\.Template/];
    const offenders = [];

    for (const file of sourceFiles('src')) {
      const source = code(readFileSync(file, 'utf8'));
      for (const pattern of banned) {
        if (pattern.test(source)) offenders.push(`${relative(file)}: ${pattern}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);

    // A template is only ever reached through the fixed-name lookup, and the
    // render call passes that path plus a variable map — never request text.
    const views = readFileSync(join(root(), 'src', 'views.js'), 'utf8');
    expect(views).toMatch(/function templatePath\s*\(/);
    expect(views).toMatch(/env\.render\(path, vars\)/);
  });
});

describe('Authorization and bodies', () => {
  it('c-acl-2 every route declares a guard and every admin route is admin-guarded', () => {
    const missing = routes.filter((entry) => !GUARDS.has(entry.guard));
    expect(missing, JSON.stringify(missing)).toEqual([]);

    // Every /admin route is admin-guarded, with one exception the route table
    // states out loud: the bare `GET /admin`, which is a 303 to /admin/boards in
    // the PHP target and never renders anything.
    const adminRoutes = routes.filter((entry) => String(entry.path).startsWith('/admin'));
    expect(adminRoutes.length).toBeGreaterThan(10);
    const wrong = adminRoutes.filter((entry) => entry.guard !== 'admin' && entry.path !== '/admin');
    expect(wrong.map((e) => `${e.method} ${e.path} -> ${e.guard}`)).toEqual([]);

    // And each admin handler checks the role itself — no inherited trust.
    const source = code(readFileSync(join(root(), 'src', 'http', 'admin.controller.js'), 'utf8'));
    const names = [...source.matchAll(/export async function (\w+)\s*\(/g)].map((m) => m[1]);
    expect(names.length).toBeGreaterThan(8);

    const unchecked = names.filter((name) => {
      const from = source.indexOf(`export async function ${name}`);
      // A handler body ends at the first line-initial `}`; scanning to the next
      // `}` would stop inside a nested object literal.
      const body = source.slice(from, source.indexOf(String.fromCharCode(10) + '}', from));
      return !body.includes('requireAdmin(');
    });
    expect(unchecked, unchecked.join(', ')).toEqual([]);
  });

  it('c-assign-1 request data is never Object.assign-ed onto a model or session', () => {
    const pattern = /Object\.assign\s*\(\s*(ctx\.session|session|ctx\.user|user|ctx\.req\.fields|ctx\.req\.query)/g;
    const offenders = [];

    for (const file of sourceFiles('src')) {
      const source = code(readFileSync(file, 'utf8'));
      for (const match of source.matchAll(pattern)) offenders.push(`${relative(file)}: ${match[0]}`);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});

describe('Headers and commands', () => {
  it('c-hdr-1 the baseline header set is on a 200, a 404 and a 403', async () => {
    const owner = await makeUser('hdr-owner', 'hdr-owner@test.example', 'Passw0rdLong1', 'admin');
    await makeUser('hdr-pleb', 'hdr-pleb@test.example', 'Passw0rdLong1');
    await makeBoard('Hdr Board', false, Number(owner.id));

    const member = await agent();
    await loginAs(member, 'hdr-owner@test.example', 'Passw0rdLong1');
    const outsider = await agent();
    await loginAs(outsider, 'hdr-pleb@test.example', 'Passw0rdLong1');

    const ok = await member.get('/');
    const forbidden = await outsider.get('/admin/users');
    const missing = await member.get('/no-such-page');

    expect(ok.status).toBe(200);
    expect(forbidden.status).toBe(403);
    expect(missing.status).toBe(404);

    for (const res of [ok, forbidden, missing]) {
      for (const [name, value] of Object.entries(BASELINE_HEADERS)) {
        expect(res.headers[name], `${name} on ${res.statusCode}`).toBe(value);
      }
      expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    }
  });

  it('c-cmd-1 the export path runs no shell, no exec and no string command', () => {
    const banned = [/shell\s*:\s*true/, /\bexec\s*\(/, /\bexecSync\s*\(/, /\bspawn\s*\(/, /child_process/];
    const offenders = [];

    for (const file of sourceFiles('src')) {
      const source = code(readFileSync(file, 'utf8'));
      for (const pattern of banned) {
        if (pattern.test(source)) offenders.push(`${relative(file)}: ${pattern}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('c-crypto-1 no Math.random, md5 or sha1 in the security-relevant sources', () => {
    const banned = [/Math\.random\s*\(/, /createHash\s*\(\s*['"]md5['"]\s*\)/, /createHash\s*\(\s*['"]sha1['"]\s*\)/, /jsonwebtoken[^;]*algorithm[^;]*none/];
    const scanned = ['src/security', 'src/session', 'src/auth', 'src/hooks', 'src/repositories', 'src/http', 'src/xml'];
    const offenders = [];

    for (const dir of scanned) {
      for (const file of sourceFiles(dir)) {
        const source = code(readFileSync(file, 'utf8'));
        for (const pattern of banned) {
          if (pattern.test(source)) offenders.push(`${relative(file)}: ${pattern}`);
        }
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});

describe('Configuration and disclosure', () => {
  it('c-data-1 no secret is hardcoded in the shipped sources', () => {
    const banned = [/DB_ROOT_PASS\s*[:=]\s*['"][^'"#]+['"]/, /JWT_SECRET\s*[:=]\s*['"][^'"]{8,}['"]/, /ADMIN_PASSWORD\s*[:=]\s*['"][^'"]{4,}['"]/, /password\s*[:=]\s*['"](Passw0rd|TestPass|CorrectHorse)[^'"]*['"]/];
    const offenders = [];

    for (const file of sourceFiles('src')) {
      const source = readFileSync(file, 'utf8');
      for (const pattern of banned) {
        if (pattern.test(source)) offenders.push(`${relative(file)}: ${pattern}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);

    // The ignore list keeps the real secrets out of the repository.
    const gitignore = readFileSync(join(root(), '.gitignore'), 'utf8');
    for (const entry of ['.env', 'var/', 'node_modules/']) expect(gitignore, entry).toContain(entry);

    // The defaults file carries no fallback signing key.
    const defaults = readFileSync(join(root(), 'src', 'config', 'defaults.js'), 'utf8');
    expect(defaults).not.toMatch(/JWT_SECRET/);
  });

  it('c-data-1 /health answers with a fixed body and nothing else', async () => {
    const res = await (await agent()).get('/health');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(JSON.parse(res.text)).toEqual({ ok: true });
    expect(res.text).not.toMatch(/DB_|PASS|SECRET|KEY/i);
  });

  it('c-csrf-1 every state-changing route rejects a tokenless request', async () => {
    const stateChanging = routes.filter((entry) => entry.method === 'POST');
    expect(stateChanging.length).toBeGreaterThan(10);

    const owner = await makeUser('csrf-owner', 'csrf-owner@test.example', 'Passw0rdLong1', 'admin');
    const http = await agent();
    await loginAs(http, 'csrf-owner@test.example', 'Passw0rdLong1');
    const probePage = await csrfToken(http, '/profile');
    expect(probePage).toMatch(/^[0-9a-f]{64}$/);

    const rejected = [];
    for (const entry of stateChanging) {
      const path = entry.path.includes(':id') ? entry.path.replace(':id', '1') : entry.path;
      const res = await http.post(path).type('form').send({});
      if (res.status !== 400) rejected.push(`${entry.method} ${path} -> ${res.status}`);
    }
    expect(rejected, rejected.join('\n')).toEqual([]);
  });
});
