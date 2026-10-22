# 01 — Architecture

Frameworkless Node ≥ 22, plain ESM, no build step. The shape deliberately mirrors
the PHP target: one entry file that loads config, applies headers, starts the
session and dispatches by hand-written route matching.

## 1. Request lifecycle

```
node src/server.js
  -> src/config/env.js          reload .env per request (dev parity); real env wins
  -> src/http/server.js         createServer(handler)
       -> src/http/headers.js   security headers on every response (C-HDR-1/-2)
       -> src/session/store.js  read cookie, load session row, ban kill (C-SESS-*)
       -> src/http/request.js   method, path, segments, query, body (urlencoded|multipart), cookies
       -> src/http/router.js    ordered match, mirrors the PHP if/elseif order
       -> src/http/*.controller.js
            -> src/security/*   csrf, guard, validator, markup, throttle, mfa, jwt
            -> src/repositories/*  prepared statements only (C-SQL-*)
            -> src/hooks/*      upload, preview, xml, directory, xpath, snapshot, export
       -> src/views.js          Nunjucks render, autoescape on
       -> error path            404 / 403 / 500 views; stack trace only when APP_DEBUG=1
```

Route matching is ordered, not a trie: the PHP front controller matches the
first true condition, and two Node routes must not disagree with that order
(`/post/:id` before `/post/:id/edit` would change behaviour). The router takes
the ordered table from `src/routes.js`, whose order is generated from
`docs/parity/route-inventory.md` row order.

## 2. Directory layout

```
src/
  server.js                     entry; equivalent of public/index.php
  routes.js                     ordered route table (guards + handlers)
  config/env.js                 .env loader: get/int/bool/list
  config/defaults.js            the shipped fallback values (single source)
  db/connection.js              mysql2/promise pool; prepared statements only
  http/
    server.js                   node:http server + request pipeline
    router.js                   ordered matcher, segment capture
    request.js                  query/body/cookie parsing, multipart parser
    response.js                 render/redirect/flash helpers, status helpers
    headers.js                  security header set
    controller.js               shared guard helpers (requireLogin/requireAdmin)
    page.controller.js  auth.controller.js  profile.controller.js
    board.controller.js thread.controller.js post.controller.js vote.controller.js
    admin.controller.js         one file per PHP controller
  security/
    csrf.js  passwords.js  login-throttle.js  mfa.js  markup.js  validator.js
    jwt.js                      baseline JWT rules (C-JWT-1)
    headers-policy.js           CSP string + header list (single source)
  session/store.js              sessions table: create/read/touch/destroy/regenerate
  repositories/
    user.repository.js  board.repository.js  post.repository.js  vote.repository.js
  auth/login.js                 attemptLogin state machine
  mail/mailer.js                log driver (var/log/mail.log) + node:smtp driver
  views.js                      Nunjucks environment, globals, filters
  lib/clock.js                  now()/sleep(); setClockForTests() — the only time source
  xml/
    reader.js                   in-house XML reader used by the import hook
    document.js                 node-like tree the reader builds
  hooks/
    upload.js     preview.js     xml-import.js  xml-export.js
    directory.js  xpath.js       snapshot.js      export.js
templates/                     Nunjucks, mirrors templates/ 1:1
public/assets/style.css  app.js
scripts/                       reset.mjs seed-admins.mjs seed-test-data.mjs
                               verify-parity-tests.mjs
test/unit/  test/integration/  test/security/  test/vulns/  test/helpers/
tools/  var/log/  var/uploads/  schema.sql  docker-compose.yml  .env.example
```

## 3. PHP → Node module map

| PHP (`src/`) | Node (`src/`) | Notes |
|---|---|---|
| `public/index.php` | `src/server.js` + `src/routes.js` | same dispatch order, same 404/403 helpers |
| `Env.php` | `config/env.js` | same keys, same defaults, env-overrides-file |
| `Database.php` | `db/connection.js` | `ATTR_EMULATE_PREPARES=false` → `multipleStatements:false`, named placeholders become `?` |
| `Auth.php` | `auth/login.js` + `session/store.js` | PHP native sessions → `sessions` table (docs/07) |
| `Mfa.php` | `security/mfa.js` | same TTL/attempts/hashing rules |
| `LoginThrottle.php` | `security/login-throttle.js` | kill switch + 4 guards ported verbatim |
| `Csrf.php` | `security/csrf.js` | per-session token, `timingSafeEqual`, rotate on login |
| `Flash.php` | `http/response.js` flash part | stored in session row |
| `Mailer.php` | `mail/mailer.js` | `MAIL_DRIVER=log` writes the same file format |
| `Markup.php` | `security/markup.js` | escape-first, ≤25 passes, http(s)+host URL allowlist |
| `Validator.php` | `security/validator.js` | same messages, same limits (see docs/02 §5) |
| `UserRepository.php` | `repositories/user.repository.js` | |
| `BoardRepository.php` | `repositories/board.repository.js` | `userCanAccess` is the ACL choke point |
| `PostRepository.php` | `repositories/post.repository.js` | `THREADS_PER_PAGE = 20` |
| `VoteRepository.php` | `repositories/vote.repository.js` | toggle/switch semantics |
| `Http/Controller.php` | `http/controller.js` | `view()`, `csrf()`, `requireLogin()`, `requireAdmin()` |
| `Http/*.php` (9) | `http/*.controller.js` (9) | one-to-one |
| `views.php` (`e`, `view`, `url`, `redirect`) | `views.js`, `http/response.js` | autoescape replaces manual `e()` |
| `templates/**` | `templates/**.njk` | generated mapping in docs/parity/template-inventory.md |
| `bin/{reset,seed-admins,seed-test-data}.php` | `scripts/{reset,seed-admins,seed-test-data}.mjs` | same flags |
| `schema.sql` | `schema.sql` | + `sessions` table |

## 4. Hook modules (new in Node, absent from PHP)

Each hook is a module in `src/hooks/` with a controller surface registered in
`src/routes.js`. Their security contract is the row in `docs/02-feature-parity.md`
§7; the control they implement is named there.

| Module | PHP counterpart | Why it exists |
|---|---|---|
| `hooks/upload.js` | none | home for `file_upload`, `path_traversal`, `security_misconfig` |
| `hooks/preview.js` | none | home for `ssrf` |
| `hooks/xml-import.js`, `hooks/xml-export.js`, `src/xml/reader.js` | none | home for `xxe`, `ssti`, `insecure_deserialization` |
| `hooks/directory.js` | none | home for `ldap_injection`, `nosql_injection`, `idor` |
| `hooks/xpath.js` | none | home for `xpath_injection` |
| `hooks/snapshot.js` | none | home for `insecure_deserialization`, `race_condition` |
| `hooks/export.js` | none | home for `command_injection` |
| `security/jwt.js` | none | home for `jwt_flaws`, `open_redirect`, `host_header_injection`, `cryptographic_failures` |
| `session/store.js` | PHP native sessions | home for `session_management`, `sqli`, `idor` |

`src/xml/reader.js` is in-house on purpose: the catalog must be able to turn
entity resolution on in a single commit, and a native `libxml` binding would add
a compile step that the "swap branch and relaunch" workflow cannot afford.

## 5. Shared seams and their contracts

Public function signatures are fixed here so agents writing different modules
agree:

```js
// src/config/env.js
export function load(path): void
export function get(key, fallback = null): string | null
export function int(key, fallback): number
export function bool(key, fallback): boolean
export function list(key): string[]

// src/db/connection.js
export function query(sql, params = []): Promise<Row[]>  // conn.query (client-side binding), placeholders only, never interpolated
export function execute(sql, params = []): Promise<{insertId, affectedRows}>
export function transaction(fn): Promise<T>                       // BEGIN/COMMIT/ROLLBACK
export function forUpdate(sql, params): Promise<Row>              // SELECT ... FOR UPDATE

// src/session/store.js
export async function start(req, res): Session                    // cookie -> row, ban kill
export async function regenerate(session, res): Session           // new id, CSRF rotate
export async function save(session, res): void
export async function destroy(session, res): void

// src/security/markup.js
export function render(raw): string        // escaped-first HTML
export function isSafeUrl(url): boolean
export function plain(raw): string

// src/repositories/board.repository.js
export async function userCanAccess(user, board): boolean         // the single ACL choke point

// src/auth/login.js
export async function attemptLogin(email, password, ip): Promise<
  {status:'ok'|'mfa'|'banned'|'throttled'|'invalid', user?, message?, waitSeconds?}>

// src/views.js
export function render(res, template, vars): void                 // autoescape on, no |safe on user data
export function notFound(res): void
export function forbidden(res, message?): void

// src/lib/faults.js
export function setTestFault(fnOrNull): void   // the pipeline rethrows fn() on the
//   next request. Deterministic way to exercise the 500 path without inventing a
//   buggy handler. Test-only: controls.test.mjs#c-info-1 asserts no fault is armed
//   during a normal run, and the setter is never called from src/ outside tests.

// src/lib/clock.js
export function now(): Date
export function nowMs(): number
export function setClockForTests(fnOrNull): void

// src/http/request.js
export async function parse(req): Promise<
  { method, path, segments, query, cookies, fields, files }>
//   every file part is exactly { field, filename, mimeType, size, buffer };
//   filename has any path separators stripped, size === buffer.length.
//   MAX_POST_BYTES caps the whole body (413 'Request body too large');
//   MAX_UPLOAD_BYTES caps one file part (400 'File is too large') and is
//   enforced here, before any handler runs. Type checks stay handler-side.

// src/http/response.js
export function redirect(res, location): void                   // always 303
export function status(res, code, template, vars): void         // 400/403/404/409/413/500
```

## 6. Rendering

- Nunjucks with `autoescape: true`. The `|safe` filter may only be applied to
  output of `security/markup.js` (that is what the XSS family tests assert).
- Layout: `templates/partials/header.njk` + `footer.njk`, included by every page
  template exactly as the PHP partials are.
- CSP (`docs/03` `C-XSS-3`) forbids inline script, so all client JS lives in
  `public/assets/app.js`. That file is tiny by design (vote button debounce,
  confirm dialogs) and is the sink the `xss_dom` branch downgrades.
- The only served static paths are `/assets/*` (`public/assets`) and, through
  controllers, `/avatar/:id` and `/attachment?file=`. There is no
  static-directory handler and no directory listing anywhere (`C-INFO-2`).

## 7. Dependencies (fixed list)

Runtime: `mysql2`, `nunjucks`, `bcryptjs`, `jsonwebtoken`, `@xmldom/xmldom`,
`xpath`.

Dev: `vitest`, `supertest`, `@vitest/coverage-v8` is not used.

No web framework, no ORM, no session middleware, no body-parser, no cookie
library, no `express`, no `fastify`, no `libxmljs2`, no TypeScript, no bundler.
Anything not on this list needs a spec commit first (`AGENTS.md` §5).

## 8. Configuration and processes

- One process: `node src/server.js` on `PORT` (8088). MariaDB in Docker on host
  port 3307 (`theboard-node-db`).
- No build, no watch-mode requirement; `npm run dev` is `node --watch`.
- Logs: `var/log/app.log` (app), `var/log/mail.log` (mail driver).
- `.env` is re-read on every request, matching the PHP dev behaviour, and real
  environment variables override file values. `PORT`, `DB_*` are the container
  overrides used by the worktree harness.
