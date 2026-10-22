# sqli — SQL injection in the user search

- Branch: `vuln/sqli`
- Catalog row: 25
- Effort: M
- Hook: staff directory (also hits the core admin user list)
- Test file: `test/vulns/sqli.test.mjs`

## Class and CWE

SQL injection — CWE-89 (with stacked queries enabled, CWE-89 variant). Family: injection.

## Intent

Prove that a request parameter reaches SQL as text, and that the connection
permutes into more than one statement, so a scanner can demonstrate boolean,
error-based, union and stacked effects through one parameter.

## Affected surface

- Route: `GET /admin/users?q=` (primary) and `GET /directory?q=` (secondary)
- Parameter: `q` (query string)
- Prerequisites: `admin` scan profile for `/admin/users`; `regular` for `/directory`
- Reachability: the search box on the admin users page; the directory page form

## Sink

`src/repositories/user.repository.js` — `allUsers(search)`. The branch replaces
the placeholder list in the `WHERE u.username LIKE ? OR u.email LIKE ?` clause
with a template string containing the raw search term, and `src/hooks/directory.js`
builds its predicate the same way. The pool no longer sets
`multipleStatements: false`, so `;`-separated statements execute.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SQL-1` | Prepared statements only, no interpolation | the `LIKE ?` placeholders are replaced by `LIKE '%${search}%'` |
| `C-SQL-2` | Driver hardening with `multipleStatements: false` | the pool option is flipped to `true` |

## Minimal diff

Files touched:

- `src/repositories/user.repository.js` — in `allUsers`, build the `WHERE` clause
  with a template literal around `search`, keep the escaping helper unused, and
  call `query(sql)` with no parameter array.
- `src/hooks/directory.js` — in `predicateFor`, interpolate the raw `q` value into
  the SQL fragment used for the directory listing.
- `src/db/connection.js` — `multipleStatements: true` in the pool config.
- `test/vulns/sqli.test.mjs` — new file.

No other file changes. The `q` value stays unvalidated on the controller path so
the payload survives intact.

## Payload sketch

```
GET /admin/users?q=%25%27%20UNION%20SELECT%201,username,password_hash,4,5,6,7,8,9,10,11--%20-
GET /admin/users?q=' AND SLEEP(3) AND '1'='1
GET /admin/users?q='; INSERT INTO boards (name, description, default_access) VALUES ('pwned','sqli',1)-- -
```

Expected effect: the union row appears in the rendered user table with the admin's
`password_hash`; the stacked insert creates a board visible in
`GET /admin/boards`.

## Differential oracle

`test/vulns/sqli.test.mjs`:

1. Sign in with the `admin` profile (`owner_olivia`), then read the seeded
   `owner_olivia` password hash from the database through the test helper.
2. Send `GET /admin/users?q=' UNION SELECT 1,username,password_hash,4,5,6,7,8,9,10,11-- -`
   and assert the response body contains that literal hash string.
3. Send the stacked payload that inserts a board named `pwned-sqli`, then
   `GET /admin/boards` and assert the board is listed.
4. Send `q=' AND SLEEP(2) AND '1'='1` and assert the elapsed time is at least
   1500 ms (boolean/time-based confirmation; skipped only if the server reports
   `SKIP` in the response, which it never does).

On `main` this test must fail because both queries run as prepared statements: the
`UNION` payload is a literal search string that matches no row, the stacked
statement is rejected by the driver, and `SLEEP` never runs.

## Must-not-break invariants

- `test/integration/user-repository.test.mjs#testAllUsersSearch` (the plain search and
  the `%`/`_` escaping case) must still pass: escaping no longer *protects*
  anything, but the search results for ordinary queries must be unchanged.
- Login, MFA, CSRF, board access and vote tests all stay green.
- `test/security/baseline-inert.test.mjs` still passes.
- `test/security/controls.test.mjs` skips exactly `C-SQL-1` and `C-SQL-2`.

## Fidelity to the PHP branch

Same branch name, same class, same surface as the PHP target's `vuln/sqli`
branch: an admin search box whose term reaches SQL. The PHP branch does it with
string interpolation into PDO SQL; the Node branch reproduces the four oracle
shapes (boolean, error, union, stacked) with `mysql2`, where the stacked variant
requires the pool's `multipleStatements` option to be turned on — the Node
equivalent of dropping prepared-statement discipline, recorded in `docs/07` §10.

## Carmentis evidence

The finding must capture the `q` parameter, the injected payload, and the echoed
`password_hash` substring in the response body. Expected label: `CWE-89 / SQL
Injection (union + stacked)`. False-negative watch-out: the payload must be
URL-encoded so the leading `'` survives the query-string parser, and the union
column count (11) has to match the `allUsers` select list — a scanner that probes
with a 1-column union will see an error and may classify it as noise.

## Definition of done

- [ ] `test/vulns/sqli.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green (baseline suite + exploit test).
- [ ] Branch is exactly one commit off `main`; diff touches only the four listed files.
- [ ] Commit message: `vuln: sqli — interpolate the user-search term into SQL and allow stacked statements`.
