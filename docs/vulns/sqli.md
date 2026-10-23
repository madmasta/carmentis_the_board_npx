# sqli — the staff search and directory filters stop using bound parameters

- Branch: `vuln/sqli`
- Catalog row: 25
- Effort: M
- Hook: core app (repository layer) + staff directory
- Test file: `test/vulns/sqli.test.mjs`

## Class and CWE

SQL injection — CWE-89. Family: injection.

## Intent

Prove that user input reaches SQL text, so an attacker can read columns the
application never intends to show and can run statements the application never
intends to run.

## Affected surface

- Route: `GET /admin/users?q=` (primary), `GET /directory?q=` (secondary hook sink)
- Parameter: `q` (query string)
- Prerequisites: `admin` profile for the primary surface, `regular` for the
  directory
- Reachability: the admin users page has a search box rendered in the page itself;
  the directory search form is reachable from the nav for any signed-in user

## Sink

`src/repositories/user.repository.js#allUsers(search)` mirrors PHP's
`UserRepository::search()`, which builds:

```sql
SELECT u.*, (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id
             AND p.deleted_at IS NULL) AS post_count
FROM users u
[WHERE u.username LIKE ? OR u.email LIKE ?]
ORDER BY u.created_at DESC LIMIT 500
```

That projection has **11 columns** in this fixed order: `id`, `username`, `email`,
`password_hash`, `role`, `is_banned`, `ban_reason`, `mfa_enabled`, `created_at`,
`updated_at`, `post_count`. The rendered table shows `username` (`VARCHAR(50)`)
and `email` (`VARCHAR(255)`) — a bcrypt hash is 60 characters, so extracted hashes
go in the **email** slot, not the username slot.

The branch concatenates the search term into the SQL text and passes no parameter
array. That forces the `LIKE` metacharacter escape to go as well: `main` builds
`'%' + escapeLike(search) + '%'` and binds it, and an interpolated version of the
same expression is what the branch writes, without the escape. The payloads below
depend on that — `password_hash`, `mod_marcus` and `default_access` all contain `_`,
which the escape would turn into `\_` and break as an identifier — so the escape is
dropped deliberately and declared as `C-SQL-3`, not lost silently in a parity test.
`src/db/connection.js` sets `multipleStatements: true` **explicitly** —
`mysql2` already defaults the flag to `false`, so an option that is merely absent
would change nothing and `C-SQL-2` would be declared but still enforced. The
interpolation must be written so the `C-SQL-1` scan sees it: the fragment is built
inside the repository module with `+` or `${`, which is what that control's source
scan looks for anywhere under `src/repositories/`.

`src/hooks/directory.js#buildFilter` also interpolates the `q` token into the
`where` fragment instead of binding it, making the directory a second instance of
the same class. That projection has **5 columns**: `id`, `username`, `role`,
`created_at`, `post_count` (`docs/02` §7).

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SQL-1` | Every statement goes through `connection.query(sql, params)` with `?` placeholders; user data never concatenates into SQL text | the `WHERE` fragment is built by string interpolation and the params array is dropped |
| `C-SQL-2` | The pool is created with `multipleStatements: false` written explicitly | the option is set to `true`, so a statement separator executes |
| `C-SQL-3` | Search terms are `LIKE`-escaped (`%`, `_`) and then bound | the interpolated fragment skips the escape, which is what lets `_`-bearing identifiers survive in the payload |

Side effect the diff must declare, not hide: interpolating `q` in
`hooks/directory.js#buildFilter` also breaks the directory token binding that
`C-DIR-1` proves, so `C-DIR-1` is listed too.

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DIR-1` | Directory filter tokens are parsed into `{field, op, value}` and the value is bound as a parameter | `buildFilter` concatenates the raw token into the `where` fragment |

Only the cases carrying the slugs `c-sql-1`, `c-sql-2`, `c-sql-3` and `c-dir-1` are
skipped (`docs/03` skip granularity): the `c-dir-2` cases in
`test/unit/hook-directory.test.mjs` — non-primitive filter values rejected — still
run and must stay green, and so do the other repository cases in
`test/unit/repository-users.test.mjs`; only `c-sql-3` (the PHP parity case
`testAllUsersSearch`) is skipped, which is the honest expression of "this branch also
removed `LIKE` escaping".

## Minimal diff

Files touched:

- `src/db/connection.js` — change the pool option to `multipleStatements: true`.
- `src/repositories/user.repository.js` — `allUsers(search)` builds the `WHERE`
  fragment with template interpolation from the **unescaped** term and calls
  `query(sql)` with no params, removing the `escapeLike()` call.
- `src/hooks/directory.js` — `buildFilter` interpolates the `q` token.
- `test/vulns/sqli.test.mjs` — new file.

## Payload sketch

Read a credential the app never renders, into the rendered `email` slot. The
payload must supply all **11** projection columns, so `post_count` is repeated:

```
GET /admin/users?q=' UNION SELECT id, username, password_hash, role, is_banned,
    ban_reason, mfa_enabled, created_at, updated_at, post_count, post_count
    FROM users WHERE username='mod_marcus'-- -
```

Run a statement the app never runs:

```
GET /admin/users?q='; INSERT INTO boards (name, description, default_access)
    VALUES ('pwned-sqli', 'stacked statement proof', 1)-- -
```

Boolean probe (no timing, deterministic). The probe has to open the `LIKE`
wildcard first — a bare `' AND 1=1-- -` collapses to `LIKE ''`, which matches no
row on either branch and proves nothing:

```
GET /admin/users?q=%' OR 1=1-- -     -> "All users (10)"
GET /admin/users?q=%' OR 1=2-- -     -> "All users (0)"
```

The heading text `All users (N)` is the string the PHP template renders and the
Node port must keep, so no new empty-state copy is invented.

Expected effect: the admin users table contains a row whose email cell holds the
60-character bcrypt hash of another account, and the `boards` table gains a row
the application never created.

## Differential oracle

`test/vulns/sqli.test.mjs`:

1. Sign in as `owner_olivia` (admin, no MFA in the seed).
2. Read the target hash straight from the database with
   `helpers/db.mjs#row("SELECT password_hash FROM users WHERE username = 'mod_marcus'")`.
3. `GET /admin/users` with the UNION payload; assert `200` and that the response
   body contains that hash inside a table cell.
4. `GET /admin/users` with the stacked-statement payload; assert `200`, then
   `helpers/db.mjs#count("SELECT COUNT(*) FROM boards WHERE name = 'pwned-sqli'")`
   equals 1.
5. Assert the boolean pair behaves as injected: the `%' OR 1=1-- -` probe renders
   `All users (10)` and the `%' OR 1=2-- -` probe renders `All users (0)`, with the
   same payload prefix in both.
6. Secondary sink: `GET /directory?q=%' OR 1=1-- -` renders all ten personas, and
   the 5-column UNION form of the same payload puts `outsider_olly` in a result the
   role filter should have excluded.
7. Assert the guard still works: an anonymous `GET /admin/users?q=<payload>` is a
   `303` to `/login`, so the injection needs a session and the finding is not also
   an access-control break.
8. Assert the non-injected search still works: `q=regular` returns exactly the
   `regular_rita` row, so the search feature functions and only the binding is gone.

On `main` every assertion in steps 3-6 must fail: `allUsers` passes the term as a
bound parameter, so all three payloads are literal search text — step 3 renders
`All users (0)`, step 4 leaves `boards` at its seeded count, step 5 renders
`All users (0)` for both probes, and step 6 filters on a token that matches no
persona; the explicit `multipleStatements: false` pool rejects step 4's second
statement even if the first half were interpolated; and `c-sql-3` keeps `'`, `%` and
`_` literal, which is why the same payloads are inert on `main`. Step 7 (the guard)
and step 8 (the working search) behave identically on both sides by design.

## Must-not-break invariants

- Step 8 (`q=regular` returns exactly the `regular_rita` row) still holds: the
  search box keeps filtering, it just interpolates. The one parity case allowed to
  fail is `c-sql-3`/`testAllUsersSearch`, and it is declared above.
- Because `LIKE` escaping is gone, a plain `q=%` on the branch returns every row
  (wildcard enumeration). That is a second symptom of the same declared control, not
  a separate finding — assert it in the same test so the evidence is complete.
- The rest of the baseline suite stays green; per `docs/04` §6 the branch declares
  `C-SQL-1`, `C-SQL-2` and `C-DIR-1`, which skips only the cases carrying those
  slugs — in `test/security/controls.test.mjs`, `test/unit/db-connection.test.mjs`
  and `test/unit/hook-directory.test.mjs` — and every other case, including
  `c-dir-2`, `c-sess-*` and `c-acl-*`, still runs.
- CSRF, sessions and ACL stay intact and are asserted in step 1-2 (the payload
  needs a real admin session; an anonymous request is redirected).
- The XSS family stays fixed: the extracted hash is escaped on output, so
  `test/security/baseline-inert.test.mjs` must still pass on this branch.

## Fidelity to the PHP branch

The PHP `vuln/sqli` branch is a string-interpolated query in the same
`UserRepository::search()` this port mirrors, plus permissive PDO. The Node form is
one interpolation plus one dropped pool option, with the same three probes (union
read, stacked write, boolean inference) the PHP exploit tests use. The parameter
name and route are identical because the route table is generated from PHP.

## Carmentis evidence

Capture the `q` value with the UNION payload and the admin page fragment showing
the hash in the email column; capture the INSERT payload and a query proving the
extra `boards` row; capture the boolean pair as the low-noise confirmation.
Expected label: `CWE-89 / SQL Injection`, with stacked statements as the second
evidence item. False-negative watch-out: if the scanner only looks for an error
message or a visible difference in row counts, the stacked-write evidence is missed;
if it renders the union output through `toPublic()`-filtered JSON it will not see
the hash either, because the leak is in the HTML table cell.

## Definition of done

- [ ] `test/vulns/sqli.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green with exactly `C-SQL-1`, `C-SQL-2`, `C-SQL-3` and `C-DIR-1` declared.
- [ ] One commit off `main`; diff touches only the three listed source files.
- [ ] Commit message: `vuln: sqli — build the staff search and directory filter from raw input`.
