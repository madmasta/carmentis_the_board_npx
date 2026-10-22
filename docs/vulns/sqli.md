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
array, and `src/db/connection.js` stops setting `multipleStatements: false` so a
statement separator starts working.

`src/hooks/directory.js#buildFilter` also interpolates the `q` token instead of
binding it, making the directory a second instance of the same class.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SQL-1` | Every statement goes through `connection.query(sql, params)` with `?` placeholders; user data never concatenates into SQL text | the `WHERE` fragment is built by string interpolation and the params array is dropped |
| `C-SQL-2` | The pool is created with `multipleStatements: false` | the option is no longer set, so it defaults to permissive and stacked statements execute |

Side effect the diff must declare, not hide: interpolating `q` in
`hooks/directory.js#buildFilter` also breaks the directory token binding that
`C-DIR-1` proves, so `C-DIR-1` is listed too.

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DIR-1` | Directory filter tokens are parsed into `{field, op, value}` and the value is bound as a parameter | `buildFilter` concatenates the raw token into the WHERE fragment |

## Minimal diff

Files touched:

- `src/db/connection.js` — delete the `multipleStatements: false` option.
- `src/repositories/user.repository.js` — `allUsers(search)` builds the `WHERE`
  fragment with template interpolation and calls `query(sql)` with no params.
- `src/hooks/directory.js` — `buildFilter` interpolates the `q` token.
- `test/vulns/sqli.test.mjs` — new file.

## Payload sketch

Read a credential the app never renders, into the rendered `email` slot:

```
GET /admin/users?q=' UNION SELECT id, username, password_hash, role, is_banned,
    ban_reason, mfa_enabled, created_at, updated_at, post_count
    FROM users WHERE username='mod_marcus'-- -
```

Run a statement the app never runs:

```
GET /admin/users?q='; INSERT INTO boards (name, description, default_access)
    VALUES ('pwned-sqli', 'stacked statement proof', 1)-- -
```

Boolean probe (no timing, deterministic):

```
GET /admin/users?q=' AND 1=1-- -     -> rows returned
GET /admin/users?q=' AND 1=2-- -     -> "No users match that search."
```

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
5. Assert the boolean pair behaves as injected: the `1=1` probe returns rows and
   the `1=2` probe returns the empty-state message, both with the same payload
   prefix.
6. Secondary sink: `GET /directory?q=<same UNION shape>` returns rows it should not
   be able to return.
7. Assert the non-injected search still works: `q=regular` returns exactly the
   `regular_rita` row, so the search feature functions and only the binding is gone.

On `main` every assertion in steps 3-6 must fail: `allUsers` passes the term as a
bound parameter, so all three payloads are literal search text that matches no row
(step 3 returns the empty-state page, step 4 leaves `boards` at its seeded count,
step 5's two probes behave identically, step 6 is a parameterized filter); the
`multipleStatements: false` pool would reject step 4's second statement even if the
first half were interpolated.

## Must-not-break invariants

- Step 7 above: parity tests for search (`test/unit/repository-users.test.mjs`) may
  not fail on the branch — the search box still filters, it just interpolates.
- The rest of the baseline suite stays green; per `docs/04` §6 the branch declares
  `C-SQL-1`, `C-SQL-2` and `C-DIR-1`, which maps to skipping
  `test/security/controls.test.mjs` proofs for those IDs plus
  `test/unit/db-connection.test.mjs` (the `C-SQL-2` proof) and
  `test/unit/hook-directory.test.mjs` (the `C-DIR-1` proof), and nothing else.
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
- [ ] `npm run verify:branch` green with exactly `C-SQL-1`, `C-SQL-2`, `C-DIR-1` declared.
- [ ] One commit off `main`; diff touches only the three listed source files.
- [ ] Commit message: `vuln: sqli — build the staff search and directory filter from raw input`.
