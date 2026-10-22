# sensitive_data_exposure — credentials and internal state in responses

- Branch: `vuln/sensitive_data_exposure`
- Catalog row: 23
- Effort: S
- Hook: core app (user records)
- Test file: `test/vulns/sensitive_data_exposure.test.mjs`

## Class and CWE

Exposure of sensitive information to an unauthorized actor — CWE-201, with
CWE-259 (credential exposure in a non-credential channel). Family: configuration
and supply chain.

## Intent

Prove that the application ships secrets and private account state to the browser,
so a stolen or shared session, a shoulder-surfed page, or a cached page leaks
credentials rather than names.

## Affected surface

- Route: `GET /admin/users` (list and search), `GET /profile`
- Parameter: none; the response shape is the defect
- Prerequisites: `admin` for the list, `regular` for the profile
- Reachability: the admin users page and the profile page

## Sink

`src/repositories/user.repository.js` — `toPublic(user)`. On `main` every user
object that reaches a template or a JSON response is passed through `toPublic`,
which returns `id, username, email, role, created_at, post_count` and is asserted
never to contain `password_hash`, `ban_reason`, `mfa_enabled` or a session id.
The branch drops the projection: `allUsers()` and `findById()` return the row as
read, and `templates/admin/users.njk` renders the extra columns in a "diagnostics"
table block that support asked for.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DATA-1` | Secrets never rendered or returned; configuration and credential values stay server-side | password hashes are projected into the page |
| `C-INFO-3` | Log records never contain credentials or session ids | the request logger now logs the session id at info level, which the branch keeps |

## Minimal diff

Files touched:

- `src/repositories/user.repository.js` — return the full row from `allUsers()` and
  `findById()`, and make `toPublic()` an identity function.
- `templates/admin/users.njk` — add the diagnostics block rendering
  `user.password_hash`, `user.ban_reason` and `user.mfa_enabled` per row.
- `src/http/server.js` — log `sid=<session id>` in each request record.
- `test/vulns/sensitive_data_exposure.test.mjs` — new file.

## Payload sketch

```
GET /admin/users?q=owner
GET /profile
```

Expected effect: the admin users table shows bcrypt hashes such as
`$2b$10$…`, the ban reason text for `banned_bob`, and MFA state per account; the
log contains session ids.

## Differential oracle

`test/vulns/sensitive_data_exposure.test.mjs`:

1. Sign in with the `admin` profile; `GET /admin/users?q=owner`.
2. Assert the response body contains a bcrypt-hash pattern matching
   `/\$2[aby]\$\d{2}\$/` and that it belongs to `owner_olivia` (compare with the
   hash read straight from the database by the test helper).
3. `GET /admin/users?q=banned` and assert the seeded ban reason
   `Repeated spam in General (seeded test ban)` appears.
4. `GET /profile` as `regular_rita` and assert the body contains her own
   `password_hash` too — the exposure is not limited to the admin surface.
5. Send one authenticated request, then read `var/log/app.log` and assert a
   `sid=` value equal to the current session cookie appears in it.

On `main` steps 2–5 must fail: the hash pattern never occurs in any response, the
ban reason is absent from the users page, and no `sid=` appears in the log.

## Must-not-break invariants

- The users table still lists usernames, e-mails, roles and post counts, and the
  search still works (`test/integration/user-repository.test.mjs#testAllUsersSearch`).
- Password **authentication** is unaffected: hashes are still verified normally
  and no plaintext is ever stored (`#testPasswordIsHashedNotStoredPlaintext` stays
  green).
- MFA enrolment state still functions; the finding is that the flag is displayed.
- `test/security/baseline-inert.test.mjs` passes; only `C-DATA-1` and `C-INFO-3`
  are skipped, and the "no plaintext password in a response" clause is re-asserted
  inside this test.

## Fidelity to the PHP branch

Same class and same artefact as the PHP target's sensitive-data branch: model rows
selected with `SELECT *` and rendered without a projection, so the hash column
travels to the browser. The Node version keeps the projection function in place
but makes it an identity, which is how this bug appears in real code.

## Carmentis evidence

Capture the response body region containing the bcrypt hash pattern and the
`sid=` line from the log. Expected label: `CWE-201 / Sensitive Data in Response`
with `CWE-259 / Credential Exposure`. False-negative watch-out: a scanner that
only looks for the literal word `password` will miss it — the column is named
`password_hash` in a table header and the value is opaque, so the finding depends
on recognising the bcrypt shape.

## Definition of done

- [ ] `test/vulns/sensitive_data_exposure.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the four listed files.
- [ ] Commit message: `vuln: sensitive_data_exposure — return password hashes and private account state to the client`.
