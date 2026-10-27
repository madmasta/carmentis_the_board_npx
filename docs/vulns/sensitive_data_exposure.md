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

`src/repositories/user.repository.js` — the two user-listing statements
(`SELECT_ALL_USERS` and `SELECT_USERS_SEARCH`), and the templates that consume them.
There is no projection helper on this target: `loadUser()` deliberately selects
`password_hash` (every privileged change re-checks the current password, docs/03
C-AUTH-2), the listing statements deliberately omit it, and the templates render only
display fields. The control is that gap, so removing it means widening the listing and
opening the templates:

```js
// src/repositories/user.repository.js
const SELECT_ALL_USERS = 'SELECT u.id, u.username, u.email, u.password_hash, u.role, ...';
const SELECT_USERS_SEARCH = 'SELECT u.id, u.username, u.email, u.password_hash, u.role, ...';
```

```jinja
{# templates/admin/users.njk - "Record diagnostics", ticket 412 #}
<tr><th>ID</th><th>Username</th><th>password_hash</th><th>ban_reason</th><th>mfa_enabled</th></tr>
...
<td class="mono">{{ u.password_hash }}</td><td>{{ u.ban_reason }}</td><td>{{ u.mfa_enabled }}</td>

{# templates/profile.njk - same record on the account owner's own page #}
<dt>Record</dt><dd class="mono">{{ profile_user.password_hash }}</dd>
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DATA-1` | Secrets never rendered or returned; credential and private account state stay server-side | the hash column is selected into both listing statements and printed on two pages, beside `ban_reason` and `mfa_enabled` |

## Minimal diff

Files touched:

- `src/repositories/user.repository.js` — add `u.password_hash` to both listing
  statements. `SELECT_USER_BY_ID` already carries it; nothing is removed from the
  file, which is why the exposure has to be argued from the rendered pages.
- `templates/admin/users.njk` — the "Record diagnostics" table above
  (`password_hash`, `ban_reason`, `mfa_enabled` per row).
- `templates/profile.njk` — the same record on the account owner's own page, which is
  what makes this CWE-201/CWE-259 rather than an admin-only reporting choice.
- `test/vulns/sensitive_data_exposure.test.mjs` — new file.

## Payload sketch

```
GET /admin/users?q=owner
GET /profile
```

Expected effect: the admin users table shows bcrypt hashes such as
`$2b$10$...`, the seeded ban reason text beside the account it belongs to, and MFA
state per account; the profile page shows the visitor their own hash.

## Differential oracle

`test/vulns/sensitive_data_exposure.test.mjs`:

1. Sign in with the `admin` profile; `GET /admin/users?q=owner` (the search
   statement — the listing and the search are two statements, and both have to carry
   the column for the finding to hold at every entry point).
2. Assert the response body contains a bcrypt-hash pattern matching
   `/\$2[aby]\$\d{2}\$/` and that it belongs to `owner_olivia` (compare with the
   hash read straight from the database by the test helper).
3. `GET /admin/users?q=banned` and assert the seeded ban reason
   `Repeated spam in General (seeded test ban)` appears.
4. `GET /profile` as `regular_rita` and assert the body contains her own
   `password_hash` too — the exposure is not limited to the admin surface.
5. Assert that no response carries the plaintext test password and that a second
   login still succeeds — the finding is exposure, not broken authentication.

On `main` steps 2-4 must fail: the hash pattern never occurs in any response, and the
seeded ban reason is absent from the users page.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The users table still lists usernames, e-mails, roles and post counts, and the
  search still works (`test/integration/user-repository.test.mjs#testAllUsersSearch`).
- The request logger is untouched: no session id, e-mail or code enters
  `var/log/app.log`, so `C-INFO-3` stays fully enforced on this branch and its
  `c-info-3` cases keep running.
- Password **authentication** is unaffected: hashes are still verified normally
  and no plaintext is ever stored (`#testPasswordIsHashedNotStoredPlaintext` stays
  green).
- MFA enrolment state still functions; the finding is that the flag is displayed.
- `test/security/baseline-inert.test.mjs` passes; only `C-DATA-1` is skipped — the
  three cases carrying that slug (the source scan, `/health`'s fixed body, and
  `no credential or private account state reaches a rendered page`), and the "no
  plaintext password in a response" clause is re-asserted inside this test.

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

## Correction history

- The sheet described a `toPublic()` projection in `user.repository.js` and a `sid=`
  change to the request logger. Neither exists on this target: the control is that the
  listing statements omit `password_hash` while `loadUser()` keeps it, and the
  templates print display fields only. The diff is therefore the two widened
  statements plus two template blocks.
- `C-INFO-3` is no longer declared. Logging session ids was a second, unrelated
  removal; declaring it would have skipped the `c-info-3` log-structure proofs that
  this branch does not affect.
- The oracle's `sid=` step became an authentication/plaintext control, so the branch
  stays a single-control claim: `C-DATA-1`. Its proof set on `main` is the source scan,
  the `/health` body case, and
  `test/security/controls.test.mjs#c-data-1 no credential or private account state
  reaches a rendered page`.
