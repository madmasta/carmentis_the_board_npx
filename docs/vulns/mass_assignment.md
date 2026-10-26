# mass_assignment — submitted keys become user columns

- Branch: `vuln/mass_assignment`
- Catalog row: 17
- Effort: M
- Hook: core app (profile update)
- Test file: `test/vulns/mass_assignment.test.mjs`

## Class and CWE

Mass parameter assignment / unchecked user-controlled input into a data model —
CWE-915. Family: authorization.

## Intent

Prove that the update path binds whatever keys the client sends, so a caller can
set columns the form never exposes — including the role column.

## Affected surface

- Route: `POST /profile`
- Parameter: any submitted field name that matches a `users` column
- Prerequisites: `regular` profile (`regular_rita`)
- Reachability: the profile page's MFA toggle form

## Sink

`src/http/profile.controller.js` — `update(ctx)`. On `main` the handler reads one
field by name (`posts(ctx, ['current_password'])`), computes the toggle from
`ctx.req.fields.mfa_enabled`, and writes a single column through
`users.setMfaEnabled()` in the repository. The branch spreads the whole submitted
field map into a `SET` clause built from a fixed column map:

```js
const COLUMN = { role: 'role', is_banned: 'is_banned', mfa_enabled: 'mfa_enabled',
                 email: 'email', username: 'username', ban_reason: 'ban_reason' };
const patch = { ...ctx.req.fields };
delete patch.csrf_token;
const sets = Object.keys(patch).filter((key) => COLUMN[key] !== undefined);
await execute(
  `UPDATE users SET ${sets.map((key) => `${COLUMN[key]} = ?`).join(', ')} WHERE id = ?`,
  [...sets.map((key) => patch[key]), Number(user.id)],
);
```

The current-password check stays ahead of it, so the path stays as reachable as it
was.

Column names come from a fixed map, and the code stays in
`src/http/profile.controller.js`, which is outside the three places `C-SQL-1`'s
source scan covers (`src/repositories/`, `src/session/store.js`, `src/hooks/`), so
`C-SQL-1` stays enforced and is **not** declared here. If the generic patch builder
were moved into `src/repositories/user.repository.js#update`, the same diff would
also trip that scan and the sheet would have to declare `C-SQL-1` too. The defect is
that the *set of columns* is chosen by the client; keys outside the map are silently
dropped, which is also why the finding needs a mapped column such as `role`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-ASSIGN-1` (field-allowlist clause) | Per-route field allowlist with casts; unknown keys dropped; dangerous keys rejected | the allowlist is replaced by a spread of the whole body, so any mapped column can be set |

## Minimal diff

Files touched:

- `src/http/profile.controller.js` — the generic patch construction above in
  `update()` (plus the `execute` import it needs), keeping the password confirmation
  check first so the path stays reachable.
- `test/vulns/mass_assignment.test.mjs` — new file.

## Payload sketch

```
POST /profile
content-type: application/x-www-form-urlencoded

csrf_token=<token>&current_password=TestPass123&mfa_enabled=0&role=admin&is_banned=0
```

Expected effect: `regular_rita` now has `role = 'admin'` and can open
`/admin/boards`.

## Differential oracle

`test/vulns/mass_assignment.test.mjs`:

1. Sign in as `regular_rita`; assert `GET /admin/boards` is `403`.
2. Send the payload above; assert a `303` and the flash `MFA has been disabled.`.
3. Read the user row and assert `role === 'admin'` and `mfa_enabled === 0`.
4. As the same session, request `GET /admin/boards` and assert `200` — the
   privilege change is effective, not just a column write.
5. Submit a body containing `__proto__=1` and assert the request is rejected with
   `400` (the dangerous-key rejection is scoped to prototype keys and must remain,
   so the finding is column exposure rather than a prototype-pollution crash).
6. Clean up by resetting the persona's role through the fixture helper.

On `main` step 3 must show `role === 'user'` — unknown fields are dropped — and
step 4 must be `403`.

The field-allowlist proof lives on `main` as
`controls.test.mjs#c-assign-1 the profile update binds only the fields its form
exposes`; that is the case this declaration skips and the audit expects to go red.
The prototype-key proofs in `test/unit/request.test.mjs` carry the sub-slug
`c-assign-1-keys`, which the skip pattern in `test/helpers/declared.mjs` does not
match, so they keep running here.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The MFA toggle still requires the current password and still refuses the change
  when it is wrong (`test/integration/admin-flow.test.mjs#testMfaTogglePersists`).
- E-mail and password change routes keep their allowlisted input readers — this
  branch touches only the profile update path, and the control assertion for those
  routes stays green.
- Prototype-key rejection remains (step 5), so the router and body parser stay
  healthy for every other route. That is why only the field-allowlist cases of
  `C-ASSIGN-1` are skipped: the `__proto__`/`constructor` cases in
  `test/unit/request.test.mjs` carry `c-assign-1-keys` and keep running, and the
  `Object.assign` source scan in `controls.test.mjs` stays green because this diff
  uses a spread rather than `Object.assign`.
- `test/security/baseline-inert.test.mjs` passes; no other control is touched.

## Fidelity to the PHP branch

PHP's version is `$_POST` copied onto an array or model that is then passed to an
update. Node reproduces it exactly with an object spread feeding a dynamically
built `SET` clause — note that the column-name interpolation is itself a
consequence of the same defect, but the finding is classified as authorization,
not SQL injection, because the accepted keys are checked against the table's
column list before use.

## Carmentis evidence

Capture the extra submitted field `role=admin`, the `303`, the changed `role`
value, and the now-successful `/admin/boards` request. Expected label:
`CWE-915 / Mass Assignment`. False-negative watch-out: the route requires the
correct current password, so a scanner that fuzzes fields without authenticating
properly never reaches the update.

## Definition of done

- [ ] `test/vulns/mass_assignment.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: mass_assignment — bind submitted keys straight into the user update`.
