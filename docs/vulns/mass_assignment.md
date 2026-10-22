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

`src/http/profile.controller.js` — `update(req)`. On `main` the handler reads its
input through `readInput(req, ['current_password', 'mfa_enabled'])`, an allowlist
with explicit casts, and the `UPDATE` names two columns. The branch builds the
patch generically:

```js
const COLUMN = { role: 'role', is_banned: 'is_banned', mfa_enabled: 'mfa_enabled',
                 email: 'email', username: 'username', ban_reason: 'ban_reason' };
const patch = { ...req.body };
delete patch.csrf_token;
const sets = Object.keys(patch).filter(k => COLUMN[k]);
await execute(
  `UPDATE users SET ${sets.map(k => `${COLUMN[k]} = ?`).join(', ')} WHERE id = ?`,
  [...sets.map(k => patch[k]), req.user.id],
);
```

Column names come from a fixed map, so `C-SQL-1` stays intact; the defect is that
the *set of columns* is chosen by the client. Keys outside the map are silently
dropped, which is also why the finding needs a mapped column such as `role`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-ASSIGN-1` | Per-route field allowlist with casts; unknown keys dropped; dangerous keys rejected | the allowlist is replaced by a spread of the whole body |

## Minimal diff

Files touched:

- `src/http/profile.controller.js` — the generic patch construction above in
  `update()`, keeping the password confirmation check first so the path stays
  reachable.
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

## Must-not-break invariants

- The MFA toggle still requires the current password and still refuses the change
  when it is wrong (`test/integration/admin-flow.test.mjs#testMfaTogglePersists`).
- E-mail and password change routes keep their allowlisted input readers — this
  branch touches only the profile update path, and the control assertion for those
  routes stays green.
- Prototype-key rejection remains (step 5), so the router and body parser stay
  healthy for every other route.
- `test/security/baseline-inert.test.mjs` passes; only `C-ASSIGN-1` is skipped.

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
