# weak_password_policy — password rules replaced by a length check

- Branch: `vuln/weak_password_policy`
- Catalog row: 29
- Effort: S
- Hook: core app (registration, profile password change)
- Test file: `test/vulns/weak_password_policy.test.mjs`

## Class and CWE

Weak password requirements — CWE-521. Family: authentication.

## Intent

Prove that the account policy accepts trivially guessable passwords, so the
credential store is the weak link regardless of how well the rest of login is
built.

## Affected surface

- Route: `POST /register` (`password`), `POST /profile/password` (`new_password`)
- Parameter: `password`, `new_password`
- Prerequisites: `anon` for registration
- Reachability: the registration form

## Sink

`src/security/validator.js` — `password(value, username, email)`. On `main` the
rules come from `PASSWORD_MIN_LENGTH` (default 10), the ≤ 200 cap, the letter and
digit requirements when the minimum is ≥ 8, and the not-equal-to-username/email
checks. The branch replaces the whole body with:

```js
if (value.length < 4) errors.push('Password must be at least 4 characters long.');
```

and `.env.example` ships `PASSWORD_MIN_LENGTH=4`, so the configuration no longer
drives anything.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-AUTH-2` | Policy from env, letter+digit, no username/email match, length cap | all clauses except a 4-character floor are deleted |

## Minimal diff

Files touched:

- `src/security/validator.js` — the single-clause body above.
- `.env.example` — `PASSWORD_MIN_LENGTH=4`.
- `test/vulns/weak_password_policy.test.mjs` — new file.

## Payload sketch

```
POST /register
content-type: application/x-www-form-urlencoded

csrf_token=<token>&username=weak_window&email=weak@test.theboard.local&password=abc&password_confirm=abc
```

Expected effect: the account is created and the app auto-logs the user in.

## Differential oracle

`test/vulns/weak_password_policy.test.mjs`:

1. Register `weak_window` with password `abc`; assert a `303` to `/` and a session
   cookie.
2. Log in again as `weak_window` with `abc` and assert success — the account
   exists with a guessable credential.
3. Register a second account whose password equals its username (`echo` / `echo`)
   and assert success, proving the username-equality clause is gone.
4. Try a password of `ab` and assert it is still rejected, proving the branch left
   a floor and the finding is about the missing clauses, not about "no validation".
5. Assert the seeded personas' passwords still work: the hashing path is untouched.

On `main` this test must fail at step 1 with the three policy errors
`Password must be at least 10 characters long.`, `Password must contain at least
one letter.` and `Password must contain at least one number.`, and no account is
created. Step 3 fails there too, because `Password must not match your username.`
is emitted.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- Registration with a strong password still succeeds, and duplicate
  username/e-mail handling is unchanged (`test/integration/auth.test.mjs`).
- `test/unit/validator.test.mjs` skips only the password-rule cases; username,
  e-mail, title and body rules stay enforced and asserted.
- Login throttling still applies to the weak accounts — that control is not
  touched by this branch.
- `test/security/baseline-inert.test.mjs` passes.

## Fidelity to the PHP branch

Same class and the same realistic form as the PHP target's weak-policy branch: the
validator body is replaced by one length test while the configuration key keeps
its name, so the policy looks configurable but is not. The Node target keeps the
same default shipped in `.env.example`, which is what a configuration-level
scanner sees.

## Carmentis evidence

Capture the accepted registration with password `abc`, the resulting session
cookie, and the successful re-login. Expected label: `CWE-521 / Weak Password
Requirements`. False-negative watch-out: a scanner that only checks the login
form's client-side `minlength` attribute will miss this — the form has no such
attribute, and the rule is server-side, so the proof is an accepted registration.

## Definition of done

- [ ] `test/vulns/weak_password_policy.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: weak_password_policy — reduce the password rule to a 4-character floor`.
