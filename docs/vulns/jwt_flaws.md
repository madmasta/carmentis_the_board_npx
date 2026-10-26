# jwt_flaws — token verification bypass in password reset

- Branch: `vuln/jwt_flaws`
- Catalog row: 14
- Effort: M
- Hook: password reset + remember-me
- Test file: `test/vulns/jwt_flaws.test.mjs`

## Class and CWE

Incorrect token verification — CWE-347, with CWE-345 (insufficient verification of
data authenticity). Family: authentication.

## Intent

Prove that the application accepts a token whose signature it never validated, so
an attacker can mint a credential for any account.

## Affected surface

- Route: `POST /reset-password`
- Parameter: `token` (form body)
- Prerequisites: `anon` profile; the target account's e-mail address (a seeded
  persona address is enough)
- Reachability: the reset link landing page

## Sink

`src/security/jwt.js` — `decode(token, purpose)`. On `main` it calls
`jwt.verify(token, secret, { algorithms: ['HS256'] })` and rejects anything else.
The branch replaces it with:

```js
const decoded = jwt.decode(String(token ?? ''), { complete: true });   // no key, no algorithms
if (decoded === null || decoded.payload === undefined) return { ok: false, message: INVALID_TOKEN };

const { payload } = decoded;
if (payload.iss !== JWT_ISSUER) return { ok: false, message: INVALID_TOKEN };
if (payload.purpose !== purpose) return { ok: false, message: INVALID_TOKEN };
if (typeof payload.jti !== 'string' || payload.jti === '') return { ok: false, message: INVALID_TOKEN };
if (typeof payload.exp === 'number' && payload.exp <= Math.floor(Date.now() / 1000)) {
  return { ok: false, message: INVALID_TOKEN };
}
return { ok: true, payload };
```

The signature and `algorithms` check disappear; the issuer, purpose, expiry and
jti-shape checks are deliberately **kept**, and the single-use claim is spent later by
`verifyActive`/`consumeToken` (unchanged), so the expired-token and replay behaviour is
identical on the branch and the finding is isolated to verification. Note that
`jwt.decode` takes only `complete`; there is no `json` option, and inventing one makes
the diff not run.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-JWT-1` (signature/algorithm clause only) | `algorithms` pinned, no `none`, `exp` enforced, `jti` single-use | the signature and algorithm check are replaced by an unverified decode; the expiry and single-use clauses stay enforced and keep running |

## Minimal diff

Files touched:

- `src/security/jwt.js` — the `decode()` body above; `signingSecret()`, `issue()` and the
  `jwt_claims` single-use machinery stay untouched.
- `test/vulns/jwt_flaws.test.mjs` — new file.

## Payload sketch

```
POST /reset-password
content-type: application/x-www-form-urlencoded

csrf_token=<token>&token=<base64url({"alg":"none","typ":"JWT"})>.<base64url({"sub":1,"jti":"forged-1","exp":4100000000})>.&password=AttackerPass123&password_confirm=AttackerPass123
```

`sub` is `owner_olivia`'s id and the signature segment is empty.

Expected effect: the admin's password is changed and the attacker can log in as
`owner_olivia` with `AttackerPass123`.

## Differential oracle

`test/vulns/jwt_flaws.test.mjs`:

1. Look up `owner_olivia`'s id through the test helper and forge the token above
   by base64url-encoding the two segments in the test itself (no library needed).
2. `GET /reset-password?token=<forged>` as an anonymous client to get the form and
   its `csrf_token` (no admin session anywhere in this test — the prerequisite is
   `anon`, and signing in first would blur attribution with the ACL branches), then
   `POST /reset-password` with the forged token; assert `303` to `/login` and the
   flash `Password updated. Sign in with your new password.` (`docs/02` §7 hook
   failure contract — not the profile flash `Password updated.`).
3. Log in as `owner_olivia` with `AttackerPass123` and assert the login succeeds.
4. Assert that a token whose `exp` is in the past is still rejected (the branch
   keeps expiry handling, so the finding is precise), and that replaying the same
   `jti` twice fails the second time.

On `main` this test must fail at step 2: `jwt.verify` throws for an unsigned
token, the response is the generic `That reset link is no longer valid.` and the
password is unchanged.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The legitimate reset flow still works end to end: request a link, read the
  token from the mail log, reset, log in (`test/integration/hooks.test.mjs`).
- `jti` replay protection and expiry remain enforced (step 4 above).
- Remember-me tokens issued by `sign()` still verify normally.
- `test/security/controls.test.mjs` skips only `C-JWT-1`.

## Fidelity to the PHP branch

The same class in the PHP target is an unsigned or weakly-signed token accepted by
a hand-rolled JWT helper. Node has the same failure mode when `decode` is used in
place of `verify`, and it is the single most common real-world instance of the
class, which is why the branch uses it instead of a key-confusion variant. The
`vuln/vulnerable_components` branch covers the library-version route to the same
outcome.

## Carmentis evidence

Capture the forged token (header with `"alg":"none"`, empty signature segment),
the successful reset response, and the subsequent admin login. Expected label:
`CWE-347 / JWT signature not verified`. False-negative watch-out: the scanner
must supply a valid CSRF token and must reuse a fresh `jti` per attempt, because
replay protection makes the second identical probe look like a failure.

## Definition of done

- [ ] `test/vulns/jwt_flaws.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: jwt_flaws — decode reset tokens without verifying the signature`.
