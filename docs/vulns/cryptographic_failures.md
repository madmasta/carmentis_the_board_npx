# cryptographic_failures — predictable tokens and a hardcoded key

- Branch: `vuln/cryptographic_failures`
- Catalog row: 5
- Effort: S
- Hook: password reset + remember-me, upload naming
- Test file: `test/vulns/cryptographic_failures.test.mjs`

## Class and CWE

Use of an insufficient PRNG and a hardcoded cryptographic key — CWE-338, CWE-321,
CWE-327. Family: authentication.

## Intent

Prove that security tokens come from a predictable generator with a known key, so
an attacker who sees one token can compute the next token for a different account.

## Affected surface

- Route: `POST /forgot-password` (issue) and `POST /reset-password` (use)
- Parameter: `token` (form body)
- Prerequisites: `anon` profile
- Reachability: the forgot-password form

## Sink

`src/security/tokens.js` — `randomToken(purpose)`. On `main` it returns
`crypto.randomBytes(24).toString('hex')`, and the JWT secret comes from
`JWT_SECRET` (≥ 32 random bytes). The branch derives tokens from a seeded
linear-congruential generator and signs with a literal:

```js
let state = Date.now() % 2147483647;
export function randomToken() {
  state = (state * 1103515245 + 12345) % 2147483648;
  return state.toString(16).padStart(8, '0') + randomToken.counter++;
}
```

and sets `const JWT_SECRET = 'theboard-dev-secret'` when `JWT_SECRET` is unset,
instead of generating one.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-CRYPTO-1` | CSPRNG for every security token; no hardcoded key | LCG seeded from the clock replaces `randomBytes`; a literal replaces the generated secret |

## Minimal diff

Files touched:

- `src/security/tokens.js` — the LCG above for `reset`, `remember` and upload-name
  purposes (MFA codes keep `randomInt`, so the MFA suite stays green and the
  finding is scoped).
- `src/security/jwt.js` — the literal default secret.
- `test/vulns/cryptographic_failures.test.mjs` — new file.

## Payload sketch

```
1) POST /forgot-password   email=regular@test.theboard.local     -> token T1 in the mail log
2) POST /forgot-password   email=owner@test.theboard.local       -> token T2 (unknown to the attacker)
3) POST /reset-password    token=<predicted T2>&password=AttackerPass123&password_confirm=AttackerPass123
```

Expected effect: step 3 succeeds and the admin's password changes, using a token
computed from the generator's state rather than an observed one.

## Differential oracle

`test/vulns/cryptographic_failures.test.mjs`:

1. Import `randomToken` from the branch's `src/security/tokens.js` in the test.
2. Request a reset for `regular_rita`; read the token from the mail log and assert
   it matches the LCG output shape (8 hex characters followed by a counter), which
   is itself the weak-randomness evidence.
3. Continue the generator in the test and predict the next token; request a reset
   for `owner_olivia`, discard the real token, and submit the predicted token to
   `POST /reset-password`.
4. Assert the reset succeeds and `owner_olivia` can now log in with
   `AttackerPass123`.
5. Assert the JWT secret equals `theboard-dev-secret` by signing a remember-me
   token in the test with that literal and having the app accept it.

On `main` this test must fail at step 2 (a 48-hex `randomBytes` value) and at step
4 (a predicted value never matches, and the secret is a random 32-byte value that
the test cannot know).

## Must-not-break invariants

- The reset flow still works normally end to end (`test/integration/hooks.test.mjs`).
- MFA code generation, CSRF tokens, session ids and upload names still pass their
  own tests — only the reset/remember token purpose is weak, and the upload-name
  case is asserted in this test, not by weakening the upload test.
- `test/security/controls.test.mjs` skips only `C-CRYPTO-1`, and its
  session-id/CSRF-length clauses are re-asserted inside this exploit test.

## Fidelity to the PHP branch

Same class as the PHP target's cryptography branch: `mt_rand`/`uniqid()`-style
predictable tokens plus a committed key. The Node form uses an LCG because it is
the smallest change that is genuinely predictable and testable without a fixed
seed, and the literal secret mirrors a committed dev key.

## Carmentis evidence

Capture two consecutive reset tokens and the derived next token that was accepted,
plus the accepted token signed with the literal secret. Expected label:
`CWE-338 / Predictable Random Value` with `CWE-321 / Hardcoded Key`.
False-negative watch-out: the token is only visible in the mail log (out-of-band),
so the run must collect mail-log artefacts; a response-only scan sees a generic
"check your e-mail" page.

## Definition of done

- [ ] `test/vulns/cryptographic_failures.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: cryptographic_failures — derive reset tokens from a clock-seeded LCG and hardcode the JWT secret`.
