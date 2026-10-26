# race_condition — single-use OTP consumed more than once

- Branch: `vuln/race_condition`
- Catalog row: 21
- Effort: M
- Hook: core app (MFA verification)
- Test file: `test/vulns/race_condition.test.mjs`

## Class and CWE

Race condition in a check-then-act sequence — CWE-362, with CWE-367 (TOCTOU).
Family: authentication.

## Intent

Prove that a single-use credential can be redeemed concurrently, so the
one-time-code guarantee (and the second factor it implements) fails under
parallelism rather than under guesswork.

## Affected surface

- Route: `POST /mfa`
- Parameter: `code` (form body)
- Prerequisites: a persona with MFA enabled (`mfa_mia`), the OTP read from the
  run's mail log, and the session that is mid-login
- Reachability: the MFA challenge page

## Sink

`src/security/mfa.js` — `verify(userId, code)`. On `main` the read of the newest
unused code, the attempt increment and the burn all happen inside
`transaction()` with `SELECT … FOR UPDATE` on the `mfa_codes` row. The branch
drops the transaction and the lock, and burns the code only after a successful
comparison, so concurrent verifications all read the same unused row.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-RACE-1` | One-shot invariants hold under concurrency: check-then-act on a single-use resource runs in a transaction with `SELECT … FOR UPDATE` | the transaction and the row lock are dropped, and the burn moves after the comparison |

`C-MFA-1` is **not** declared: per `docs/03`'s clause ownership, `C-MFA-1` is the
OTP lifecycle (issue, TTL, attempt cap, re-issue invalidation, resend throttle) and
`C-RACE-1` is single-use under concurrency. This diff changes only the latter.

## Minimal diff

Files touched:

- `src/security/mfa.js` — replace `transaction()`/`forUpdate()` with plain
  `query()` calls, move the `used_at = NOW()` update after the comparison, and put
  `await delayMs(350)` between the read and the burn. That seam is the sanctioned
  way to make the window provable (`docs/04` §9): it is part of the branch diff, it
  is at least 300 ms, and the test asserts **counts**, never elapsed time.
- `test/vulns/race_condition.test.mjs` — new file.

## Payload sketch

```
POST /mfa      (x12, sent concurrently, same session, same token)
content-type: application/x-www-form-urlencoded

csrf_token=<token>&code=<the single OTP from the mail log>
```

Expected effect: more than one request completes the login, i.e. two independent
authenticated sessions exist from one code.

## Differential oracle

`test/vulns/race_condition.test.mjs`:

1. Log in as `mfa_mia`, read the OTP from the run's mail log.
2. Build 12 HTTP agents that share the mid-login session cookie and the CSRF
   token, and fire the 12 `POST /mfa` requests with `Promise.all`.
3. Count the responses that are a `303` to `/` (a completed login), read
   `MAX(mfa_codes.attempts)` for that user, and collect the session ids in the
   `Set-Cookie` headers of the completed responses.
4. Assert completions ≥ 2, `attempts` ≥ 2 (two or more readers each reached the
   increment, so each of them saw an unused row) and at least two distinct session
   ids were issued — the code was consumed more than once.
5. Assert that a *serial* replay still fails (`mfa.verify()` returns an empty list
   the first time and a non-empty list the second, and no unused row is left), so
   the single-use rule works one-at-a-time and the finding is a concurrency
   defect.

The user in the test is created with `makeUser('race', …)` plus
`users.setMfaEnabled(true)` rather than the `mfa_mia` persona, because the burst
must be the only activity in the run's mail log.

On `main` this test must fail at step 4: exactly one request completes, the rest
receive `Incorrect code. Please try again.` or
`No pending verification code. Please request a new one.`, and only one session
row gains a `user_id`.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- All ten MFA lifecycle cases in `test/integration/mfa.test.mjs` stay green —
  expiry, attempt cap, resend throttle and hashing are untouched.
- The attempt counter is still incremented (asserted by this test reading
  `mfa_codes.attempts` afterwards), so the branch is not also removing `C-MFA-1`.
- Login throttling unaffected; `test/security/baseline-inert.test.mjs` passes.
- Only the `c-race-1` cases are skipped — and only the OTP one: the vote cases in
  `test/integration/race-baseline.test.mjs` carry `c-race-1-vote` and the reset-token
  case carries `c-race-1-token`, so those two invariants keep running here (this diff
  touches neither the vote write nor the reset-token write). The ten `c-mfa-1`
  lifecycle cases in `test/integration/mfa.test.mjs` run and must stay green.

## Fidelity to the PHP branch

The PHP target's race branch has the same shape: the code row is read, then
verified, then burned, without a transaction. Node makes the window wider and
easier to prove because the pool serves concurrent requests on separate
connections, and the 350 ms seam in the branch diff makes the window wide enough
that 12 parallel requests reliably land inside it; the assertion is on the number of
successful verifications and `sessions` rows, never on elapsed time.

## Carmentis evidence

Capture the single OTP, the count of `303` completions from one code, and the two
authenticated session rows. Expected label: `CWE-362 / Race Condition in a
single-use credential`. False-negative watch-out: the requests must be truly
concurrent and must reuse the same mid-login session and CSRF token; a scanner
that replays the code serially sees a correct rejection and reports nothing.

## Definition of done

- [ ] `test/vulns/race_condition.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: race_condition — verify and burn the OTP without a row lock`.
