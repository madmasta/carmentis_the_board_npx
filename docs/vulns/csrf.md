# csrf — CSRF protection replaced by a request-header heuristic

- Branch: `vuln/csrf`
- Catalog row: 6
- Effort: S
- Hook: core app
- Test file: `test/vulns/csrf.test.mjs`

## Class and CWE

Cross-site request forgery — CWE-352. Family: authentication.

## Intent

Prove that a state-changing request is accepted without the session token, so any
third-party page can drive the application as the logged-in user.

## Affected surface

- Route: every state-changing route; `POST /thread/:id/reply` is the reference
  probe, `POST /admin/users/:id/ban` is the high-impact confirmation
- Parameter: absence of `csrf_token`, presence of `X-Requested-With: fetch`
- Prerequisites: `regular` profile (and `admin` for the ban confirmation)
- Reachability: every form in the UI carries the token, so the attack is a
  hand-built cross-origin form

## Sink

`src/http/controller.js` — `csrf(req)`. On `main` it compares the submitted token
with the session token using `crypto.timingSafeEqual` and rejects anything else
with `400`. The branch adds a convenience path for the app's own fetch calls:

```js
if (!token && req.headers['x-requested-with'] === 'fetch') return;   // same-origin fetch
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-CSRF-1` | Token required on every state-changing request, constant-time compare, rotate on login | an attacker-settable header substitutes for the token |

## Minimal diff

Files touched:

- `src/http/controller.js` — the header bypass above, and the same bypass in
  `src/routes.js` where the router applies the CSRF pre-check.
- `test/vulns/csrf.test.mjs` — new file.

## Payload sketch

```
POST /thread/1/reply
content-type: application/x-www-form-urlencoded
x-requested-with: fetch
cookie: theboard_session=<victim session id>

body=created+by+a+cross+origin+form
```

The branch's bypass condition is exactly
`token missing && req.headers['x-requested-with'] === 'fetch'`. A browser cannot
set a custom header on a cross-origin simple form POST, so the browser-reachable
impact of this exact diff is limited to XSS-assisted or API-client callers; the
scanner-visible finding is the unauthenticated-token acceptance and the state
change it allows, which is what the oracle asserts. The sheet records this limit
honestly rather than claiming a one-click drive-by.

## Differential oracle

`test/vulns/csrf.test.mjs`:

1. Sign in as `regular_rita` and note the thread's reply count.
2. `POST /thread/:id/reply` with a valid token → `303` and the count increases
   (control sanity, must pass on every branch).
3. `POST /thread/:id/reply` with **no** token and **no** header → expect `400` on
   every branch; assert it.
4. `POST /thread/:id/reply` with no token but `x-requested-with: fetch` → the
   branch answers `303` and the reply count increases.
5. Repeat step 4 against `POST /admin/users/:id/ban` as an admin session and
   assert the target user's `is_banned` flag flips.

On `main` step 4 and step 5 must fail with `400 Invalid or missing CSRF token.`
and no state change.

## Must-not-break invariants

- Step 2 and step 3 above are themselves invariants: token-valid requests still
  work, and a tokenless request without the magic header is still rejected.
- Token rotation on login still happens (`test/unit/csrf.test.mjs` stays green
  except the one skipped assertion).
- Login, MFA and ban flows otherwise unchanged; `test/security/baseline-inert.test.mjs`
  passes.
- Only `C-CSRF-1` is skipped.

## Fidelity to the PHP branch

Same class and same downgrade shape as the PHP target's CSRF branch: the token
check is not deleted, it is made conditional, which is the realistic way this bug
appears and the reason a naive "is the token compared?" audit passes.

## Carmentis evidence

Capture the state-changing request without `csrf_token`, the header or Referer
condition that made it succeed, and the resulting state change (new reply id,
ban flag). Expected label: `CWE-352 / CSRF`. False-negative watch-out: the
finding is invisible from the response body alone — the app redirects back to the
thread, so the scanner must confirm the side effect by re-reading the resource.

## Definition of done

- [ ] `test/vulns/csrf.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the listed files.
- [ ] Commit message: `vuln: csrf — accept a request header in place of the CSRF token`.
