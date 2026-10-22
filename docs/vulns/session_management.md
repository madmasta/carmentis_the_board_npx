# session_management — session id survives authentication

- Branch: `vuln/session_management`
- Catalog row: 24
- Effort: M
- Hook: session store
- Test file: `test/vulns/session_management.test.mjs`

## Class and CWE

Session fixation with insufficient session regeneration — CWE-384. CWE-330 is
**not** claimed here: the id itself stays a CSPRNG value, and the weak-randomness
label belongs to `vuln/cryptographic_failures`. What this branch does is accept an
id the client chose.
Family: authentication.

## Intent

Prove that an identifier an attacker can obtain or plant is the same identifier
the application uses after the victim authenticates, so the attacker can act on
the victim's authenticated session.

## Affected surface

- Route: `POST /login` (cookie `theboard_session`)
- Parameter: the session cookie value
- Prerequisites: `anon` profile to mint the pre-login id, then a login request
- Reachability: every request carries the cookie

## Sink

`src/session/store.js` — `regenerate(session, res)`, called from
`src/auth/login.js#completeLogin`. On `main` `regenerate` deletes the old row,
creates a new row with a fresh `crypto.randomBytes(16)` id and writes a new
cookie. The branch turns it into a no-op that keeps the current id and merely
extends `expires_at` to 30 days, and it accepts the id from a `sid` query
parameter when no cookie is present (the shared-link convenience path).

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SESS-2` | Id regenerated on login and privilege change; old row deleted | `regenerate` keeps the id and only touches the expiry |
| `C-SESS-1` (never-adopted clause) | Ids from a CSPRNG, never adopted from an untrusted source | `sid` from the query string is adopted as the session id; the id-generation clause stays intact |

## Minimal diff

Files touched:

- `src/session/store.js` — `regenerate` becomes an expiry update; `start()` accepts
  `?sid=` when the cookie is absent.
- `src/auth/login.js` — no change (the call site stays, which is what makes the
  downgrade invisible to a call-site audit).
- `test/vulns/session_management.test.mjs` — new file.

## Payload sketch

```
1) GET /login                                  -> Set-Cookie: theboard_session=<id0>
2) POST /login  email=regular@test.theboard.local  password=TestPass123
   Cookie: theboard_session=<id0>              -> Set-Cookie: theboard_session=<id0>   (unchanged)
3) GET /admin/boards  with Cookie: theboard_session=<id0>  (as an attacker who learned id0)
```

Expected effect: the same id that was anonymous before login is the authenticated
id afterwards, and the attacker who observed `id0` now holds an authenticated
session.

## Differential oracle

`test/vulns/session_management.test.mjs`:

1. `GET /login` and capture the issued cookie value `id0` (an anonymous session
   row exists in `sessions`).
2. `POST /login` as `regular_rita` with that cookie; capture the response cookie.
3. Assert the response cookie value is still `id0`, and assert the `sessions`
   table now shows `user_id` set on the row with `id = id0` — the identity was
   attached to the pre-existing id.
4. Using a fresh HTTP agent that only carries `id0`, request `/profile` and assert
   the authenticated profile of `regular_rita` is returned.
5. Assert that a session id presented in the query string (`?sid=id0`) is honoured
   by a follow-up request that sends no cookie.

On `main` step 3 must fail: `regenerate` issues a different id, the `id0` row keeps
`user_id NULL` and is deleted, and step 5 gets an anonymous response.

## Must-not-break invariants

- Login, logout and MFA still function; the flash messages and the intended-path
  behaviour are unchanged (`test/integration/auth.test.mjs` green).
- Session expiry sweep still runs and removes rows (asserted inside this test with
  the clock moved forward).
- Cookie flags remain `HttpOnly`/`SameSite=Lax` — the finding is regeneration and
  id provenance, not flags; `test/integration/session.test.mjs` flags assertions
  stay green.
- Only the `c-sess-1` and `c-sess-2` cases in
  `test/integration/session.test.mjs` are skipped; the cookie-attribute cases and
  everything under `c-sess-3` (mid-session ban kill) and `c-sess-4` still run, so
  the shared file is never skipped wholesale.
- The request logger records the **matched route template**, never the raw request
  target, so a fixated id carried in `?sid=` still never reaches
  `var/log/app.log` — assert that here. `C-INFO-3` therefore stays enforced on this
  branch; if a future diff made the logger record raw targets, `C-INFO-3` would have
  to be declared here instead.

## Fidelity to the PHP branch

PHP's form of this class is `session.use_strict_mode=0` plus no
`session_regenerate_id()` on login. The Node form is the same two decisions on
the database-backed store, which is why the store exists in this port
(`docs/07` §2): the id lifecycle is observable in the `sessions` table, giving the
scanner a hard artefact instead of a cookie-string guess.

## Carmentis evidence

Capture the cookie value before and after authentication (identical), the
`sessions` row showing `user_id` attached to the pre-login id, and a successful
authenticated request replayed from a different client with only that id.
Expected label: `CWE-384 / Session Fixation`. False-negative watch-out: many
scanners treat "the cookie is not re-issued" as a non-finding; the row-level
artefact and the cross-client replay are what make the finding reportable.

## Definition of done

- [ ] `test/vulns/session_management.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the listed files.
- [ ] Commit message: `vuln: session_management — keep the session id across authentication and accept it from the query string`.
