# security_misconfig — the shipped defaults are the vulnerability

- Branch: `vuln/security_misconfig`
- Catalog row: 22
- Effort: M
- Hook: core app (configuration and static handling)
- Test file: `test/vulns/security_misconfig.test.mjs`

## Class and CWE

Security misconfiguration — CWE-16, with CWE-215 (verbose errors) and CWE-219
(storage of code with debug/exposed endpoints). Family: configuration and supply
chain.

## Intent

Prove that the application can be started straight from its own shipped
configuration and be unsafe without a single line of application logic changing —
the class a "just deploy it" reviewer is supposed to catch.

## Affected surface

- Route: app-wide (`/login` throttling off, error pages verbose), plus
  `GET /assets/` (directory listing) and `GET /server-info`
- Parameter: none
- Prerequisites: `anon` profile
- Reachability: everything, because the defaults are global

## Sink

`config/defaults.js` (the fallback map used by `src/config/env.js`),
`.env.example`, and the static handler. On `main` the defaults are
`APP_DEBUG=0`, `LOGIN_THROTTLE_DISABLED=0`, no directory listing, and no
diagnostic route. The branch changes the shipped defaults and the template
configuration:

```js
export const DEFAULTS = { APP_DEBUG: '1', LOGIN_THROTTLE_DISABLED: '1', HOST: '0.0.0.0', … };
```

adds a `GET /server-info` route returning `process.version`, `process.platform`,
the loaded configuration keys with values masked to their first two characters,
and enables a directory listing for `/assets/`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-AUTH-3` | Throttle enforced; kill switch honoured only with `APP_DEBUG=1` and it announces itself | both defaults ship enabled, so brute forcing is unlimited by configuration |
| `C-INFO-1` | Generic error page unless explicitly debugging | `APP_DEBUG` now defaults to `1`, so traces render by default |
| `C-INFO-2` | Only allowlisted static paths served, no listing | `/assets/` lists files and `/server-info` exists |

## Minimal diff

Files touched:

- `config/defaults.js` — the three default values above.
- `.env.example` — `APP_DEBUG=1`, `LOGIN_THROTTLE_DISABLED=1`, `HOST=0.0.0.0`.
- `src/http/server.js` — directory-listing branch for `/assets/` and the
  `/server-info` route.
- `test/vulns/security_misconfig.test.mjs` — new file.

## Payload sketch

```
GET /server-info
GET /assets/
POST /login      (30 wrong passwords in 2 minutes, all answered "Invalid email or password.")
GET /thread/999999        (stack frames in the body because APP_DEBUG defaults to 1)
```

Expected effect: unlimited password guessing, an inventory of the runtime, a file
listing, and traces by default — with no application code path altered.

## Differential oracle

`test/vulns/security_misconfig.test.mjs`:

1. Run the test with **no** `.env` values for the three keys (the helper deletes
   them from the environment) so the shipped defaults decide.
2. `GET /server-info` returns `200` with `process.version` and
   `process.platform`.
3. `GET /assets/` returns a listing containing `app.js` and `style.css`.
4. Send 12 wrong-password logins for `regular@test.theboard.local` inside 60 s and
   assert none of them is throttled (all carry the generic flash), then assert the
   page body contains the `BRUTE-FORCE PROTECTION IS OFF` banner and that
   `var/log/app.log` carries the `[SECURITY] login throttle BYPASSED` lines — the
   guards still announce themselves, which is the point: the configuration is what
   is wrong.
5. `GET /thread/999999` and assert the 500 page contains stack frames with no
   query parameter required.

On `main` this test must fail at every step: `/server-info` is `404`, `/assets/` is
`404`, the tenth wrong password returns the throttled flash, and the 500 page is
generic.

## Must-not-break invariants

- The kill switch's four guards must all still fire (step 4 asserts the banner and
  the log line), so the branch is a configuration change, not a removal of the
  guard logic.
- Setting `APP_DEBUG=0` and `LOGIN_THROTTLE_DISABLED=0` in the environment restores
  the secure behaviour — assert it as a final step, because "it can be turned off"
  is what makes this a misconfiguration rather than a logic defect.
- The rest of `test/unit/logging.test.mjs` and `test/integration/static.test.mjs`
  stay green apart from the two skipped controls.
- `test/security/baseline-inert.test.mjs` passes; `C-AUTH-3`, `C-INFO-1` and
  `C-INFO-2` are skipped only for their default-value clauses.

## Fidelity to the PHP branch

The PHP target's misconfiguration branch ships a `.env.example` with
`APP_DEBUG=1` and the throttle switch on, plus verbose errors. The Node target
ships the same three defaults in the file **and** in `config/defaults.js`, because
in Node the fallback map is what a bare `npm start` uses when nobody copied a
`.env` — the more common way to leave a misconfiguration in place.

## Carmentis evidence

Capture `/server-info`'s body, the `/assets/` listing, the absence of a throttle
response after repeated failures, and the banner text as the app's own admission.
Expected label: `CWE-16 / Security Misconfiguration`. False-negative watch-out:
the run must not export `APP_DEBUG=0` itself — the harness sets
`THEBOARD_VULN=vuln/security_misconfig` and must leave the three keys unset, or the
test and the scanner will both measure the restored secure defaults.

## Definition of done

- [ ] `test/vulns/security_misconfig.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the four listed files.
- [ ] Commit message: `vuln: security_misconfig — ship debug, throttle-off and exposed diagnostics as the defaults`.
