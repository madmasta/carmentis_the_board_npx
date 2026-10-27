# security_misconfig — the shipped defaults are the vulnerability

- Branch: `vuln/security_misconfig`
- Catalog row: 22
- Effort: M
- Hook: core app (configuration and static handling)
- Test file: `test/vulns/security_misconfig.test.mjs`

## Class and CWE

Security misconfiguration — CWE-16, with CWE-215 (information exposure through an
error message). Family: configuration. The catalog row lists the same two IDs; a
third label would double-count the verbose-error evidence.

## Intent

Prove that the application can be started straight from its own shipped
configuration and be unsafe without a single line of application logic changing —
the class a "just deploy it" reviewer is supposed to catch.

## Affected surface

- Route: app-wide — `POST /login` (guessing is unlimited) and any route that can throw
  (error pages verbose) — plus `GET /assets/` (directory listing) and
  `GET /server-info` (runtime and configuration inventory)
- Parameter: none
- Prerequisites: `anon` profile
- Reachability: everything, because the defaults are global

## Sink

`src/config/defaults.js` (the fallback map behind `src/config/env.js`), `.env.example`
(the file a fresh checkout copies), and the static/route surface. On `main` the shipped
values are `APP_DEBUG=0`, `LOGIN_THROTTLE_DISABLED=0`, `HOST=127.0.0.1`, there is no
directory listing, and there is no diagnostics route. The branch ships the unsafe
values and the two diagnostic surfaces:

```js
// src/config/defaults.js — what a bare `npm start` runs with
APP_DEBUG: '1',
LOGIN_THROTTLE_DISABLED: '1',
HOST: '0.0.0.0',
```

`.env.example` carries the same three values, because on this target the file beats the
defaults (docs/01 §3: real environment > `.env` > `DEFAULTS`), so a deployment that
copies the template lands in the same place.

```js
// src/http/server.js — serveStatic() falls through to a directory index
async function listDirectory(res, path) {
  if (path !== '/assets/' && path !== '/assets') return false;
  const dir = join(root(), 'public', 'assets');
  const items = readdirSync(dir).map((name) => `<li><a href="${name}">${name}</a> (${…})</li>`);
  res.end(`<!DOCTYPE html>…<h1>Index of /assets/</h1><ul>${items}</ul>…`);
  return true;
}

// src/http/page.controller.js — registered in src/routes.js as
// { method: 'GET', path: '/server-info', guard: 'anon', handler: page.serverInfo }
export function serverInfo(ctx) {
  json(ctx.res, {
    node: process.version, platform: process.platform, arch: process.arch,
    pid: process.pid, uptime: process.uptime(),
    config: /* every key in DEFAULTS, secret-shaped values masked to two characters */
  });
}
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-AUTH-3` (shipped-default clause) | Throttle enforced; kill switch honoured only with `APP_DEBUG=1` and it announces itself | both defaults ship enabled, so brute forcing is unlimited by configuration; the guard logic and its banner stay in place |
| `C-INFO-1` (`APP_DEBUG` default clause) | Generic error page unless explicitly debugging | `APP_DEBUG` now defaults to `1`, so traces render by default; the trace-to-log behaviour is untouched |
| `C-INFO-2` (listing and diagnostics clause) | Only allowlisted static paths served, no listing | `/assets/` lists files and `/server-info` exists; the `/.git`, `/uploads` and containment clauses stay enforced and their cases keep running |

## Minimal diff

Files touched:

- `src/config/defaults.js` — the three default values above.
- `.env.example` — `APP_DEBUG=1`, `LOGIN_THROTTLE_DISABLED=1`, `HOST=0.0.0.0`.
- `src/http/server.js` — the `listDirectory()` fallback in `serveStatic()`.
- `src/http/page.controller.js` — the `serverInfo` handler: runtime facts plus the
  loaded configuration keys, with secret-shaped values masked to two characters.
- `src/routes.js` — register `{ method: 'GET', path: '/server-info', guard: 'anon',
  handler: page.serverInfo }`. Registration is not optional: `C-ACL-4` makes
  the router refuse to start for any handler reached without a guard entry, so a
  diff that only touches `server.js` yields an unreachable route and the exploit
  test cannot pass.
- `test/vulns/security_misconfig.test.mjs` — new file.

## Payload sketch

```
GET /server-info
GET /assets/
POST /login      (30 wrong passwords in 2 minutes, all answered "Invalid email or password.")
``` plus the fault probe below.

The verbose-error half is probed through the deterministic seam `docs/01` §5
defines: the test arms `src/lib/faults.js#setTestFault(() => new Error('probe'))`
and issues an ordinary `GET /` request. `GET /thread/999999` is **not** a usable
probe — that route answers `404` for a missing thread on every branch, so it would
show a generic page on both sides.

Expected effect: unlimited password guessing, an inventory of the runtime, a file
listing, and traces by default — with no application code path altered.

## Differential oracle

`test/vulns/security_misconfig.test.mjs`:

1. Measure the shipped configuration, not a cleared key: read `.env.example`, apply
   its values for `APP_DEBUG`, `LOGIN_THROTTLE_DISABLED` and `HOST` over the
   worktree's own `.env` (which carries this suite's database credentials and has to
   stay), `load()` the merged file through `src/config/env.js`, and clear those three
   keys from the real environment so the shipped configuration decides. The same
   helper backs the three control probes in `test/security/controls.test.mjs`, and the
   previous path is restored through `loadedPath()` afterwards.
2. `GET /server-info` returns `200` with `process.version` and
   `process.platform`.
3. `GET /assets/` returns a listing containing `app.js` and `style.css`.
4. Send 12 wrong-password logins for `regular@test.theboard.local` inside 60 s and
   assert none of them is throttled (all carry the generic flash), then assert the
   page body contains the `BRUTE-FORCE PROTECTION IS OFF` banner and that
   `var/log/app.log` carries the `[SECURITY] login throttle BYPASSED` lines — the
   guards still announce themselves, which is the point: the configuration is what
   is wrong.
5. Arm `setTestFault`, `GET /`, and assert the 500 body contains a stack frame and
   the fault name — with no query parameter or special route required. Then
   `setTestFault(null)`.
6. Restore `APP_DEBUG=0`, `LOGIN_THROTTLE_DISABLED=0` and `HOST=127.0.0.1` into the
   environment and assert the throttle fires and the armed fault renders the generic
   500 view again.

On `main` this test must fail at steps 2-5: `/server-info` is `404`, `/assets/` is
`404`, the twelve attempts do **not** all get the generic flash — with
`LOGIN_MAX_ATTEMPTS=5` and three failures already seeded for that address by the
fixture (`docs/02` §6 invariant 9), the throttle trips partway through the loop —
and the same armed fault renders the generic 500 view. Do not assert on a specific
attempt index; assert that at least one attempt in the window is throttled. Step 6
(restoring the keys) behaves the same on both sides.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The kill switch's four guards must all still fire (step 4 asserts the banner and
  the log line), so the branch is a configuration change, not a removal of the
  guard logic.
- Step 6 above is what makes this a misconfiguration rather than a logic defect:
  the secure behaviour is one environment key away, and the branch proves it.
- Cases in `test/unit/logging.test.mjs`, `test/integration/static.test.mjs` and
  `test/integration/pipeline.test.mjs` that do not carry the `c-info-1`, `c-info-2` or
  `c-auth-3` slugs stay green; only those slugs' cases are skipped — including
  `pipeline.test.mjs#has no static directory handler — c-info-2 the static root never
  lists`, the case this branch turns red.
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
- [ ] One commit off `main`; diff touches only the five listed files.
- [ ] Commit message: `vuln: security_misconfig — ship debug, throttle-off and exposed diagnostics as the defaults`.

## Correction history

- The file list named `config/defaults.js`; the real path is `src/config/defaults.js`,
  and the `/server-info` handler is a new export in `src/http/page.controller.js`
  (`page.serverInfo`), not part of `src/http/server.js`, which only gains the
  directory-listing fallback.
- Clearing `APP_DEBUG` / `LOGIN_THROTTLE_DISABLED` from `process.env` is **not** enough
  to measure what the project ships: on this target a `.env` beats `DEFAULTS`
  (docs/01 §3), and every worktree carries a `.env` with the safe values. The oracle now
  applies `.env.example`'s values over the worktree file and loads that — which is what
  "deploy it straight from the box" means. Without that change the three control probes
  stayed green on the branch and the branch-contract audit
  (`test/security/controls.test.mjs#a control the sheet declares removed is really
  removed`) correctly refused the branch.
- The C-INFO-2 proof set gained
  `test/integration/pipeline.test.mjs#has no static directory handler — c-info-2 the
  static root never lists`, so the declaration skips exactly the case this branch
  breaks.
