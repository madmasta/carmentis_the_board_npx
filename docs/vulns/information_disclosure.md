# information_disclosure — environment and stack traces in responses

- Branch: `vuln/information_disclosure`
- Catalog row: 12
- Effort: S
- Hook: core app (health endpoint, error page)
- Test file: `test/vulns/information_disclosure.test.mjs`

## Class and CWE

Exposure of sensitive information through an error message and through a
diagnostic endpoint — CWE-200, CWE-215. Family: configuration and supply chain.

## Intent

Prove that the application hands an attacker its configuration and internals,
which is what turns other classes into full compromise and what a scanner
independently reports.

## Affected surface

- Route: `GET /health` (expanded) and any route that throws, plus
  `GET /health?debug=1`
- Parameter: none required; `debug` widens it
- Prerequisites: `anon` profile
- Reachability: `/health` is documented in the README and linked by the smoke test

## Sink

`src/routes.js` — the inline `health(ctx)` handler behind `GET /health`, and
`src/views.js` — `renderError()`, which is where the trace gate actually lives
(`src/http/server.js` only supplies the stack). On `main` `/health` returns exactly
`{"ok":true}`, and `renderError()` renders the trace only when `bool('APP_DEBUG')`
is true, with the stack written to `var/log/app.log` in every mode. The branch prints
diagnostics for support:

```js
// src/routes.js
json(ctx.res, {
  ok: true, version: process.version, platform: process.platform,
  cwd: process.cwd(), uptime: process.uptime(), argv: process.argv, env: process.env,
});

// src/views.js — the gate itself widens
const debugging = bool('APP_DEBUG', false) || traceRequested === true;

// src/http/server.js — the caller decides from the request
renderError(res, 500, 'Something went wrong. The error has been logged.', {
  trace: error?.stack ?? String(error),
  traceRequested: String(req.query?.debug ?? '') === '1',
});
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-INFO-1` | Generic 500 page; stack traces never in a response | `?debug=1` renders the stack |
| `C-DATA-1` | Configuration values never rendered or logged | the whole `process.env` is returned by `/health` |

## Minimal diff

Files touched:

- `src/routes.js` — the `/health` expansion above.
- `src/views.js` — `renderError()` takes a `traceRequested` flag and widens its
  `APP_DEBUG` gate with it. This is the control: passing a trace from the caller is
  not enough on `main`, because the view discards it.
- `src/http/server.js` — supplies `trace` unconditionally and sets `traceRequested`
  from `?debug=1`.
- `test/vulns/information_disclosure.test.mjs` — new file.

## Payload sketch

```
GET /health
GET /?debug=1          (with a fault armed through src/lib/faults.js)
```

The throwing request is produced by the deterministic fault seam
(`src/lib/faults.js#setTestFault`, docs/01 §5) rather than by breaking a handler: the
same seam the `C-INFO-1` proofs use, so the differential is the rendering gate and
nothing else.

Expected effect: `/health` returns the environment including `DB_PASS`, and the
error response contains `at ` stack frames with absolute file paths.

## Differential oracle

`test/vulns/information_disclosure.test.mjs`:

1. Set `process.env.THEBOARD_SECRET_SENTINEL = 'sentinel-9f31c2'` before the
   request.
2. `GET /health` and assert `env.THEBOARD_SECRET_SENTINEL` equals the planted
   sentinel, that `version` equals `process.version`, that `cwd` equals
   `process.cwd()`, and that `env` has more than ten keys — configuration
   disclosure. There is no `DB_PASS` in `process.env` on this target: the app's
   configuration loader does not publish it to the environment, so the sentinel is
   the planted witness.
3. Arm the fault and request `/?debug=1`: assert the body carries the fault message
   and a frame matching `at …server.js`.
4. Assert that the same request **without** `?debug=1` returns the generic view
   (`Something went wrong. The error has been logged.`) with no `at ` frames. This is
   a scoping control, green on both sides: the disclosure is opt-in per request, so
   the finding is that a request can ask for internals at all. `main` refuses —
   `test/integration/error-handling.test.mjs#c-info-1 the trace is gated on the
   configuration value alone`.
5. Assert the log file still received the trace (the branch did not move it).

On `main` step 2 returns exactly `{"ok":true}` — the same shape the pipeline smoke
case pins, `test/integration/pipeline.test.mjs#answers /health with json and the full
header set — c-data-1 the health body carries nothing else — and step 3 returns the
generic view with no `at ` frames.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- `/health` still answers `200` with a body that parses as JSON and contains
  `"ok":true` (the smoke test in `test/integration/static.test.mjs` stays green).
- Error status codes are unchanged: a throwing route is still `500`, a missing
  resource is still `404`.
- `C-DATA-1`'s other clauses hold: session ids and password hashes still never
  appear in `/health` output; assert that inside this test.
- `test/security/baseline-inert.test.mjs` passes; only `C-INFO-1` and `C-DATA-1`
  are skipped.

## Fidelity to the PHP branch

Same class as the PHP target's disclosure branch, which turns on
`display_errors` and dumps `phpinfo()`-style data. The Node form is the direct
equivalent: an env dump on a documented endpoint and a stack trace on demand.

## Carmentis evidence

Capture the `/health` JSON body with the sentinel value and the 500 response
containing file paths and frames. Expected label: `CWE-200 / Information
Disclosure` with `CWE-215 / Verbose Error`. False-negative watch-out: the
environment dump is only valuable because the test plants a sentinel; in a real
run the scanner should be given a marker value in the target environment,
otherwise the evidence is a list of key names.

## Definition of done

- [ ] `test/vulns/information_disclosure.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: information_disclosure — dump the environment on /health and render stack traces on request`.

## Correction history

- The sheet put the `/health` handler in `src/server.js`. It is the inline
  `health(ctx)` in `src/routes.js`, and the trace gate is in
  `src/views.js#renderError`, not in the error handler: passing `trace` from
  `src/http/server.js` changes nothing on `main`, and that gate is exactly the control
  this branch removes.
- The third diff file (`src/http/thread.controller.js`, deleting the null check to
  force a `TypeError`) was dropped. The deterministic fault seam already provides a
  throwing request, so the branch no longer touches a handler and the diff stays
  inside the three files above.
- The oracle's "reachable without any flag" claim was wrong: `?debug=1` is the only
  new path in, and step 4 is now a scoping control rather than a second disclosure.
- Step 2 named `DB_PASS`; the Node configuration loader keeps database settings out of
  `process.env`, so the planted sentinel plus `version`/`cwd`/`argv` is the witness.
