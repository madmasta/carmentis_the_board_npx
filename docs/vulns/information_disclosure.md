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

`src/server.js` — the error handler and the `/health` handler. On `main`
`/health` returns exactly `{"ok":true}` and the error handler renders the generic
500 view with the trace written only to `var/log/app.log`, unless `APP_DEBUG=1`.
The branch prints diagnostics for support:

```js
if (path === '/health') {
  json(res, { ok: true, version: process.version, cwd: process.cwd(),
              uptime: process.uptime(), env: process.env, argv: process.argv });
}
...
if (req.query.debug === '1' || Env.bool('APP_DEBUG', false)) {
  html(res, 500, `<pre>${String(err.stack)}</pre>`);
}
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-INFO-1` | Generic 500 page; stack traces never in a response | `?debug=1` renders the stack |
| `C-DATA-1` | Configuration values never rendered or logged | the whole `process.env` is returned by `/health` |

## Minimal diff

Files touched:

- `src/server.js` — the `/health` expansion and the `?debug=1` branch in the error
  handler.
- `src/http/thread.controller.js` — delete the `if (thread === null) notFound(res)`
  check in `show`, providing a request that reliably throws.
- `test/vulns/information_disclosure.test.mjs` — new file.

## Payload sketch

```
GET /health
GET /thread/999999?debug=1&boom=1
```

(The branch also removes the null check in `src/http/thread.controller.js#show`,
so an unknown id dereferences `undefined` and raises a `TypeError` — a realistic
way to reach the error path, and the third file in the diff.)

Expected effect: `/health` returns the environment including `DB_PASS`, and the
error response contains `at ` stack frames with absolute file paths.

## Differential oracle

`test/vulns/information_disclosure.test.mjs`:

1. Set `process.env.THEBOARD_SECRET_SENTINEL = 'sentinel-9f31c2'` before the
   request.
2. `GET /health` and assert the body contains `sentinel-9f31c2`, `DB_PASS`, and
   `process.version` — configuration disclosure.
3. Trigger the throwing route with `?debug=1` and assert the response body
   contains `at ` followed by a path segment from this repository, and that it
   contains the exception class name.
4. Assert that the same route without `?debug=1` returns the generic view
   (`Something went wrong. The error has been logged.`), so the disclosure is
   reachable without any flag — the query parameter is not the only path in.
5. Assert the log file still received the trace (the branch did not move it).

On `main` step 2 returns exactly `{"ok":true}` and step 3 returns the generic view
with no `at ` frames.

## Must-not-break invariants

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
