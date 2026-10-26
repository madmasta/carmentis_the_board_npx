# cors_misconfig — origin reflection with credentials

- Branch: `vuln/cors_misconfig`
- Catalog row: 4
- Effort: S
- Hook: core app (response headers)
- Test file: `test/vulns/cors_misconfig.test.mjs`

## Class and CWE

Cross-origin misconfiguration — CWE-942 (permissive cross-domain policy). Family:
request handling.

## Intent

Prove that a cross-origin, credentialed read of authenticated pages is permitted,
so any site the user visits can read their session-bound data.

## Affected surface

- Route: `GET /admin/users`, `GET /profile`, `GET /avatar/:id`
- Parameter: `Origin` request header; `OPTIONS` preflight handling
- Prerequisites: `regular` or `admin` profile for the interesting data
- Reachability: every GET route

## Sink

`src/http/headers.js`. On `main` no `Access-Control-*` header is ever emitted and
there is no `OPTIONS` handler (`C-HDR-3`). The branch adds a permissive CORS
layer, intended to make the app "embeddable":

```js
const origin = req.headers.origin;
if (origin) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
}
```

plus an `OPTIONS` handler answering `Access-Control-Allow-Headers: content-type`
and `Access-Control-Allow-Methods: GET, POST`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-HDR-3` | No CORS headers, no origin reflection, no preflight handler | the reflection block and preflight handler are added |

## Minimal diff

Files touched:

- `src/http/headers.js` — the block above.
- `src/http/router.js` — dispatch `OPTIONS` to the preflight responder.
- `test/vulns/cors_misconfig.test.mjs` — new file.

## Payload sketch

```
GET /admin/users?q= HTTP/1.1
Origin: http://evil.example
Cookie: theboard_session=<admin session id>
```

Expected effect: the response carries `Access-Control-Allow-Origin: http://evil.example`
and `Access-Control-Allow-Credentials: true`, so a browser would release the body
to that origin.

## Differential oracle

`test/vulns/cors_misconfig.test.mjs`:

1. Sign in with the `admin` profile.
2. `GET /admin/users` with `Origin: http://evil.example`; assert the two
   `Access-Control-*` headers with exactly those values.
3. Assert `Access-Control-Allow-Origin` is the literal origin and not `*`, which
   is what makes the finding credentialed rather than merely open, and assert the
   body contains `owner_olivia`.
4. Send an `OPTIONS /admin/users` preflight from the same origin and assert the
   allowed methods and headers come back, confirming the preflight path exists.
5. Repeat step 2 with `Origin: null` (sandboxed iframe case) and assert it is
   echoed too, which is the second half of the misconfiguration.

On `main` this test must fail at step 2: none of the CORS headers are present on
any response, and `OPTIONS` is answered `404`.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The rest of the security header set is untouched — `C-HDR-1` assertions stay
  green, including CSP and `X-Frame-Options: DENY`; this branch is CORS only, so
  clickjacking is not part of the finding.
- CSRF remains enforced: a cross-origin `POST` with a JSON content type is blocked
  by the preflight requirement plus the token check, and the test asserts that a
  credentialed cross-origin state change still cannot happen.
- Same-site cookie flags stay `SameSite=Lax`; the finding is that the response is
  released by policy, not that the cookie is sent cross-site on a GET.
- `test/security/baseline-inert.test.mjs` passes; only `C-HDR-3` is skipped.

## Fidelity to the PHP branch

Same class and same mechanism as the PHP target's CORS branch: reflect the request
origin and allow credentials. The Node target emits the headers from one central
place, matching how PHP sets them in the front controller, so the diff is a single
added block.

## Carmentis evidence

Capture the `Origin` request header, the echoed `Access-Control-Allow-Origin`,
`Access-Control-Allow-Credentials: true`, and the authenticated body the pair
would release. Expected label: `CWE-942 / Permissive CORS policy`.
False-negative watch-out: the scanner must send an `Origin` header — a scan
without one produces a clean response and no finding — and must check the
combination with `Credentials: true`, since reflection alone would be a lower
severity.

## Definition of done

- [ ] `test/vulns/cors_misconfig.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: cors_misconfig — reflect the request origin with credentials allowed`.
