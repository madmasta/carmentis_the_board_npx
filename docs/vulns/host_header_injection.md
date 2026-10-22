# host_header_injection — reset link built from the Host header

- Branch: `vuln/host_header_injection`
- Catalog row: 10
- Effort: S
- Hook: password reset
- Test file: `test/vulns/host_header_injection.test.mjs`

## Class and CWE

Host header injection leading to credential-link poisoning — CWE-640, with
CWE-200 (trust boundary). Family: request handling.

## Intent

Prove that a request-supplied `Host` value is trusted when building an absolute
URL that is handed to a user by e-mail, so the reset link can be pointed at an
attacker host and the token delivered there.

## Affected surface

- Route: `POST /forgot-password`
- Parameter: `Host` request header (also `X-Forwarded-Host` on this branch)
- Prerequisites: `anon` profile
- Reachability: the forgot-password form

## Sink

`src/security/jwt.js` — `resetUrl(token)`. On `main` the absolute URL is built
from `APP_URL` only, and the request pipeline rejects a `Host` that is not in the
configured allowlist (`HOST_ALLOWLIST`, default: the `APP_URL` host and
`localhost`). The branch builds the URL from the request host and accepts
`X-Forwarded-Host` when present:

```js
const base = req.headers['x-forwarded-host'] ?? req.headers.host;
return `http://${base}/reset-password?token=${token}`;
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-COOKIE-1` | Request-supplied host never used to build absolute URLs, cookies or links | the reset link is built from the header, and the host allowlist check is removed |

## Minimal diff

Files touched:

- `src/security/jwt.js` — `resetUrl` takes the request and uses the header base.
- `src/http/request.js` — delete the `hostIsAllowed()` check.
- `test/vulns/host_header_injection.test.mjs` — new file.

## Payload sketch

```
POST /forgot-password
content-type: application/x-www-form-urlencoded
host: evil.example
x-forwarded-host: pw.evil.example

csrf_token=<token>&email=owner@test.theboard.local
```

Expected effect: the mail record's link is
`http://pw.evil.example/reset-password?token=<real token>`.

## Differential oracle

`test/vulns/host_header_injection.test.mjs`:

1. Point the mailer at a temp mail log.
2. Send the payload with the spoofed `X-Forwarded-Host` and the spoofed `Host`.
3. Read the last mail record and assert the link starts with
   `http://pw.evil.example/reset-password?token=` and that a token follows it.
4. Repeat with only a spoofed `Host: evil.example` and assert the link uses
   `evil.example`, proving the plain header path too.
5. Assert that a real reset link requested with the default host still works end
   to end (request, extract token, reset the password of a throwaway account).

On `main` steps 3 and 4 must fail: the link uses the `APP_URL` host
(`http://localhost:8088` in the test environment) and the request with an
allowlist-violating `Host` is answered `400 Unknown host`.

## Must-not-break invariants

- Step 5 above is the invariant: the legitimate reset flow is unchanged.
- Session cookie naming and flags are untouched — the finding is link poisoning,
  not cookie scope; `test/integration/session.test.mjs` stays green.
- Throttling, CSRF and MFA remain enforced on this route.
- `test/security/baseline-inert.test.mjs` passes; only `C-COOKIE-1` is skipped.

## Fidelity to the PHP branch

Same class and same primitive as the PHP target's host-header branch, which
interpolates `$_SERVER['HTTP_HOST']` into the reset link. Node exposes the same
trap through `req.headers.host`, plus the `X-Forwarded-Host` variant that the
branch also enables.

## Carmentis evidence

Capture the spoofed header and the absolute link in the resulting mail record.
Expected label: `CWE-640 / Host Header Injection in a password reset link`.
False-negative watch-out: the evidence is the mail log entry, not the response
body, which is deliberately generic; and the token must not be re-requested after
the probe, because a second request overwrites the link the scanner is trying to
demonstrate.

## Definition of done

- [ ] `test/vulns/host_header_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: host_header_injection — build the reset link from the request host`.
