# open_redirect — post-login redirect accepts external targets

- Branch: `vuln/open_redirect`
- Catalog row: 19
- Effort: S
- Hook: core app (intended-path redirect)
- Test file: `test/vulns/open_redirect.test.mjs`

## Class and CWE

URL redirection to untrusted site — CWE-601. Family: request handling.

## Intent

Prove that a caller-supplied redirect target survives the internal-path filter and
becomes a cross-origin `Location`, which is the trust-stealing step in credential
phishing.

## Affected surface

- Route: `GET /login?next=` storing `intended_path`, consumed by `POST /login`
- Parameter: `next` (query string) and the stored `intended_path` in the session
- Prerequisites: `anon` profile, then any successful login
- Reachability: every login form; the app itself creates `?next=` when an
  anonymous visitor hits a protected page

## Sink

`src/http/auth.controller.js` — `consumeIntendedPath()`. On `main` it accepts a
value only when it starts with `/` and not `//`, otherwise `/`. The branch accepts
anything that parses as a URL and any protocol-relative value:

```js
if (path.startsWith('//') || /^https?:\/\//i.test(path)) return path;
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-REDIR-1` | Post-login redirect restricted to internal paths | protocol-relative and absolute-http values are allowed through |

## Minimal diff

Files touched:

- `src/http/auth.controller.js` — the scheme-relative clause in `consumeIntendedPath()`.
- `src/http/headers.js` — the `//` clause removed from `safeRedirectLocation()` (control characters and backslash tricks still throw).
- `test/vulns/open_redirect.test.mjs` — new file.

The absolute-URL clause stays: `http://evil.invalid/x` still collapses to `/` on this branch, and the exploit test asserts that bound, so the finding is the missing-host hop rather than an arbitrary scheme.
- `test/vulns/open_redirect.test.mjs` — new file.

## Payload sketch

```
GET  /login?next=//evil.example/confirm
POST /login
content-type: application/x-www-form-urlencoded

csrf_token=<token>&email=regular@test.theboard.local&password=TestPass123
```

Expected effect: the login response is `303 Location: //evil.example/confirm`.

## Differential oracle

`test/vulns/open_redirect.test.mjs`:

1. `GET /login?next=//evil.example/confirm` to plant the value, then read the
   session row and assert `intended_path` was stored (the plant works on every
   branch).
2. `POST /login` with valid credentials; assert the response is `303` and the
   `Location` header equals `//evil.example/confirm`.
3. Repeat with `next=https://evil.example/login` and assert the same.
4. Repeat with `next=/board/2` and assert the redirect is `/board/2` — legitimate
   internal use is unchanged.

On `main` steps 2 and 3 must return `Location: /` because the filter rewrites
external values, while step 4 must still be `/board/2`.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- Step 4 above is the invariant: internal redirects keep working exactly as on
  `main`, and `test/integration/auth.test.mjs` intended-path assertions for
  internal paths stay green.
- The `intended_path` is still cleared after use (assert it by re-reading the
  session row).
- CSRF is still required on the login POST, and throttling still applies — this
  branch does not touch them.
- `test/security/baseline-inert.test.mjs` passes; only `C-REDIR-1` is skipped.

## Fidelity to the PHP branch

The PHP target's open-redirect branch relaxes the same guard in
`consumeIntendedPath()`. The Node branch relaxes the identical predicate on the
identical parameter, so the two targets present the same probe (`?next=//host`)
and the same evidence (`Location` value).

## Carmentis evidence

Capture the `next` parameter value and the resulting `Location` header pointing
off-origin. Expected label: `CWE-601 / Open Redirect`. False-negative watch-out:
the redirect only materialises after a successful login, so a scanner that probes
`?next=` anonymously and inspects the `GET /login` response sees nothing — the
finding needs the login POST in the chain.

## Definition of done

- [ ] `test/vulns/open_redirect.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: open_redirect — allow protocol-relative and absolute targets in the post-login redirect`.

## Correction history

- `C-HDR-2` is no longer declared removed. The diff does edit
  `safeRedirectLocation`, but it drops only the protocol-relative clause and keeps the
  CR/LF/control-character refusal and the absolute-URL bound, so the register's header-write
  control still holds on this branch (the C-HDR-2 probe stays green, and an audit that let a
  'kept' control be declared away would silently weaken the baseline claim). The catalog row
  names only `C-REDIR-1`, and the sheet now matches it.
