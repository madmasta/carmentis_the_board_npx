# xss_config — the protection mechanism itself is reconfigured away

- Branch: `vuln/xss_config`
- Catalog row: 31
- Effort: M
- Hook: core app (headers policy, view environment)
- Test file: `test/vulns/xss_config.test.mjs`

## Class and CWE

Protection mechanism failure — CWE-693, with CWE-116 (improper encoding). Family:
output handling.

## Intent

Prove that the application's defence layer has been switched off by configuration
rather than by a coding mistake in one handler, so every reflection point is
simultaneously exposed and the second layer (CSP) no longer limits the impact.

## Affected surface

- Route: `GET /directory?q=` (reference probe), and every other template that
  relies on autoescape
- Parameter: `q` (query string)
- Prerequisites: `regular` profile
- Reachability: the directory search form

## Sink

Two configuration points, not a handler:

- `src/security/headers-policy.js` — the CSP string becomes
  `default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src * data:` with
  `frame-ancestors` removed and no `form-action`/`base-uri`/`object-src`.
- `src/views.js` — the Nunjucks environment is created with
  `autoescape: false`, and templates are expected to escape by hand. The directory
  template's search-term echo is one of the places the manual escape was forgotten:

```njk
<span class="q-value">{{ q }}</span>
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XSS-3` | CSP with `script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'` | the policy is relaxed to allow inline script and eval, and frame-ancestors is dropped |
| `C-XSS-2` | Template autoescape on; the safe filter only wraps markup output | autoescape is disabled globally and one echo has no manual escape |

## Minimal diff

Files touched:

- `src/security/headers-policy.js` — the relaxed CSP above.
- `src/views.js` — `autoescape: false` in the environment constructor.
- `templates/directory.njk` — remove the manual `|e` from the search-term echo
  (the only manual-escape removal; every other template keeps its explicit
  escapes so the rest of the suite still passes).
- `test/vulns/xss_config.test.mjs` — new file.

## Payload sketch

```
GET /directory?q=%3Cscript%3Edocument.title%3D%27config-xss%27%3C%2Fscript%3E
GET /directory?q=%22%20onmouseover%3Dalert(1)%20x%3D%22
```

Expected effect: the first renders a live `<script>` element in the page, which
the shipped CSP now permits; the second injects an attribute into the search
input's value.

## Differential oracle

`test/vulns/xss_config.test.mjs`:

1. `GET /directory?q=<payload>` as `regular_rita`.
2. Assert the response contains the `<script>document.title='config-xss'</script>`
   element verbatim (no `&lt;script`).
3. Assert the `Content-Security-Policy` header contains `unsafe-inline` and
   `unsafe-eval` and **does not** contain `frame-ancestors`, and that
   `X-Frame-Options` has been removed along with it — the second layer is gone,
   which is the configuration half of the finding.
4. Assert the other security headers (`nosniff`, `Referrer-Policy`, COOP) are
   still present, so the diff is scoped to the XSS-relevant policy.
5. Assert a second reflection point that still escapes by hand (the profile
   username) is not exploitable, proving autoescape is off globally while most
   templates survived because of their explicit escapes — this is what makes it a
   configuration defect rather than a per-handler bug.

On `main` step 2 must render `&lt;script&gt;…` escaped and step 3 must show the
full policy including `script-src 'self'` and `frame-ancestors 'none'`.

## Must-not-break invariants

- The other 16 templates keep working and their suites stay green, because each
  has an explicit escape at the reflection points the tests cover — the branch is
  only acceptable if the rest of the suite passes, which is enforced by
  `verify:branch`.
- `test/security/baseline-inert.test.mjs` **must fail** on this branch (the
  sanitizer probe post is rendered through a template whose escape was removed by
  the autoescape change), which the harness checks as the secondary differential.
- CSRF, sessions, ACL and headers other than CSP stay intact and are asserted.
- `C-XSS-1` is **not** skipped: `markup.js` is unchanged on this branch, which is
  what separates it from `vuln/xss_stored`.

## Fidelity to the PHP branch

Same class as the PHP target's XSS-by-configuration branch: the sanitizer is left
alone and the protective layer (CSP, output encoding default) is reconfigured.
The Node-specific expression is the template engine's global `autoescape` flag and
the CSP string constant, both single places, which is why the diff is three files.

## Carmentis evidence

Capture the `q` payload with the live `<script>` element in the response, and the
relaxed `Content-Security-Policy` header values. Expected label:
`CWE-693 / Protection Mechanism Failure` together with `CWE-79 / XSS`.
False-negative watch-out: a scanner that reports the header relaxation and the
reflection as one finding under-reports; the two artefacts must both be captured,
because the class is precisely "the mitigation is gone", and it distinguishes this
branch from `vuln/xss_reflected`, where CSP is still strict.

## Definition of done

- [ ] `test/vulns/xss_config.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `test/security/baseline-inert.test.mjs` fails on this branch and passes on `main`.
- [ ] `npm run verify:branch` green otherwise.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: xss_config — disable template autoescape and relax the CSP`.
