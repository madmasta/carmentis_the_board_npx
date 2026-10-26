# xss_config — the protection layer is switched off by configuration

- Branch: `vuln/xss_config`
- Catalog row: 31
- Effort: M
- Hook: core app (headers policy, view environment)
- Test file: `test/vulns/xss_config.test.mjs`

## Class and CWE

Protection mechanism failure — CWE-693, with CWE-79 (the consequence). Family: output
handling.

## Intent

Prove that the finding is different when the **defence** is misconfigured rather than one
handler being wrong: encoding is switched off at the template layer, the second layer
(CSP) is loosened at the same time, and the application's sanitizer is untouched — so
every reflection point gains the same weakness while the code that escapes looks
familiar.

## Affected surface

- Route: `GET /directory?q=` — the reference probe, on the search-summary echo
- Parameter: `q` (query string)
- Prerequisites: `regular` profile
- Reachability: the directory search form; every template is affected by the CSP half,
  and any template that relies on autoescape is affected by the encoding half

## Sink

Two configuration points, not a handler:

- `src/security/headers-policy.js` — the pinned CSP constant becomes
  `default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src * data:; style-src 'self' 'unsafe-inline'`,
  dropping `script-src 'self'`, `frame-ancestors`, `form-action`, `base-uri` and
  `object-src` with it. `X-Frame-Options: DENY` stays — the ported header block is not
  touched (that would reach outside the declared controls), so framing is weakened rather
  than removed, and the branch's test asserts the header is still there.
- `templates/directory.njk` — the search-summary echo opts out of the encoding default
  with the filter the engine provides:

  ```njk
  <span class="q-value">{{ q|safe }}</span>
  ```

  There is no per-template encoding switch in Nunjucks: `{% autoescape false %}` is a
  Jinja tag, and using it here fails at render time with `unknown block tag: autoescape`.
  The environment-wide `autoescape: false` does exist but takes the whole suite with it
  (no template in this port escapes by hand), so the encoding half of this branch is the
  `|safe` fence being applied to a request-derived value — which is precisely the fence
  C-XSS-2 draws.

`src/views.js` keeps `autoescape: true`, and `src/security/markup.js` is untouched: the
sanitizer still escapes stored posts. That combination is the class — the mechanism is
off in the two places a defender would configure, not broken in the code that renders a
post.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XSS-3` | Pinned CSP: `script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'` | the policy constant is replaced with the relaxed one; the framing directive disappears with it, while `X-Frame-Options` (a C-HDR-1 header, not declared away) stays |
| `C-XSS-2` | Output encoding on both exits: autoescape on with `|safe` fenced to the renderer, and the app's own script using inert sinks | `|safe` is applied to `q`, a request-derived value, which is the one use the fence forbids |

The register has probes for both halves. The CSP case compares three response shapes
against `CSP_PINNED` and fails here. The `|safe` case scans every template for a `|safe`
that does not wrap the markup renderer, and fails here on the directory echo. (A third
case — `autoescape: true` in `src/views.js`, no `{% autoescape false %}` anywhere — stays
green on this branch and exists to keep the environment default itself fenced.) The audit
case therefore has real evidence for both declared controls.

## Minimal diff

Files touched:

- `src/security/headers-policy.js` — the relaxed policy constant, and no
  `X-Frame-Options`.
- `templates/directory.njk` — `|safe` on the `q-value` echo of the search term.
- `test/vulns/xss_config.test.mjs` — new file.

No other template changes: every other reflection point keeps relying on autoescape,
which is exactly why the suite still passes and why this reads as a configuration defect
rather than a broken renderer.

## Payload sketch

```
GET /directory?q=%3Cscript%3Edocument.title%3D%27config-xss%27%3C%2Fscript%3E
GET /directory?q=%3Cimg%2Fsrc%3Dx%2Fonerror%3Dconfig-xss%3E
```

Expected effect: the first arrives as a live `<script>` element inside
`<span class="q-value">` — and the shipped CSP now permits inline script, so the
element is not merely present, it is allowed to run. The second injects an element with
an inline handler, likewise permitted by the relaxed policy.

## Differential oracle

`test/vulns/xss_config.test.mjs`:

1. Sign in as `regular_rita` and `GET /directory?q=<script payload>`.
2. Assert the `<span class="q-value">` region *is* `<script>document.title='config-xss'</script>`
   verbatim — the echo is not encoded — while the same value in the search field's `value`
   attribute stays escaped (`&lt;script&gt;document.title`). That pairing is what shows the
   encoding default is intact everywhere except the one fenced filter.
3. Assert `Content-Security-Policy` contains `unsafe-inline` and `unsafe-eval`, and
   **does not** contain `frame-ancestors`, `object-src`, `base-uri` or `form-action` — the
   second layer is gone, which is the configuration half of the finding and the part that
   separates this branch from `vuln/xss_reflected`. Assert `X-Frame-Options: DENY` is still
   emitted, which bounds the change to the declared controls.
4. Assert the unrelated security headers are still emitted (`nosniff`, `Referrer-Policy`,
   COOP, `X-Content-Type-Options`, and `X-Frame-Options`), so the diff is scoped to the
   XSS-relevant policy rather than a general header regression.
5. Assert the defence that was *not* reconfigured still holds: a stored post body is
   still escaped by `markup.js` (`<strong>` renders, `<img …onerror>` does not), and the
   profile page still escapes the username — so encoding is off in one configured place,
   not everywhere.

On `main` step 2 must show `&lt;script&gt;…` and step 3 must show the pinned policy with
`script-src 'self'` and `frame-ancestors 'none'` present.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch. The stored probe is rendered
  through the `markup` filter, and `markup.js` is untouched, so it stays inert text; the
  external-script case is untouched too (that is `vuln/xss_dom`).
- Every other template keeps relying on autoescape, and their suites stay green — enforced
  by `verify:branch`'s baseline run, which is the practical proof that the encoding change
  is a configuration switch and not a renderer defect.
- `C-XSS-1` is not declared: `markup.js` is unchanged, which is what separates this branch
  from `vuln/xss_stored`. The stored-probe invariant in step 5 re-proves it.
- CSRF, sessions, ACL, throttling and the non-CSP headers are untouched and asserted.
- Declared for the run: `C-XSS-3` and `C-XSS-2`.

## Fidelity to the PHP branch

The PHP target's branch turns off the protective layer rather than breaking a handler:
output-encoding defaults and the response's CSP/meta policy are loosened in one place
each. The Node expression is the CSP constant plus the template engine's autoescape
switch — both configuration-shaped, both single lines — which is why the diff is two
production files.

## Carmentis evidence

Capture **both** artefacts: the `q` payload with the live `<script>` element in the
directory response, and the relaxed `Content-Security-Policy` header (plus the missing
`frame-ancestors`/`object-src`/`base-uri`/`form-action` missing from it). Expected labels:
`CWE-693 / Protection Mechanism Failure` together
with `CWE-79 / XSS`.

False-negative watch-out: reporting the header relaxation and the reflection as one
finding under-reports the class — the point is that the mitigation is gone, and that is
what distinguishes this branch from `vuln/xss_reflected`, where the CSP is still strict
and the injected element is not permitted to run. A scanner that only checks the CSP
header will also miss that the directory's search echo is the reflection point; the
payload has to be url-encoded because the raw `<script>` string contains characters a
query parser may otherwise mangle.

## Definition of done

- [ ] `test/vulns/xss_config.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green, with the inert probe gate reported as staying green
  on this branch.
- [ ] One commit off `main`; diff touches only the two listed production files plus the
  test.
- [ ] Commit message: `vuln: xss_config — disable template autoescape and relax the CSP`.

## Correction history

Two mechanism claims turned out not to exist. `{% autoescape false %}` is a Jinja tag, not
Nunjucks: the template compiles and then throws `unknown block tag: autoescape` at render
time, which would have made the branch a 500 rather than a vulnerability. The encoding
half is therefore `{{ q|safe }}` on the directory echo — the same filter the C-XSS-2 fence
governs, which is why that control's register probe fails on this branch.

The first version of this sheet also turned `autoescape` off in `src/views.js` globally and
claimed the rest of the suite would survive "because each template has an explicit
escape". No template in this port escapes by hand — autoescape is the default the whole
suite relies on — so a global switch takes the baseline suite down with it and the branch
stops being a controlled downgrade. The encoding half is therefore a template-scoped
`{% autoescape false %}`, and the sheet's claim about `baseline-inert.test.mjs` failing
here is likewise wrong (the stored post goes through `markup.js`, which this branch does
not touch), so it now says the gate stays green.
