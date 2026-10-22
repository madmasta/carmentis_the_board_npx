# xss_reflected — preview card echoes the submitted value unescaped

- Branch: `vuln/xss_reflected`
- Catalog row: 34
- Effort: S
- Hook: link preview
- Test file: `test/vulns/xss_reflected.test.mjs`

## Class and CWE

Reflected cross-site scripting — CWE-79. Family: output handling.

## Intent

Prove that a value taken from the request and rendered back in the same response
is not encoded, so a crafted link executes in the victim's session.

## Affected surface

- Route: `POST /preview` (`url`) and its rendered result page
- Parameter: `url` (form body); the branch also reflects the parsed hostname
- Prerequisites: `regular` profile (the preview box is behind login)
- Reachability: the "Preview link" form; the attack is a self-posting link or a
  CSRF-assisted POST

## Sink

`templates/preview.njk`. On `main` the template renders
`{{ preview.title }}`, `{{ preview.description }}` and `{{ url }}` with
autoescape, and the extractor never returns markup. The branch wants the preview
card to show the submitted URL "readably", so it renders the host through the safe
filter:

```njk
<p class="preview-host">{{ host|safe }}</p>
```

with `host = new URL(url).hostname` taken verbatim from the submitted value
(the `URL` constructor does not reject a hostname containing markup when the
value is percent-encoded into the authority).

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XSS-2` | Template autoescape on; the safe filter only wraps `markup.render` output | the safe filter is applied to a request-derived value |

## Minimal diff

Files touched:

- `templates/preview.njk` — the `|safe` on `host` above.
- `src/hooks/preview.js` — return `host` from the parsed URL without the
  host-name shape check (`/^[a-z0-9.-]+$/i`) that `main` applies before rendering.
- `test/vulns/xss_reflected.test.mjs` — new file.

## Payload sketch

```
POST /preview
content-type: application/x-www-form-urlencoded

csrf_token=<token>&url=http://%3Cimg%20src%3Dx%20onerror%3D1%3E/
```

Expected effect: the response contains `<img src=x onerror=1>` as an element
inside `<p class="preview-host">`.

## Differential oracle

`test/vulns/xss_reflected.test.mjs`:

1. Sign in as `regular_rita`.
2. `POST /preview` with the payload; assert `200`.
3. Assert the response contains `<p class="preview-host"><img src=x onerror=1></p>`
   — the element is live, not escaped.
4. Assert the CSP header is still present with `script-src 'self'` on this
   response, isolating the finding to the encoding defect.
5. Assert a normal URL still previews correctly (`http://example.com/x` renders
   `example.com`), so the card itself works and the defect is encoding only.

On `main` step 3 must fail: the host fails the shape check and the request is
answered `400 That is not a previewable address`; if the shape check were
bypassed, autoescape would render `&lt;img`.

## Must-not-break invariants

- Step 5 above is the invariant, plus the rest of the preview behaviour:
  scheme allowlist, address-class rejection and the redirect refusal all stay
  enforced (`test/unit/hook-preview.test.mjs` green), so this branch is not also
  `ssrf`.
- Extracted title and description remain escaped (the XSS is on the host echo
  only) — assert with a payload inside a stubbed page title.
- Stored content is unaffected, so `test/security/baseline-inert.test.mjs` must
  still pass on this branch (unlike the stored/DOM branches).
- Only `C-XSS-2` is skipped.

## Fidelity to the PHP branch

The PHP reflected-XSS branch echoes `$_GET`/`$_POST` data into the page without
`htmlspecialchars`. The Node form is one template filter away, which is exactly
how the class appears in a Nunjucks app; the parameter position differs (POST
body rather than query string) because the preview capability is a POST in this
application, and the branch adds a hostname echo so the reflected value lands in
an HTML text context.

## Carmentis evidence

Capture the `url` parameter with the percent-encoded host payload and the live
`<img …onerror>` element inside `p.preview-host`. Expected label:
`CWE-79 / Reflected XSS`. False-negative watch-out: the value must be
percent-encoded so it survives both the form encoding and `new URL()` parsing;
a literal `<` in the authority makes `URL` throw and the app returns a clean
`400`, which reads as "handled".

## Definition of done

- [ ] `test/vulns/xss_reflected.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green and `test/security/baseline-inert.test.mjs` passes.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: xss_reflected — render the preview host through the safe filter`.
