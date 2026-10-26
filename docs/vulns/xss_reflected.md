# xss_reflected — the preview form echoes the submitted value through the safe filter

- Branch: `vuln/xss_reflected`
- Catalog row: 34
- Effort: S
- Hook: link preview
- Test file: `test/vulns/xss_reflected.test.mjs`

## Class and CWE

Reflected cross-site scripting — CWE-79. Family: output handling.

## Intent

Prove that a value taken from the request and rendered back on the same page is
encoded, and that the encoding is what holds: remove it and the caller breaks out of
the attribute they were supposed to be sitting inside.

## Affected surface

- Route: `POST /preview` (`url`), answered by the same page that carries the form
- Parameter: `url` (form body), echoed back into the form's value attribute
- Prerequisites: `regular` profile (the preview box is behind login) and a CSRF token
- Reachability: the "Preview link" form on the profile page; the attack is a
  self-posting link or a CSRF-assisted POST

## Sink

`templates/preview.njk`, at the form's own echo: `value="{{ url }}"`. Whatever the
caller posted comes back on the next render — the preview is a POST that re-displays
the same screen — and on `main` autoescape turns it into attribute text. The branch
makes the field "show the address as typed":

```njk
<input type="url" name="url" required value="{{ url|safe }}">
```

A `"` in the submitted value then closes the attribute and the remainder is parsed as
markup. This is the reachable reflection point in this application; the hostname is
not. Node's `new URL()` rejects an authority containing markup — both
`http://%3Cimg%3E/` and `http://<img>/` throw before any host reaches a template — so
the earlier draft of this sheet, which echoed a parsed hostname through `|safe`, is
unreachable in either direction and has been replaced.

Two constraints shape the payload, and both come from `parseTarget`:

- it rejects any value containing whitespace, so the payload uses `/` where HTML would
  take a space (`<img/src=x/onerror=…>` is a valid element);
- a value it rejects is answered by a **plain-text error page that echoes nothing**. The
  payload therefore has to be a well-formed URL that merely fails to resolve, so the
  preview screen re-renders and the echo happens.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XSS-2` | Template autoescape on; the `safe` filter only wraps `markup.render` output | the `safe` filter is applied to `url`, a value taken straight from the request |

## Minimal diff

Files touched:

- `templates/preview.njk` — `{{ url }}` becomes `{{ url|safe }}` in the form field.
- `test/vulns/xss_reflected.test.mjs` — new file.

`src/hooks/preview.js` is untouched: the scheme allowlist, the resolver gate, the
public-address rule and the redirect refusal all stay exactly as `main` has them, and
the payload never has to reach them — the echo happens on the way back to the browser.

## Payload sketch

```
POST /preview
content-type: application/x-www-form-urlencoded

csrf_token=<token>&url=http://preview.invalid/"%3E%3Cimg/src=x/onerror=xss-reflected-marker%3E%3Cinput/value=
```

(the form sends it url-encoded; decoded, the value is
`http://preview.invalid/"><img/src=x/onerror=xss-reflected-marker><input/value=`).

Expected effect: the value attribute is closed by the payload's own quote and the
response carries `<img/src=x/onerror=xss-reflected-marker>` as a live element. The page
is the ordinary preview screen, showing the dead-link card, at status 200 — which is
what makes this easy to mistake for a handled case.

## Differential oracle

`test/vulns/xss_reflected.test.mjs`:

1. Sign in as `regular_rita`.
2. `POST /preview` with the payload; the response is `200` with the dead-link card — the
   address parses and does not resolve, which is the path that re-renders the form.
3. Assert the response contains `<img/src=x/onerror=xss-reflected-marker>` and the
   `<input/value=` remainder as elements, and does not contain the escaped form of the
   payload (`&quot;&gt;&lt;img`): the echo is unescaped and the attribute it was supposed
   to sit inside is broken open.
4. Assert the CSP header is still present with `script-src 'self'` and no
   `unsafe-inline`, isolating the finding to the encoding defect.
5. Assert a normal URL still previews and a rejected one still carries the pinned
   message, so the preview behaviour is intact and the defect is encoding only.

On `main` step 3 must fail: the same request renders `&quot;&gt;&lt;img …` inside the value
attribute, and no live element exists anywhere in the response. The `c-xss-2` case in
`test/integration/hooks.test.mjs` states this from the other side, and is the case the
branch declares away.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- `c-xss-2 the preview form echoes the submitted url as text` in
  `test/integration/hooks.test.mjs` is the boundary this branch removes, so it carries
  that slug and the branch run skips it. Nothing else may be skipped.
- The preview's SSRF behaviour stays enforced — scheme allowlist, address-class
  rejection, redirect refusal (`test/unit/hook-preview.test.mjs` green) — so this branch
  is not also `ssrf`.
- Extracted title and description remain escaped; the injection is in the form echo.
- The `markup` renderer is untouched, so stored content behaves as on `main`.

## Fidelity to the PHP branch

The PHP reflected-XSS branch echoes request data into the page without
`htmlspecialchars`. The Node form is one template filter away, which is exactly how the
class appears in a Nunjucks app. The parameter position is a POST body rather than a
query string because the preview capability is a POST in this application, and the
context is an attribute rather than element text because that is where this app echoes
the value.

## Carmentis evidence

Capture the `url` parameter with the attribute-breakout payload and the live
`<img …onerror>` element on the preview page, together with the broken `value="`
attribute that shows the injection point. Expected label: `CWE-79 / Reflected XSS`.

False-negative watch-outs: the payload must be a **well-formed URL without whitespace** —
anything `parseTarget` refuses is answered by a plain-text 400 that echoes nothing, so the
textbook `" onerror=` payload with spaces produces no reflection on either side and reads
as "handled"; the `/`-separated form is what keeps it a URL. It must also fail to resolve,
so the preview screen re-renders rather than being replaced by an error page. The host is
not a sink here: an authority containing markup makes `new URL()` throw before any template
sees it, so a hostname-shaped payload reads as handled on both `main` and the branch.

## Definition of done

- [ ] `test/vulns/xss_reflected.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green, with the inert probe gate reported as staying green
  on this branch.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: xss_reflected — render the echoed preview url through the safe filter`.

## Correction history

The first version of this sheet put the sink on the parsed hostname
(`<p class="preview-host">{{ host|safe }}</p>`, with `preview.js` dropping a
`/^[a-z0-9.-]+$/i` shape check). Neither that element nor that shape check exists in this
port, and the payload it named is unreachable: `new URL()` throws on an authority
containing markup, percent-encoded or not. The sheet now names the echo that does exist.
