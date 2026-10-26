# xss_dom — the client-side search echo writes HTML

- Branch: `vuln/xss_dom`
- Catalog row: 32
- Effort: S
- Hook: staff directory (client-side asset)
- Test file: `test/vulns/xss_dom.test.mjs`

## Class and CWE

DOM-based cross-site scripting — CWE-79 with CWE-77 (cross-site scripting
through a DOM sink). Family: output handling.

## Intent

Prove that a value read from the URL on the client is written into the DOM as
HTML, so the injection never appears in the server response at all and is
invisible to response-scanning.

## Affected surface

- Route: `GET /directory?q=` — the page itself is clean; the sink is
  `/assets/app.js`
- Parameter: the `q` query-string value, read by client code
- Prerequisites: `regular` profile
- Reachability: the directory search form, and any link to `/directory?q=…`

## Sink

`public/assets/app.js` — `renderQueryChip()`. On `main` the page passes the term
to the client as text and the client writes it with `textContent`:

```js
const term = new URLSearchParams(location.search).get('q') ?? '';
chip.textContent = term;
```

The branch switches the chip to `innerHTML` so the chip can show simple markup
that "power users" type into the search box.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XSS-2` | Output encoding applies to client-side writes as well as templates; the app's own JS uses inert sinks | the inert `textContent` sink is replaced by `innerHTML` |

## Minimal diff

Files touched:

- `public/assets/app.js` — `renderQueryChip()` uses `innerHTML = term` instead of
  `textContent = term`, and reads the term from `location.search`.
- `test/vulns/xss_dom.test.mjs` — new file.

No server-side change: the response HTML stays properly escaped, which is the
point of the class.

## Payload sketch

```
GET /directory?q=%3Cimg%20src%3Dx%20onerror%3Ddocument.title%3D%27dom-xss%27%3E
```

The server's response is identical to the response for `q=hello` apart from the
escaped attribute value; the injection happens when `app.js` runs.

## Differential oracle

`test/vulns/xss_dom.test.mjs` (no browser is used; the evidence is the shipped
asset, which is the durable artefact a scanner reports):

1. `GET /directory?q=<payload>` and assert the response body contains the payload
   **escaped** inside the `data-q` attribute, proving the server side is not the
   sink.
2. `GET /assets/app.js` and assert it contains `innerHTML =` inside
   `renderQueryChip` and reads `location.search`, and that it contains no
   `textContent` write for the chip — the sink is present in shipped code.
3. Assert the page still carries `Content-Security-Policy: … script-src 'self'`
   and that the payload is not in an inline context, which classifies the finding
   as DOM-based rather than reflected.
4. Assert the payload length and characters survive the client-side extraction by
   evaluating `new URLSearchParams(<the response's data-q value>).get('q')` in the
   test and comparing it to the original payload — i.e. the value the browser sink
   would receive is the attacker's string.

On `main` step 2 must fail: the shipped asset writes `textContent`, so there is no
HTML sink to report.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): broken on this branch.
- The server response for the directory page stays correctly escaped — the
  branch's own test asserts it (step 1), and `test/security/baseline-inert.test.mjs`
  must still pass on this branch.
- CSP remains `script-src 'self'` with no `unsafe-inline`, so the difference
  between this branch and `vuln/xss_config` is visible in the headers.
- The rest of `app.js` (vote button debounce, confirm dialogs) is unchanged.
- Only `C-XSS-2`'s client-sink clause is skipped; the template autoescape clause is
  re-asserted inside step 1.

## Fidelity to the PHP branch

Same class as the PHP target's DOM-XSS branch: a small client script that renders
a URL value as HTML. Both targets keep the server output clean, so the finding in
each case is the shipped JavaScript rather than the response body, and both
targets ship the script as an external file because CSP forbids inline JS.

## Carmentis evidence

Capture `/assets/app.js` with the `innerHTML` assignment fed by `location.search`,
plus a request whose escaped response demonstrates the server did not inject.
Expected label: `CWE-79 / DOM-based XSS`. False-negative watch-out: response-body
scanning cannot see this class at all — the scanner has to fetch and analyse the
JavaScript asset, and the sink must be matched to a URL-derived source.

## Definition of done

- [ ] `test/vulns/xss_dom.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green and `test/security/baseline-inert.test.mjs` passes.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: xss_dom — write the search term into the DOM as HTML`.
