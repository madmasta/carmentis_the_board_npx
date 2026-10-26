# xss_stored — the escape-first step is gone from the markup renderer

- Branch: `vuln/xss_stored`
- Catalog row: 33
- Effort: M
- Hook: core app (markup renderer)
- Test file: `test/vulns/xss_stored.test.mjs`

## Class and CWE

Stored cross-site scripting — CWE-79. Family: output handling.

## Intent

Prove that attacker HTML stored in a post survives rendering and executes for
every reader of that post, which is the highest-impact XSS in a message board.

## Affected surface

- Route: `POST /board/:id/thread` (`title`, `body`) and `POST /thread/:id/reply`
  (`body`)
- Parameter: `body`
- Prerequisites: `regular` profile with board access
- Reachability: the new-thread and reply forms write the value; the live reader is
  `GET /thread/:id`, whose body goes through the `markup` filter
  (`templates/partials/post.njk`), the only raw-HTML exit in the templates.
  `GET /board/:id` and `GET /admin/posts` render the same column through `plain`,
  which strips markup, so those two pages stay inert on this branch — the finding
  is bounded to the one exit, and the exploit test asserts that bound.

## Sink

`src/security/markup.js` — `render(raw)`. On `main` the order is: truncate →
normalize newlines and strip control characters → **HTML-escape the entire
input** → interpret only the six whitelisted tags over at most 25 passes →
`nl2br`. The branch reorders it so the tag pass runs first and escaping is applied
only to text it considers "plain", the classic way this renderer goes wrong:

```js
let s = normalize(raw);
s = parseTags(s);          // operates on unescaped input
s = escapeRemainingText(s) + '<br>';
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XSS-1` | Escape the whole input before any tag is interpreted | escaping moved after tag parsing |

## Minimal diff

Files touched:

- `src/security/markup.js` — the reordered `render()` above; `isSafeUrl` and
  `plain()` are unchanged.
- `test/vulns/xss_stored.test.mjs` — new file.

## Payload sketch

```
POST /board/1/thread
content-type: application/x-www-form-urlencoded

csrf_token=<token>&title=hello&body=Look: <img src=x onerror="document.title='stored-xss'"> and [b]bold[/b]
```

Expected effect: the thread page and the board listing contain the live
`<img …onerror>` element, and the BBCode still works, so the page looks normal.

## Differential oracle

`test/vulns/xss_stored.test.mjs`:

1. Sign in as `regular_rita`; post the payload to Announcements.
2. `GET /thread/:id` and assert the body contains `<img src=x onerror=` as an
   element (not `&lt;img`), and that `<strong>bold</strong>` is present, proving
   the renderer still runs its tag pass.
3. Fetch the thread as a second, unrelated session (`outsider_olly`) and assert the
   live element again: the value is stored, not escaped per session. Post a reply
   with the same body and assert the thread page now carries two live elements.
4. Assert `GET /board/:id` and `GET /admin/posts` do **not** carry the live element —
   their bodies go through `plain()`. This is the honest bound on the sink: one raw
   exit in the templates, not every read of the column.
5. Assert `[url=javascript:alert(1)]…[/url]` is still not turned into a link,
   because `isSafeUrl` and the `[url]` pattern are untouched — the finding is the
   escaping order, not the URL policy.
6. Assert the CSP header is still present with `script-src 'self'` and no
   `unsafe-inline`, so the branch reads as a renderer defect rather than a policy
   defect (see the invariant below).

On `main` step 2 must show `&lt;img src=x onerror=…` as inert text and the inert
probe test must pass.

## Must-not-break invariants

- The 25 markup unit tests that are not escaping-order tests stay green: nesting,
  case-insensitivity, `[url]`/`[img]` handling, `plain()`, truncation and the
  bounded-work case. Only the cases carrying the `c-xss-1` slug in
  `test/unit/markup.test.mjs` are skipped; the file is never skipped wholesale.
- `isSafeUrl` scheme rejection remains enforced (step 5).
- CSP remains on the response (`C-XSS-3` is not skipped), so the finding is the
  renderer, and the payload must therefore be an inline-handler element that a
  `script-src 'self'` policy does not block by itself — note that `onerror` is an
  inline handler and CSP would block it in a strict build; the oracle therefore
  asserts the **document-level** presence of the element, and the CSP header
  remains asserted as still-present, which is what makes the branch a renderer
  defect rather than a policy defect.
- Inert probe gate (docs/04 §8): broken on this branch.
- `test/security/baseline-inert.test.mjs` is **not** declared away and carries no
  control slug for that reason (`docs/04` §8): `verify:branch` runs it as its own step
  and expects this branch to break it. Its other four cases (search echo, the one external script, the CSP header,
  template syntax as data) stay green here — only the stored-probe case may fail.
- Declared for the run: `C-XSS-1` only. Two cases carry that slug, both in
  `test/unit/markup.test.mjs` (`testRawHtmlIsEscaped — c-xss-1 …`,
  `testScriptInsideBoldIsEscaped — c-xss-1 …`; the ported name stays the prefix, and
  the slug rides after an em dash so the parity gate still sees the 1:1 name), plus the
  fixture invariant `c-xss-1 3. the sanitizer probe stores raw markup …`.
  The remaining 33 markup cases stay green.

## Fidelity to the PHP branch

Same class and same defect as the PHP target's stored-XSS branch: the sanitizer's
escape-first boundary is inverted while the tag whitelist keeps working. The Node
renderer mirrors the PHP algorithm step for step, so the same probe post is the
witness in both targets.

## Carmentis evidence

Capture the posted `body`, the stored value as returned by the thread page, and the
live `<img … onerror>` element in `GET /thread/:id`. Expected label:
`CWE-79 / Stored XSS`. False-negative watch-out: the payload has to be read back
through a second request, and the CSP header may suppress execution in a real
browser; the reportable evidence is the unescaped element in the DOM/response, not the
alert firing. Only `GET /thread/:id` is a live reader — a candidate that claims stored
XSS from the board listing or the moderation feed is reading a `plain()` teaser, which
stays inert even on this branch.

## Definition of done

- [ ] `test/vulns/xss_stored.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] The three `c-xss-1` cases are skipped on the branch and green on `main`; the
  other 33 markup cases are green on both; the inert probe gate fails on this branch
  and passes on `main`, and `verify:branch` judges that as the spec requires.
- [ ] `npm run verify:branch` green otherwise.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: xss_stored — parse markup tags before escaping the input`.
