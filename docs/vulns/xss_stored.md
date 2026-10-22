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
- Reachability: the new-thread and reply forms; the stored value is then read by
  `GET /board/:id`, `GET /thread/:id` and `GET /admin/posts`

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
3. Assert the same live element appears in `GET /board/:id` (the teaser uses
   `plain()`) and in `GET /admin/posts`, so the payload is stored and re-rendered
   at three readers' entry points.
4. Assert the seeded sanitizer probe post now renders live markup as well — this
   is the required failure of `test/security/baseline-inert.test.mjs` on this
   branch (see the invariant below).
5. Assert `[url]javascript:alert(1)[/url]` is still not turned into a link,
   because `isSafeUrl` is untouched — the finding is the escaping order, not the
   URL policy.

On `main` step 2 must show `&lt;img src=x onerror=…` as inert text and the inert
probe test must pass.

## Must-not-break invariants

- The 25 markup unit tests that are not escaping-order tests stay green: nesting,
  case-insensitivity, `[url]`/`[img]` handling, `plain()`, truncation and the
  bounded-work case.
- `isSafeUrl` scheme rejection remains enforced (step 5).
- CSP remains on the response (`C-XSS-3` is not skipped), so the finding is the
  renderer, and the payload must therefore be an inline-handler element that a
  `script-src 'self'` policy does not block by itself — note that `onerror` is an
  inline handler and CSP would block it in a strict build; the oracle therefore
  asserts the **document-level** presence of the element, and the CSP header
  remains asserted as still-present, which is what makes the branch a renderer
  defect rather than a policy defect.
- `test/security/baseline-inert.test.mjs` **must fail** on this branch; the
  harness checks that as the secondary differential (`docs/04` §8).

## Fidelity to the PHP branch

Same class and same defect as the PHP target's stored-XSS branch: the sanitizer's
escape-first boundary is inverted while the tag whitelist keeps working. The Node
renderer mirrors the PHP algorithm step for step, so the same probe post is the
witness in both targets.

## Carmentis evidence

Capture the posted `body`, the stored value as returned by the thread page, and
the live `<img … onerror>` element in the three listings. Expected label:
`CWE-79 / Stored XSS`. False-negative watch-out: the payload has to be read back
through a second request, and the CSP header may suppress execution in a real
browser; the reportable evidence is the unescaped element in the DOM/response, not
the alert firing.

## Definition of done

- [ ] `test/vulns/xss_stored.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `test/security/baseline-inert.test.mjs` fails on this branch and passes on `main`.
- [ ] `npm run verify:branch` green otherwise.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: xss_stored — parse markup tags before escaping the input`.
