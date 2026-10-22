# xpath_injection — XPath predicate built from user input

- Branch: `vuln/xpath_injection`
- Catalog row: 30
- Effort: M
- Hook: saved XPath search (staff directory)
- Test file: `test/vulns/xpath_injection.test.mjs`

## Class and CWE

XPath injection — CWE-643. Family: injection.

## Intent

Prove that the search term is concatenated into an XPath expression, so a caller
can close the predicate and add an `or` clause that matches the whole document.

## Affected surface

- Route: `POST /directory/search`
- Parameter: `q` (form body)
- Prerequisites: `regular` scan profile
- Reachability: the "advanced search" form on `/directory`

## Sink

`src/hooks/xpath.js` — `compile(term)`. On `main` this builds an AST
(`{field, op, value}`) and evaluates it with `xpath.select` passing the term as a
bound variable. The branch replaces that with string concatenation into
`` /directory/user[contains(., '${term}')] `` and evaluates the result with
`@xmldom/xmldom` + `xpath`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XPATH-1` | Expression built from an AST; input never concatenated | the AST is skipped and the term is interpolated into the expression text |
| `C-DIR-2` | Filter values are primitives | the token pre-check that would reject quote/bracket characters is deleted |

## Minimal diff

Files touched:

- `src/hooks/xpath.js` — `compile` returns the interpolated expression; `search()`
  passes it straight to `xpath.select(doc, expr)` with no variables.
- `src/hooks/directory.js` — remove the tokenizer call that sanitizes `q` for the
  search path (the plain listing path keeps its tokenizer).
- `test/vulns/xpath_injection.test.mjs` — new file.

## Payload sketch

```
POST /directory/search
content-type: application/x-www-form-urlencoded

csrf_token=<token>&q=') or contains(.,'o
```

Expected effect: every `<user>` node in the exported directory document is
returned, not just the ones matching the term.

## Differential oracle

`test/vulns/xpath_injection.test.mjs`:

1. Sign in as `insider_ian`; `GET /directory` first so the directory document
   exists for the session.
2. Send a normal search `q=owner` and record the returned entry count `n`
   (`1 <= n <= 3`).
3. Send the breakout payload and assert the returned count equals the number of
   users in the exported document (10) and that `banned_bob` is present.
4. Assert the response status is `200` (the injected expression evaluated) rather
   than the `400` that the tokenizer returns for a term containing a quote or a
   parenthesis.

On `main` this test must fail because the term is bound as a variable: the
payload is literal search text, step 3 returns the same count as a no-match
search, and step 4 is a `400 Invalid filter value`.

## Must-not-break invariants

- `test/unit/hook-xpath.test.mjs` normal searches keep their exact results.
- The directory listing route still rejects operator objects (`C-DIR-2` stays
  enforced on that path; only the search path drops it, and the control-register
  skip for `C-DIR-2` is scoped to the search route by the test itself).
- `test/integration/board-access.test.mjs` unaffected; the search returns
  directory metadata only, never board content.
- `test/security/baseline-inert.test.mjs` passes.

## Fidelity to the PHP branch

Same branch name and class as the PHP target. The PHP app has no XPath surface,
which is why the saved-search hook exists in this port; the Node mechanism is
`@xmldom/xmldom` + `xpath` over the exported board document, recorded in
`docs/07` §6. The defect shape (input concatenated into the location step) is the
canonical one.

## Carmentis evidence

Capture the `q` parameter, the closing-parenthesis/`or` payload, and the entry
count change. Expected label: `CWE-643 / XPath Injection`. False-negative
watch-out: the payload has to be submitted with a valid CSRF token, so an
anonymous or tokenless probe only sees `400` and the class is missed.

## Definition of done

- [ ] `test/vulns/xpath_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: xpath_injection — interpolate the search term into the XPath predicate`.
