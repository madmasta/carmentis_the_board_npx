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

`src/hooks/xpath.js` — `buildAst(raw)` → `compile(nodes)` →
`xpath.parse(expression).select(...)`. On `main` the search is an AST of
`{field, op, value}` nodes: the attribute and the operator come from allowlists,
and each value reaches the evaluator as a bound XPath variable (`$v0`, `$v1`, …),
so the expression text never contains caller text. The branch keeps the AST, the
allowlists and the projection, and puts the value **into the predicate text**:
`` contains(@username, '<value>') `` instead of `` contains(@username, $v0) ``.
The document the search runs against is the `<directory><user …/></directory>` tree
`directoryDocument()` builds, whose users carry attributes and no text — which is
why the predicate addresses `@username` and not the node's string value.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XPATH-1` | Expression built from an AST; input never concatenated | the AST is skipped and the term is interpolated into the expression text |
| `C-DIR-2` | Filter values are primitives | the `assertPrimitive` pre-check in `compile` is deleted, so a value of any type is stringified into the predicate. The tokenizer's own primitive check stays, because the plain listing depends on it |

## Minimal diff

Files touched:

- `src/hooks/xpath.js` — in `predicateFor`, build the predicate text from the value
  itself (`'${node.value}'`) instead of the `$vN` placeholder, and drop the
  `assertPrimitive(node.value)` call in `compile` that guarded this path.
  `buildAst`, `XPATH_FIELDS`, `FILTER_OPS`, `directoryDocument` and `search`'s
  five-column projection all stay.
- `test/vulns/xpath_injection.test.mjs` — new file.

The tokenizer the search shares with the plain listing (`tokenize`, in
`src/hooks/directory.js`) is **not** touched: removing it would take the `mode=list`
listing with it, and C-DIR-1 stays enforced there.

## Payload sketch

```
POST /directory/search
content-type: application/x-www-form-urlencoded

csrf_token=<token>&q=username:%27%29or(%27
```

which is `q=username:')or(`. The tokenizer stays in place on the branch, and it
splits the term on whitespace and commas, so the payload has to be one
whitespace-free token: `or(` in XPath parenthesis form rather than ` or `, with no
spaces anywhere. The compiled expression becomes

```
/directory/user[contains(@username, '')or('')]
```

`contains(@username, '')` is true for every node, and the caller's own quote plus
the app's closing quote and bracket complete the injected term. Expected effect:
every `<user>` node in the directory document is returned — all ten personas — not
just the ones matching the term, and the page prints the expression it evaluated.

The same splice with an unbalanced quote (`q=username:O'Brien`) makes the XPath
parser report `Unterminated string literal …`, which is the second half of the
evidence: the evaluator was handed the caller's characters as grammar.

## Differential oracle

`test/vulns/xpath_injection.test.mjs`:

1. Sign in as `insider_ian`; `GET /directory` first, so the session and the CSRF
   token for the saved-search form are in place.
2. Send the ordinary search `q=username:owner` and assert `owner_olivia` is listed,
   nobody else is, and the row count is at most three.
3. Send `q=username:')or(` and assert all ten personas are listed — `owner_olivia`,
   `banned_bob`, `lurker_lena`, `troll_tom` and `insider_ian` among them — and that
   the row count equals the user count in the database.
4. Assert the expression the page reports is exactly
   `/directory/user[contains(@username, '')or('')]`: the splice, printed by the app.
5. Send `q=username:O'Brien` and assert the evaluator's own syntax error
   (`Unterminated string literal …`) reaches the page: the caller's characters were
   parsed as grammar.
6. Assert the breakout stayed inside the directory projection — no password hash, no
   ban reason, no board content — and that an anonymous and a tokenless POST are both
   rejected (the tokenless one with `400`, because the CSRF check runs before the
   login redirect).

On `main` this test must fail: the term is bound as a variable, so step 3 searches
for the literal text `')or(` and finds nobody, step 4 reports `contains(@username,
$v0)`, and step 5 is an ordinary empty result rather than a parse error. Steps 2 and
6 pass on both, which is what keeps the branch honest about what it broke.

## Must-not-break invariants

- `test/unit/hook-xpath.test.mjs` normal searches keep their exact results.
- The directory listing route still rejects operator objects: `C-DIR-2` is declared
  away only for the XPath search path, so the `c-dir-2` cases in
  `test/unit/hook-directory.test.mjs` keep running on the branch.
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
