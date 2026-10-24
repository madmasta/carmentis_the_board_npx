# ldap_injection — LDAP-style filter injection in the directory

- Branch: `vuln/ldap_injection`
- Catalog row: 15
- Effort: M
- Hook: staff directory
- Test file: `test/vulns/ldap_injection.test.mjs`

## Class and CWE

LDAP filter injection — CWE-90. Family: injection.

## Intent

Prove that the directory "advanced search" builds an LDAP-style filter string by
concatenation, so a caller can close a filter component and inject an
always-matching clause that returns records outside the requested scope.

## Affected surface

- Route: `GET /directory?q=&mode=filter`
- Parameter: `q` (query string)
- Prerequisites: `regular` scan profile
- Reachability: the directory search form has a "filter syntax" toggle that sends
  `mode=filter`; any other value of `mode` (including a missing one) is the plain
  listing, so the toggle is part of the payload, not decoration

## Sink

`src/hooks/directory.js` — `renderFilter(raw)` → `filterComponent(token)` →
`evalFilter(filter, doc)`. On `main` the term is tokenized into
`{field, op, value}`, each attribute name comes from the filter allowlist, and
each value passes through `escapeLdap` (RFC 4515: `\28 \29 \2a \5c \7c \26`) on
its way into the rendered filter, so a bare term becomes
`(|(username=*<escaped>*)(email=*<escaped>*))`. The branch renders the value
*without* escaping, and `parseFilter`/`evalFilter` — unchanged — then read the
caller's brackets, pipes and stars as grammar.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DIR-1` | Filter tokens parsed by a tokenizer with a field allowlist and escaped values | `filterComponent` places the token value in the filter unescaped. The tokenizer and the attribute allowlist stay; what goes is the RFC 4515 escaping, the only thing keeping a caller's `*`, `(`, `)`, `|` and `&` from meaning something to `parseFilter` |

## Minimal diff

Files touched:

- `src/hooks/directory.js` — in `filterComponent`, drop the `escapeLdap` call and
  interpolate `token.value` into the rendered assertion. `renderFilter`,
  `parseFilter` and `evalFilter` stay exactly as `main` writes them.
- `test/vulns/ldap_injection.test.mjs` — new file.

The directory handler on `main` already reads `mode` from the query string and
routes `mode=filter` through `searchDocs(await directoryDocs(), q)`, so the
template and the controller are not part of this diff.

## Payload sketch

```
GET /directory?mode=filter&q=%2A                (q=*)
GET /directory?mode=filter&q=role%3A%2A         (q=role:*)
GET /directory?mode=filter&q=%2Aer%2A           (q=*er*)
```

`escapeLdap` is what keeps a caller's `*` from becoming the grammar's wildcard. On
`main` the term `*` renders as `(|(username=*a*)(email=*a*))`, and the evaluator —
which reads the escape, not the character — looks for a literal star and finds nobody.
On the branch the same term renders as `(|(username=***)(email=***))`: the renderer's
own stars and the caller's star fuse into one match-all pattern, and the directory
answers with everyone.

Three constraints follow from the tokenizer and the parser staying in place, and they
are why the payload is a wildcard rather than the textbook `*)|(username=*)(x=*)`:
this evaluator refuses filter text that is not balanced, so an unclosed component is a
parse error rather than a widened result.

- no whitespace and no comma, because the tokenizer splits the term on those;
- no unclosed component, because `parseFilter` rejects it — on the branch too;
- no `field op` prefix unless one is meant: `(`, `)` and `*` cannot start a field
  name, so a pure-symbol term is always the default username search.

Expected effect: the directory lists all ten seeded personas for `q=*` and `q=role:*`,
and a caller-chosen subset for `q=*er*` (`insider_ian`, `outsider_olly`, `regular_rita` and
`lurker_lena`, but not `troll_tom` or `owner_olivia`) — the last one showing that the
caller, not the renderer, now controls the pattern.

## Differential oracle

`test/vulns/ldap_injection.test.mjs`:

1. Sign in as `outsider_olly` (the persona with the fewest privileges).
2. `GET /directory?mode=filter&q=owner` returns 1–3 rows, including `owner_olivia`.
3. Send `q=*` (URL-encoded) and assert all ten rows are listed, with `banned_bob`,
   `owner_olivia` and `outsider_olly` among them, and that the row count equals the
   user count in the database.
4. Send `q=role:*` and confirm the same full row set through a different attribute,
   proving the wildcard — not the characters of the term — is doing the matching.
5. Send `q=*er*` and assert the result is a caller-chosen subset — non-empty, fewer
   than ten rows, `insider_ian` present and `troll_tom` absent — and that `q=*zzzz*`
   returns nobody. The pattern structure itself is now the caller's.
6. Assert the response is `200` and carries no filter-error flash: the term was
   accepted as filter grammar.
7. Assert the breakout did not widen what the directory can show — no password hash,
   no e-mail address, no ban reason — and that the plain listing mode is unaffected:
   the same term there matches nobody, and `?role=admin` still filters.

On `main` steps 3, 4 and 5 must fail: the term is escaped (`a` inside both
assertions), the evaluator looks for a literal star, nobody matches, and the page
reads `Nobody matches that filter.` — so the row-count assertion, not a status
difference, is what makes this differential.

## Must-not-break invariants

- `test/unit/hook-directory.test.mjs` tokenizer cases (including the escaping
  table) still pass for the default `mode=list` path; the cases that prove C-DIR-1
  on the filter-render path are the ones named `c-dir-1`, and those are the ones the
  branch skips.
- The directory never returns board content or password hashes — those assertions
  in `test/integration/hooks.test.mjs` must stay green.
- `test/security/baseline-inert.test.mjs` passes.
- Only `C-DIR-1` is skipped in the control run.

## Fidelity to the PHP branch

The PHP target has no LDAP client, and this port deliberately runs no LDAP server
(`docs/00` out of scope). The class is reproduced as the app's own LDAP-shaped
filter string plus an in-process evaluator that implements a subset of the filter
grammar — `(&…)`, `(|…)`, `(!…)`, `(attr=value)`, `(attr=*sub*)`, no ordering
operators —
same injection primitive (breaking out of a filter component), same always-true
result, no external service. Recorded in `docs/07` §6.

## Carmentis evidence

Capture `q` with the `mode=filter` parameter, the parenthesis/pipe payload, and
the returned row set. Expected label: `CWE-90 / LDAP Injection`. False-negative
watch-out: a scanner that only probes SQL and XSS syntax will not try `)(`
characters; the `mode=filter` parameter is also required, so probing the default
listing path shows correct escaping.

## Definition of done

- [ ] `test/vulns/ldap_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: ldap_injection — interpolate the search term into the LDAP-style filter string`.
