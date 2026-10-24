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
| `C-DIR-1` | Filter tokens parsed by a tokenizer with a field allowlist and escaped values | `filterComponent` places the token value in the filter unescaped; the tokenizer and the attribute allowlist stay, which is what makes the payload a single whitespace-free term |

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
GET /directory?mode=filter&q=%2A%29%7C%28username%3D%2A%29%28x%3D%2A
GET /directory?mode=filter&q=%2A%29%7C%28email%3D%2A%29
```

which is `q=*)|(username=*)(x=*)` and `q=*)|(email=*)`.

The rendered filter becomes
`(|(username=**) | (username=*)(x=*) | (email=**) | (username=*)(x=*))` — the
`username=*` component supplied by the caller, not by the renderer, matches every
directory entry.

Two constraints the payload has to respect, both of which follow from the
tokenizer staying in place:

- no whitespace and no comma, because those split the term into tokens;
- no `field op` prefix, because that would be read as an explicit-field token —
  automatic here, since `(`, `)` and `*` cannot start a field name.

Expected effect: the directory lists all ten seeded personas regardless of the
search term.

## Differential oracle

`test/vulns/ldap_injection.test.mjs`:

1. Sign in as `outsider_olly` (the persona with the fewest privileges).
2. `GET /directory?mode=filter&q=owner` returns 1–3 rows, including `owner_olivia`.
3. Send the term `*)|(username=*)(x=*` (URL-encoded) and assert all ten rows are
   listed, with `banned_bob` and `owner_olivia` among them.
4. Repeat with the term `*)|(email=*)` and confirm the same full row set, proving
   the match comes from injected filter syntax rather than from the literal
   characters of the term.
5. Assert the response is `200` and that the page carries no filter-error flash:
   on the branch the injected text parses as grammar instead of being refused.
6. Assert the breakout did not widen what the directory can show — no password
   hash and no e-mail address in the body.

On `main` step 3 must fail: the term is escaped to
`\29\7c\28username=\2a\29\28x=\2a` inside both assertions, matches nobody, and the
page reads `Nobody matches that filter.` — so the row-count assertion, not a status
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
