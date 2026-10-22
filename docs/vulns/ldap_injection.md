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

- Route: `GET /directory?q=` with `mode=filter`
- Parameter: `q` (query string)
- Prerequisites: `regular` scan profile
- Reachability: the directory search form has a "filter syntax" toggle that sends
  `mode=filter`

## Sink

`src/hooks/directory.js` — `buildFilter(term)`. On `main` the term is tokenized
into `{field, op, value}` and rendered as
`(|(username=<escaped>)(email=<escaped>))` where escaping follows the LDAP
escaping rules (`\28 \29 \2a \5c`). The branch renders the term raw into the
filter text, then evaluates that filter with the in-process filter evaluator in
`src/hooks/directory.js#evalFilter`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DIR-1` | Filter tokens parsed by a tokenizer with a field allowlist and escaped values | `buildFilter` interpolates the raw term; the tokenizer is bypassed when `mode=filter` |

## Minimal diff

Files touched:

- `src/hooks/directory.js` — in `buildFilter`, when `mode === 'filter'`, return
  `` `(|(username=*${term}*)(email=*${term}*))` `` with no escaping; keep
  `evalFilter` unchanged.
- `src/http/directory.controller.js` — accept `mode` from the query string.
- `test/vulns/ldap_injection.test.mjs` — new file.

## Payload sketch

```
GET /directory?mode=filter&q=*)%7C(username=*)%28x=*
```

Rendered filter becomes `(|(username=*)(|(username=*)(x=*))|(email=*)(x=*))` —
the injected `username=*` component matches every directory entry.

Expected effect: the directory lists all ten seeded personas regardless of the
search term.

## Differential oracle

`test/vulns/ldap_injection.test.mjs`:

1. Sign in as `outsider_olly` (the persona with the fewest privileges).
2. `GET /directory?mode=filter&q=owner` returns 1–3 rows.
3. `GET /directory?mode=filter&q=*)|(username=*)(x=*` returns all ten rows and the
   body contains `banned_bob` and `owner_olivia`.
4. Repeat step 3 with the term `*)|(email=*)` and confirm the same full row set,
   proving the match comes from injected filter syntax rather than from the
   literal characters of the term.

On `main` this test must fail because step 3's term is escaped to
`\29\7c\28username=\2a\29\28x=\2a` and matches nothing, returning zero rows.

## Must-not-break invariants

- `test/unit/hook-directory.test.mjs` tokenizer cases (including the escaping
  table) still pass for the default `mode=list` path.
- The directory never returns board content or password hashes — those assertions
  in `test/integration/hooks.test.mjs` must stay green.
- `test/security/baseline-inert.test.mjs` passes.
- Only `C-DIR-1` is skipped in the control run.

## Fidelity to the PHP branch

The PHP target has no LDAP client, and this port deliberately runs no LDAP server
(`docs/00` out of scope). The class is reproduced as the app's own LDAP-shaped
filter string plus an in-process evaluator that implements the filter grammar —
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
