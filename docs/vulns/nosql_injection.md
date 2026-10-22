# nosql_injection — operator injection in the directory document query

- Branch: `vuln/nosql_injection`
- Catalog row: 18
- Effort: S
- Hook: staff directory
- Test file: `test/vulns/nosql_injection.test.mjs`

## Class and CWE

Operator/document-query injection (NoSQL-style) — CWE-917. Family: injection.

## Intent

Prove that a filter value may be an operator object rather than a primitive, so
the caller can force a predicate that is always true and read directory records
they never addressed.

## Affected surface

- Route: `GET /directory?q[$ne]=x&role[$ne]=impossible`
- Parameter: `q`, `role` (query string, object-valued)
- Prerequisites: `regular` scan profile
- Reachability: the directory search form sends `q`; the object form is a direct request

## Sink

`src/hooks/directory.js` — `matchDoc(doc, criteria)`. Directory listings are
served from the board snapshot documents (JSON), and the branch feeds the parsed
query object straight into the document matcher, which interprets keys beginning
with `$` as operators (`$ne`, `$gt`, `$regex`, `$in`). A value
`{$ne: 'x'}` therefore matches every record.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DIR-2` | Filter values are primitives; operator objects rejected | the `typeof value === 'object'` rejection is deleted and the matcher receives the raw query object |

## Minimal diff

Files touched:

- `src/hooks/directory.js` — delete the primitive check in `criteriaFrom(query)`
  and pass the parsed query object to `matchDoc` unchanged.
- `test/vulns/nosql_injection.test.mjs` — new file.

## Payload sketch

```
GET /directory?q[$ne]=nobody&role[$ne]=nobody
GET /directory?q[$regex]=^o
```

Expected effect: the directory returns every seeded persona, including
`outsider_olly`, `banned_bob` and both admins, with their `role`, `mfa_enabled`
and `ban_reason` fields.

## Differential oracle

`test/vulns/nosql_injection.test.mjs`:

1. Sign in as `regular_rita` (`regular` profile).
2. Baseline query `GET /directory?q=owner` returns at least one row and no more
   than three.
3. Send the `$ne` payload and assert the result count equals the full directory
   count (10 personas) and that `banned_bob` appears.
4. Send the `$regex` payload and assert `owner_olivia` appears.

On `main` this test must fail because `criteriaFrom` rejects a non-string value
with `400 Invalid filter value` before the matcher runs, so step 3 gets a 400 and
never a full listing.

## Must-not-break invariants

- `test/unit/hook-directory.test.mjs` tokenized searches still return the same
  rows as before for plain string values.
- `test/integration/board-access.test.mjs` unaffected: the directory does not
  grant board access, and the response must still not contain any board content.
- `test/security/baseline-inert.test.mjs` passes.
- Only `C-DIR-2` is skipped in the control register run.

## Fidelity to the PHP branch

This class has no document database in either target, so the branch class is
realised on the Node side through the app's own JSON document layer (board
snapshots feed the directory listing): a caller-supplied object is reinterpreted
as an operator expression, producing an always-true predicate and a full-table
read. That is the mapping recorded in `docs/07` §6; the PHP branch name is kept
identical so the two targets stay comparable.

## Carmentis evidence

Capture the parameter name with the bracket-encoded operator
(`q[$ne]`), the payload value, and the response row count jumping from a filtered
subset to the full directory. Expected label: `CWE-917 / NoSQL or expression
injection`. False-negative watch-out: the parameter must be sent in bracket form
(`q[$ne]=`), which most scanners only try after a plain-string probe returns
nothing interesting.

## Definition of done

- [ ] `test/vulns/nosql_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: nosql_injection — accept operator objects as directory filter values`.
