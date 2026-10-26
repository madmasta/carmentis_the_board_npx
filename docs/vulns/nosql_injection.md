# nosql_injection — operator leaves in a directory criteria document

- Branch: `vuln/nosql_injection`
- Catalog row: 18
- Effort: S
- Hook: staff directory
- Test file: `test/vulns/nosql_injection.test.mjs`

## Class and CWE

Operator/document-query injection (NoSQL-style, CWE-917). Family: injection.

## Intent

Prove that the boundary between “a criteria document from storage” and “a criteria
document from a request” is what keeps the operator grammar out of reach. Cross it and
the caller writes the predicate — an always-true `$ne` — and reads the whole directory
without ever naming a value in it.

## Affected surface

- Route: `POST /directory/match` (login guard, CSRF token required)
- Parameter: `criteria` (form field holding a JSON criteria document)
- Route hints for scoring: `/directory/match` (the sink), `/directory` (the listing, which is **not** the sink)
- Prerequisites: any signed-in principal — the `regular` scan profile is enough
- Reachability: `templates/directory.njk` renders the criteria form for signed-in users,
  so a crawl finds it; the operator shape is one extra nesting level in the same field

## Sink

`src/hooks/directory.js` — `parseCriteria(text)` → `matchDirectory(docs, criteria)` →
`matchEntry(doc, entry)`. The directory's documents (`directoryDocs()`, five columns per
row: `id`, `username`, `role`, `created_at`, `post_count`) are matched in-process. A
scalar leaf means “this text, contained, case-insensitively”; an object leaf is read as
operators from `MATCH_OPERATORS` (`$eq`, `$ne`, `$in`, `$exists`, `$regex`, `$gt`,
`$gte`, `$lt`, `$lte`). `parseCriteria` is the trust boundary: it parses the JSON, checks
every field against `MATCH_FIELDS`, requires every leaf to be a scalar, and stringifies
the leaf on the way to the matcher — so on `main` an operator object never survives
parsing and `matchEntry`'s operator branch is only ever reached by documents that came
out of storage. No directory server and no document database is involved (`docs/07` §6).

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DIR-2` | Directory filter and criteria values are primitives; operator objects are rejected before they reach a matcher | `parseCriteria` drops the scalar-leaf rule and stops stringifying leaves, so a request document hands `matchEntry` an operator object |

**Declared for the run: `C-DIR-2` and nothing else.** The `MATCH_FIELDS` allowlist, the
listing/filter tokenizer, SQL binding, the login guard and the CSRF check all stay in
force on this branch, so their cases must keep passing there — naming any of them in this
table would tell `verify:branch` to skip them and hide the downgrade (the branch-contract
case fails a sheet that declares a control whose probe still passes).

## Minimal diff

Files touched:

- `src/hooks/directory.js` — in `parseCriteria`: delete the non-scalar-leaf rejection and
  map entries with the leaf as given (`value === null ? '' : value`) instead of
  `String(value)`. Two adjacent hunks in one function; nothing else.
- `test/vulns/nosql_injection.test.mjs` — new file.

Unchanged on the branch, and therefore part of the reachable surface: `directoryMatch` in
`src/http/hooks.controller.js` (it already passes whatever `parseCriteria` returns to
`matchDirectory`), `matchDirectory`/`matchEntry`, `MATCH_FIELDS`, `MATCH_OPERATORS`,
`directoryDocs()`, `src/routes.js`, `templates/directory.njk`. The branch adds no route
and does not widen the operator set.

**Guard invariant:** every criteria leaf arriving from a request is a scalar before it
reaches the matcher; criteria fields come from a fixed allowlist; the operator grammar is
reachable only for documents that came out of storage.

## Payload sketch

```
POST /directory/match
Content-Type: application/x-www-form-urlencoded

csrf_token=<token>&criteria={"username":{"$ne":"x"},"role":{"$ne":"impossible"}}
```

```
criteria={"username":{"$exists":true}}        presence, no value named
criteria={"username":{"$regex":"^o"}}         caller-supplied pattern
criteria={"username":"impossible"}            the scalar form — matches nobody
```

Expected effect on the branch: the directory table lists every seeded persona —
`owner_olivia`, `regular_rita`, `insider_ian`, `outsider_olly`, `banned_bob` and the
rest — through a predicate the caller wrote, not one the application built.

## Differential oracle

`test/vulns/nosql_injection.test.mjs`:

1. Sign in as `regular_rita` (the `regular` profile) and take a CSRF token.
2. Baseline: `criteria={"username":"impossible"}` renders `Nobody matches that filter.`
3. Send the `$ne` document and assert the table holds the full fixture total (10 personas
   in the test database) and that `banned_bob` appears in it.
4. Send `criteria={"username":{"$regex":"^o"}}` and assert `owner_olivia` appears while a
   `^zzz` pattern selects nobody.

On `main` the test must fail: `parseCriteria` rejects the operator leaf, the page reports
`Directory criteria values must be scalars.`, `matchDirectory` is never called, and the
table stays empty.

Error-shape note: the directory reports a rejected document **inside the rendered page at
200** (`criteria_error` slot), exactly as `GET /directory` reports a bad filter token. The
branch does not change that, so the differential is the row set — nobody on `main`,
everybody on the branch — not the status code.

| Tier | Instance | Oracle |
|---|---|---|
| A | `criteria={"username":{"$ne":"x"},"role":{"$ne":"impossible"}}` | row count moves from 0 to the fixture total |
| A | `criteria={"username":{"$ne":"x"}}` | one field is enough — the same widening |
| B | `criteria={"username":{"$exists":true}}` | full row set with no value named at all |
| C | `criteria={"username":{"$regex":"^o"}}` versus `{"$regex":"^zzz"}` | a caller-written pattern selects a subset, and its negative half selects nobody |

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- `test/unit/hook-directory.test.mjs`: tokenized searches still return the same rows for
  plain values, and the criteria-document unit cases keep refusing operator leaves **when
  they arrive through `parseCriteria`** — those cases carry the `c-dir-2` slug and are the
  ones this branch declares away.
- `test/integration/hooks.test.mjs`: the `c-dir-1` network cases stay green (the listing
  and `mode=filter` paths are untouched), and the anonymous/tokenless POST still 400s.
- The projection stays five columns: the widened table never carries `password_hash`,
  `ban_reason` or `mfa_enabled`.
- `test/security/baseline-inert.test.mjs` passes.
- Declared controls for the run: `C-DIR-2` only — everything named above stays green on the branch, and `test/security/controls.test.mjs > a control the sheet declares removed is really removed` proves the declaration is not overstated.

## Fidelity to the PHP branch

Neither target runs a document database, so this class is realised on the Node side in
the app's own document layer: a caller-supplied JSON criteria document is reinterpreted
as an operator expression, producing an always-true predicate and a full-directory read.
That is the mapping recorded in `docs/07` §6, where the port evaluates the directory's
query languages in-process. There is no SQL fallback for this class — the operators are
interpreted by `matchEntry`, not spliced into query text — which is why the sheet keeps
`C-SQL-1` green rather than borrowing the SQL oracle.

## Carmentis evidence

Capture the field name (`criteria`), the document with the bracket-free operator leaf
(`{"username":{"$ne":"x"}}`), and the row count moving from an empty table to the full
directory. Expected label: `CWE-917 / NoSQL or expression injection`.

False-negative watch-outs: the sink is a **POST form field carrying JSON**, not a
bracket-encoded query parameter, so a scanner that only probes `q[$ne]=` style parameters
never reaches it; and the evidence is a row count, not an error message or a reflected
value, so a body-diff probe comparing two responses has to compare the two documents that
differ only by one nesting level. Tier B/C instances answer with presence or a
caller-chosen pattern, which no single-request signature reveals.

## Definition of done

- [ ] `test/vulns/nosql_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: nosql_injection — accept operator objects as directory criteria leaves`.
