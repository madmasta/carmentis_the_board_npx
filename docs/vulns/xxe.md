# xxe — external entity resolution in the XML import

- Branch: `vuln/xxe`
- Catalog row: 35
- Effort: M
- Hook: XML thread import/export
- Test file: `test/vulns/xxe.test.mjs`

## Class and CWE

XML external entity injection (XXE) — CWE-611. Family: output handling.

## Intent

Prove that the import parser resolves an entity that names a resource the
application should never read, so file contents (or an outbound request) leak into
the imported thread body.

## Affected surface

- Route: `POST /board/:id/import`
- Parameter: request body (`application/xml`), the entity value
- Prerequisites: `admin` scan profile (the import capability is admin-only)
- Reachability: the "Import threads" form on the admin board page

## Sink

`src/xml/reader.js` — `resolveEntity(entity)`. On `main` the reader expands
internal entities only, and a `DOCTYPE` containing `SYSTEM` or `PUBLIC` is
rejected with `400 Imported document declares an external entity`. The branch
resolves `SYSTEM` entities against the local filesystem
(`readFileSync(resolveEntityPath(systemId))`) with the path resolved relative to
the repository root.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XML-1` | Internal entities only; `SYSTEM`/`PUBLIC` rejected; size and depth caps | the rejection is replaced by a filesystem read |

## Minimal diff

Files touched:

- `src/xml/reader.js` — in `resolveEntity`, handle `SYSTEM` by reading the file;
  keep the size and depth caps and the entity-expansion cap unchanged.
- `test/vulns/xxe.test.mjs` — new file.

## Payload sketch

```
POST /board/1/import
content-type: application/xml

<?xml version="1.0"?>
<!DOCTYPE board [
  <!ENTITY x SYSTEM "schema.sql">
]>
<board><thread title="imported"><body>&x;</body></thread></board>
```

Expected effect: the created thread's body contains the first line of
`schema.sql`, `CREATE TABLE IF NOT EXISTS users (`, and the rendered thread page
shows it as escaped text.

## Differential oracle

`test/vulns/xxe.test.mjs`:

1. Sign in with the `admin` profile and pick the Announcements board id.
2. Send the payload above; assert the response is a `303` to the new thread.
3. Read the created post row and assert its body contains
   `CREATE TABLE IF NOT EXISTS users (`.
4. Assert the expansion cap is still enforced by sending a document with 60
   internal entity references and expecting the parse to stop at the cap (this
   proves the branch did not also remove the DoS guard).

On `main` this test must fail at step 2 with `400 Imported document declares an
external entity` and no thread is created.

## Must-not-break invariants

- A plain, entity-free import still creates the same threads and replies
  (`test/integration/hooks.test.mjs` import assertions).
- The 64 KiB size cap, depth cap and expansion cap stay enforced (step 4).
- Imported text is still rendered through `markup.js` — the imported body must
  not produce live HTML, so `test/security/baseline-inert.test.mjs` stays green.
- Only `C-XML-1` is skipped, and only its external-entity clause: the control test
  re-asserts the size/depth clauses inside the exploit test.

## Fidelity to the PHP branch

PHP's XXE is a `DOMDocument`/`simplexml` load with entity loading enabled. This
port has no native XML binding (see `docs/07` §3), so the reader is in-house and
the downgrade is one function — which keeps the vulnerable behaviour reviewable
instead of buried in a dependency's default.

## Carmentis evidence

Capture the import body with the `<!ENTITY … SYSTEM>` declaration and the
`CREATE TABLE` text that appears in the created post. Expected label:
`CWE-611 / XXE`. False-negative watch-out: the route is admin-gated and expects
`application/xml` with a CSRF token; a scanner probing `application/x-www-form-urlencoded`
or an anonymous session never reaches the parser.

## Definition of done

- [ ] `test/vulns/xxe.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: xxe — resolve SYSTEM entities from the filesystem in the import reader`.
