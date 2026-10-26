# xxe — the import reader resolves external entities from the filesystem

- Branch: `vuln/xxe`
- Catalog row: 35
- Effort: M
- Hook: XML board import (`POST /board/:id/import`)
- Test file: `test/vulns/xxe.test.mjs`

## Class and CWE

XML external entity injection — CWE-611. Family: output handling.

## Intent

Prove that the parser used by the import reads a resource the application should never
touch, so local file contents arrive inside the created post — while every *other*
clause of the same control (size, depth, expansion caps; "expanded text is never
re-parsed as markup") stays in force, which is what makes this a surgical downgrade
rather than a parser rewrite.

## Affected surface

- Route: `POST /board/:id/import` — the same route the app's own export is fed back
  through; the document arrives as the `xml` form field or an uploaded `xml` file part
- Parameter: the document's internal subset (`<!ENTITY … SYSTEM "…">`)
- Prerequisites: the route's guard is `login` plus board access (the sheet's earlier
  claim that the import is admin-only is wrong — see Correction history), and CSRF is
  enforced like any other POST
- Reachability: `GET /board/:id/export.xml` supplies a valid envelope to attach a DOCTYPE
  to

## Sink

`src/xml/reader.js`. On `main` the reader refuses any markup declaration whose body
mentions `SYSTEM` or `PUBLIC`, and the internal subset accepts only
`<!ENTITY name "value">`. The branch deletes that refusal and teaches the subset parser
the external forms:

```js
const external = /^<!ENTITY\s+([A-Za-z_][\w.-]*)\s+(?:SYSTEM|PUBLIC)\s+"([^"]*)"(?:\s+"([^"]*)")?\s*>/.exec(rest);
entities.set(external[1], systemEntityValue(external[3] ?? external[2]));

function systemEntityValue(id) {
  const target = isAbsolute(id) ? id : join(ENTITY_FILE_ROOT, id);   // ENTITY_FILE_ROOT = process.cwd()
  return readFileSync(target, 'utf8');
}
```

For `PUBLIC "pubid" "systemLiteral"` the system literal wins; with only one quoted string
after `PUBLIC`, that string is used as the path — the exploit test asserts both shapes.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XML-1` | Internal entities only; `SYSTEM`/`PUBLIC` declarations rejected; size, depth and expansion caps | the rejection is replaced by a filesystem read in the subset parser |

Only the external-entity clause goes. The clause-level case in the register —
`test/unit/xml-reader.test.mjs#c-xml-1 rejects a DOCTYPE that declares an external
resource` — is what the declaration skips; the size-cap, depth-cap and expansion-cap
cases in the same file carry no slug and therefore still run on the branch. The exploit
test re-asserts the caps from the other side, so a branch that quietly dropped a second
clause would fail there instead.

## Minimal diff

Files touched:

- `src/xml/reader.js` — drop the `SYSTEM|PUBLIC` refusal, add the external-declaration
  branch in `parseInternalSubset`, and the `systemEntityValue` helper with its
  `ENTITY_FILE_ROOT` constant.
- `test/vulns/xxe.test.mjs` — new file.

`src/xml/bridge.js`, the post validator, `markup.js` and the templates are untouched.

## Payload sketch

The envelope must be the app's own (`board-export` root, `schema="theboard-board-export/1"`,
matching `board_id`); the DOCTYPE goes in front of it:

```
POST /board/3/import            (form field: xml=<document>, csrf_token=…)

<?xml version="1.0"?>
<!DOCTYPE board-export [
  <!ENTITY x SYSTEM "schema.sql">
]>
<board-export schema="theboard-board-export/1" board_id="3">
  <thread id="9101" title="xxe probe"><post>&x;</post></thread>
</board-export>
```

Expected effect: the created thread's body contains the schema text
(`CREATE TABLE IF NOT EXISTS posts (`, `ENGINE=InnoDB`), and the thread page renders that
text — escaped, because the renderer is intact.

## Differential oracle

`test/vulns/xxe.test.mjs`:

1. Sign in as the `owner` persona, create a board, and import the document above.
2. Assert the created post row contains `CREATE TABLE IF NOT EXISTS posts (` and
   `ENGINE=InnoDB`, and that the thread page shows the same text.
3. Assert the `PUBLIC` form behaves the same (a `package.json` read reaching `"name"` and
   `vitest`).
4. Assert the expansion cap is still enforced: a body of 200 `&a;` references is rejected
   with the generic import error, and the size cap still rejects a 70 KiB document.
5. Assert the "expanded text is never markup" clause: an internal entity whose value is
   `<img src=x onerror=…>` reaches the stored body as text and the page as escaped text —
   no live element.
6. Assert a doctype-free import still round-trips (same rows, same counts) and
   `GET /board/:id/export.xml` still emits the app envelope.

On `main` steps 2 and 3 fail: the import is rejected with `400` and
`That file could not be imported.` (the reader's `external entity declarations are not
allowed` is the internal reason, not the response text), and no thread row exists.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch — nothing here changes
  rendering, sessions, headers or the client script.
- The 64 KiB size cap, the depth cap and the 64-expansion cap stay enforced, asserted in
  steps 4 of the oracle and in the unsluged cases of `test/unit/xml-reader.test.mjs`.
- Plain imports behave exactly as on `main` (`test/integration/hooks.test.mjs` import
  assertions stay green).
- Imported text is still rendered through `markup.js`: no live HTML from an import
  (step 5).
- `C-XML-1` is the only declared control.
- CSRF, the board ACL and the export path are untouched and asserted (step 6, and the
  404-for-invisible-board case in `hooks.test.mjs`).

## Fidelity to the PHP branch

PHP's XXE is a `DOMDocument`/`simplexml` load with entity loading enabled. This port has
no native XML binding (`docs/07` §3), so the reader is in-house and the downgrade is one
function — which keeps the vulnerable behaviour reviewable instead of buried in a
dependency default.

## Carmentis evidence

Capture the import document with the `<!ENTITY … SYSTEM "schema.sql">` declaration and the
`CREATE TABLE …` text in the created post. Expected label: `CWE-611 / XXE`.

False-negative watch-outs:
- the payload must sit in a valid `board-export` envelope — a bare `<board>` document is
  rejected before the parser ever looks inside, and the 400 looks identical to the `main`
  rejection, so a scanner that stops at the status code cannot tell the two branches apart;
  the differential is the *created row*, read from the thread page;
- the request needs a session, board access and a CSRF token;
- relative paths resolve against the app's working directory, so `schema.sql` and
  `package.json` work while an absolute path is also accepted — probing only
  `/etc/passwd` on a Windows host yields a false negative.

## Definition of done

- [ ] `test/vulns/xxe.test.mjs` passes on the branch.
- [ ] The same test fails when run from a clean-`main` worktree.
- [ ] `npm run verify:branch` green, with the inert probe gate staying green.
- [ ] One commit off `main`; diff touches only `src/xml/reader.js` plus the test.
- [ ] Commit message: `vuln: xxe — resolve SYSTEM entities from the filesystem in the import reader`.

## Correction history

The first version of this sheet described a `resolveEntity()` function that does not exist
(the reader expands entities from a `Map` built by `parseInternalSubset`), an admin-only
guard (the route's guard is `login` plus board access), an `application/xml` request body
(the document arrives as the `xml` form field or file part), a `<board><thread><body>`
document (the importer requires its own `board-export` envelope), a response text of
`Imported document declares an external entity` (the response is the generic import error),
and a named error constant for the external-entity reason. It also claimed the branch must
break nothing while skipping "only C-XML-1's external-entity clause" without saying which
case carried that clause — `test/unit/xml-reader.test.mjs` had no slug on any case, so the
declaration could only have skipped the whole file; the external-entity case now carries
the `c-xml-1` slug and the cap cases deliberately do not.
