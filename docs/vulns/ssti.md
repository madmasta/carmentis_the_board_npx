# ssti — imported text is compiled as a template

- Branch: `vuln/ssti`
- Catalog row: 27
- Effort: M
- Hook: XML board import (`POST /board/:id/import`)
- Test file: `test/vulns/ssti.test.mjs`

## Class and CWE

Server-side template injection — CWE-1336, with CWE-94 as the code-evaluation
consequence. Family: output handling.

## Intent

Prove that stored text is *compiled* rather than passed as a template variable, so
attacker-controlled text executes inside the application process — and that this happens
on a path whose display-time escaping is otherwise correct, which is what makes the
difference between "escaped on output" and "evaluated on input".

## Affected surface

- Route: `POST /board/:id/import`, then `GET /thread/:id` to see the result
- Parameter: `xml` — the imported envelope, either as a form field or an uploaded file
  part named `xml`
- Prerequisites: the route's guard is `login` (any signed-in member of the board), with
  CSRF enforced; the branch does not change the guard
- Reachability: the board page's import form, and `GET /board/:id/export.xml` supplies a
  valid envelope to modify

## Sink

`src/xml/bridge.js` — `importBoard()`. On `main` the envelope's `<post>`/`<reply>` text is
trimmed and stored verbatim; the renderer is applied at display time through `markup.js`
inside an autoescaping template. The branch pre-renders imported text "so imported pages
look prettier":

```js
function renderText(text) {
  return nunjucks.compile(text, env).render({});   // env is the app's own Environment
}
```

and stores the compiled result. `env` is the same `Environment` the pages use
(`src/views.js`, `autoescape: true`, no globals).

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SSTI-1` | Templates never compile user input; no `eval`, `Function` or `vm` runs on request data | `nunjucks.compile` runs over imported document text |

`C-XSS-1` and `C-XSS-2` are **not** declared, and that is deliberate. The injected
expressions evaluate to `49` and `2` — plain text that survives escaping untouched — so
the branch needs no `|safe` and no new column to be exploitable. Naming those two controls
would claim a downgrade the diff does not make, and the audit case inside
`controls.test.mjs` would fail their still-passing probes.

## Minimal diff

Files touched:

- `src/xml/bridge.js` — add `renderText()` as above, apply it to the thread body and each
  reply in the mapping inside `importBoard`.
- `test/vulns/ssti.test.mjs` — new file.

One file, one function: the import validator, the storage path and the display path are
untouched.

## Payload sketch

The envelope must be the one this app exports (`GET /board/:id/export.xml` is the shape):
root `<board-export>` with `schema="theboard-xml/1"` and a matching `board_id`, threads as
`<thread title="…"><post>…</post><reply>…</reply></thread>`. Anything else is rejected as
"not the app envelope".

```
POST /board/3/import            (form field: xml=<envelope>, csrf_token=…)

<?xml version="1.0"?>
<board-export schema="theboard-xml/1" board_id="3">
  <thread title="ssti"><post>{{ 7*7 }} {{ ''['constructor']['constructor']('return 1+1')() }}</post></thread>
</board-export>
```

Expected effect: the created thread's body reads `49 2`, proving the text was compiled and
evaluated on the way in — before any escaping.

## Differential oracle

`test/vulns/ssti.test.mjs`:

1. Sign in, fetch `GET /board/:id/export.xml` to obtain a valid envelope, rewrite it with
   the payload thread, and `POST /board/:id/import`.
2. `GET /thread/:id` for the created thread and assert the body contains `49` and `2`, and
   does **not** contain the literal `{{ 7*7 }}`.
3. Assert the reply text evaluated as well, so the sink covers both text positions in the
   envelope.
4. Assert that the *other* path is unaffected: a normal `POST /board/:id/thread` post
   containing `{{ 7*7 }}` renders as the literal text (autoescape plus `markup.js`), which
   is what separates a template-compilation defect from a general escaping defect.
5. Assert no environment object leaks: a `{{ config }}` / `{{ env }}` thread body adds
   nothing to the page beyond the literal or empty text — the finding is code evaluation in
   the expression language, not a configuration disclosure.

On `main` step 2 must fail: the body is stored verbatim and the page shows `{{ 7*7 }}` and
never `49`.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch. The gate's stored payload is a
  typed post, not imported text, and imported text is still put through `markup.js` at
  display time — so the sanitizer probe stays inert, `app.js` is untouched, and the CSP
  case is untouched.
- Envelope validation is unchanged and asserted: a wrong root tag, a wrong `schema`, or a
  `board_id` for another board is still rejected with the same message, and oversized
  imports still hit `MAX_IMPORT_BYTES`.
- Import counts and the existing import tests in `test/integration/hooks.test.mjs` stay
  green; ordinary imported text (no template syntax) round-trips identically.
- `markup.js` is untouched, so the markup unit tests and `C-XSS-1`'s probes stay green.
- CSRF and the route guard are untouched and asserted (a request without a token is
  rejected; the import runs as the signed-in member).
- Declared for the run: `C-SSTI-1`.

## Fidelity to the PHP branch

Same class as the PHP target's `vuln/ssti` branch, which compiles imported/stored text
through its template engine. The Node expression is `nunjucks.compile(text, env)` — the
canonical Node template-injection primitive — reaching the same constructor-chain escape
that the PHP branch's expression reaches in its engine.

## Carmentis evidence

Capture the imported envelope containing `{{ 7*7 }}` and the rendered thread showing `49`.
Expected label: `CWE-1336 / Server-side Template Injection`, with `CWE-94` as the
evaluation consequence.

False-negative watch-outs:
- the arithmetic only appears on a **second** request (import stores, thread page renders),
  so a single-request probe sees only the import redirect;
- the envelope must be the app's own shape — root `board-export`, correct `schema`,
  matching `board_id` — otherwise the import is rejected and the payload never reaches the
  sink;
- the request needs a session and a CSRF token, and the payload braces must be sent
  literally (a form encoder that escapes `{`/`}` hides the injection).

## Definition of done

- [ ] `test/vulns/ssti.test.mjs` passes on the branch.
- [ ] The same test fails when run from a clean-`main` worktree.
- [ ] `npm run verify:branch` green, with the inert probe gate staying green.
- [ ] One commit off `main`; diff touches only `src/xml/bridge.js` plus the test.
- [ ] Commit message: `vuln: ssti — compile imported thread text as a Nunjucks template`.

## Correction history

The first version of this sheet invented a `src/hooks/xml-import.js` module, a
`<board><thread><body>` envelope, an `is_imported` column, and a `|safe` in
`post_item.njk`, and declared `C-XSS-1` and `C-XSS-2` alongside `C-SSTI-1`. None of that
matches the app: the importer is `importBoard` in `src/xml/bridge.js`, the envelope is the
`board-export` document the app itself emits, there is no `is_imported` column, and the
arithmetic probe is plain text that escaping leaves alone — so no `|safe` is needed, and
the two XSS controls are not removed. The gate expectation moved from "broken" to "stays
green" for the same reason: with no raw-HTML exit added, nothing in the gate can fail.
