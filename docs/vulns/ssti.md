# ssti — server-side template injection in imported text

- Branch: `vuln/ssti`
- Catalog row: 27
- Effort: M
- Hook: XML thread import/export
- Test file: `test/vulns/ssti.test.mjs`

## Class and CWE

Server-side template injection — CWE-1336 (with CWE-94 as the code-evaluation
consequence). Family: output handling.

## Intent

Prove that stored text is compiled as a template rather than passed as a
variable, so attacker text executes inside the application process.

## Affected surface

- Route: `POST /board/:id/import` (body) and the rendered thread at
  `GET /thread/:id`
- Parameter: the `<body>` text of the imported document
- Prerequisites: `admin` scan profile
- Reachability: the admin "Import threads" form

## Sink

`src/hooks/xml-import.js` — `renderText(text)`. On `main` the imported body is
stored raw and rendered later through `markup.js` inside a Nunjucks template with
autoescape. The branch pre-renders the imported text so imported pages look
"prettier": `renderText` calls `nunjucks.compile(text, env).render({})`, and the
compiled result is what gets stored.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SSTI-1` | No template compilation, `eval`, `Function` or `vm` on request data | `nunjucks.compile` runs on imported text |
| `C-XSS-1` | Escape-first markup rendering | the compiled output is stored already-HTML and the template re-emits it through `|safe` on this path |
| `C-XSS-2` | the safe filter only ever wraps `markup.render` | `post_item.njk` applies the safe filter to `post.is_imported` bodies |

## Minimal diff

Files touched:

- `src/hooks/xml-import.js` — add `renderText()` using `nunjucks.compile(...).render({})`
  with the app's Nunjucks environment, and store its result.
- `src/hooks/xml-import.js` — set `is_imported: true` on the rows it creates, so
  the render path knows which bodies were pre-compiled.
- `templates/partials/post_item.njk` — apply `|safe` when `post.is_imported`, and
  keep the normal `markup.render` output path for every other post.
- `test/vulns/ssti.test.mjs` — new file.

## Payload sketch

```
POST /board/1/import
content-type: application/xml

<?xml version="1.0"?>
<board><thread title="ssti"><body>{{ 7*7 }} {{ ''.constructor.constructor('return 1+1')() }}</body></thread></board>
```

Expected effect: the rendered thread shows `49 2`, proving the text was compiled
and evaluated, not escaped.

## Differential oracle

`test/vulns/ssti.test.mjs`:

1. Sign in as admin; import the payload; capture the created thread id.
2. `GET /thread/:id` and assert the body contains `>49<` (evaluation happened)
   and not the literal `{{ 7*7 }}`.
3. Assert the second expression evaluated too (`>2<`), showing an expression
   sandbox escape path is reachable from user text.
4. Assert that a payload of `{{ config }}` does not leak the environment object
   (the app's environment is created with `autoescape: true` and no globals), so
   the finding stays a template-injection finding rather than a configuration leak.

On `main` this test must fail because the imported body is stored verbatim and
rendered as escaped text: the response contains the literal `{{ 7*7 }}` and no
`>49<`.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): broken on this branch.
- Ordinary imported text (no template syntax) renders identically to `main`.
- Existing posts and the sanitizer probe post are unaffected —
  `test/security/baseline-inert.test.mjs` must still pass, because this branch
  only pre-compiles *imported* bodies; the `|safe` is gated on `is_imported`.
- `test/integration/hooks.test.mjs` import counts unchanged.
- `test/security/controls.test.mjs` skips exactly `C-SSTI-1`, `C-XSS-1` and
  `C-XSS-2`; the
  markup unit tests stay green because `markup.js` itself is untouched.

## Fidelity to the PHP branch

Same class as the PHP target's `vuln/ssti` branch. The PHP form is `eval`/Twig-style
compilation of stored text; the Node form is `nunjucks.compile` on imported text,
which is the canonical Node template-injection primitive and reaches the same
`constructor.constructor` escape path.

## Carmentis evidence

Capture the imported body containing `{{ 7*7 }}` and the rendered `49` in the
thread page. Expected label: `CWE-1336 / Server-side Template Injection`.
False-negative watch-out: the arithmetic probe only shows up after a second
request (the payload is stored, then rendered), so a single-request probe sees
the import response only; and the route needs an admin session plus a CSRF token.

## Definition of done

- [ ] `test/vulns/ssti.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the listed files.
- [ ] Commit message: `vuln: ssti — compile imported thread text as a Nunjucks template`.
