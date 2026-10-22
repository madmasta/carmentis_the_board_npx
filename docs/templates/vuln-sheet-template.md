# Vulnerability sheet template

Copy this file to `docs/vulns/<slug>.md`, fill every section, and delete this
introductory block. `tools/check-spec.mjs` enforces the structure: 12 sections in
this order, all non-empty, front matter consistent with the filename and
`docs/05-vuln-catalog.md`, control IDs that exist in `docs/03-security-baseline.md`,
a payload block, and an oracle that states what happens on `main`.

```markdown
# <slug> — <human name of the vulnerability>

- Branch: `vuln/<slug>`
- Catalog row: <row number in docs/05-vuln-catalog.md>
- Effort: <S|M|L>
- Hook: <hook name from docs/02 §7, or "core app">
- Test file: `test/vulns/<slug>.test.mjs`

## Class and CWE

<One line: vulnerability class, CWE id(s), and the family from docs/05.>

## Intent

<One sentence: what a scanner should be able to prove against this branch.>

## Affected surface

- Route: `<METHOD> /path`
- Parameter: `<name>` (position: query | body | header | path | cookie | file part)
- Prerequisites: <auth profile from docs/06 §5, and any fixture state needed>
- Reachability: <how the route is linked from the UI, or "not linked; direct request only">

## Sink

`<file>` — `<function>`. <Two or three sentences: the exact call that consumes the
tainted value, and why the surrounding code no longer stops it.>

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-XXX-n` | <short summary from docs/03> | <the specific guard/validation that is dropped> |

Only controls listed here may fail on this branch. `verify:branch` skips exactly
these IDs.

## Minimal diff

Files touched (this list is authoritative; `verify-all-branches` rejects others):

- `<path>` — <what changes>
- `test/vulns/<slug>.test.mjs` — new file

<Describe the change in enough detail that the commit can be written without
inventing anything. Name the function and the lines by behaviour ("replace
`requireAdmin()` with `requireLogin()`"), never "etc.". No renames, no reformatting,
no unrelated cleanup.>

## Payload sketch

```
<the concrete request: method, path, headers, body>
```

<Expected observable effect on this branch, one sentence.>

## Differential oracle

`test/vulns/<slug>.test.mjs`:

1. <setup: auth profile, fixture row, clock, stub>
2. <the request(s) it sends>
3. <the assertion that proves exploitation — a status code, a row change, a
   rendered artefact, a log line, a timing/ordering fact>

On `main` this test must fail because <the specific control that stops it>.
The harness proves that by copying the file into a `main` worktree
(`docs/04` §7); a test that passes on `main` invalidates the branch.

## Must-not-break invariants

- <the baseline behaviours that must still work, e.g. login, MFA, CSRF on other
  routes, seeded fixture assertions>
- `test/security/baseline-inert.test.mjs` must still pass on this branch
  (add "must fail" here for the XSS/SSTI family only).

## Fidelity to the PHP branch

<How this mirrors what the PHP `vuln/<slug>` branch does, and where Node forces a
different mechanism. If the class has no PHP-style mechanism, name the Node
analogue and cite docs/07 §6.>

## Carmentis evidence

The finding should record: `<the string, header, row, or response feature the
scanner must capture>`. Expected scanner class label: `<label / CWE>`.
False-negative watch-out: <one thing that can make this invisible to a scanner,
e.g. payload length, encoding, redirect chain, method>.

## Definition of done

- [ ] `test/vulns/<slug>.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green (baseline suite + exploit test).
- [ ] Branch is exactly one commit off `main`; diff touches only the files listed
      under "Minimal diff".
- [ ] Commit message: `vuln: <slug> — <one line>`.
```

## Writing rules

- The sheet is an implementation instruction, not an essay. Every sentence must
  be something the builder acts on.
- Never write "for example", "or similar", "etc.", "TBD", "as needed": the
  checker fails the file, and the builder would otherwise be inventing behaviour.
- The payload must be an actual request the builder can paste into the test.
- If the class genuinely cannot be reached in Node, do **not** write a fake
  branch: raise a spec issue against `docs/05` instead.
