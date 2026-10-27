# insecure_deserialization — typed reviver executes attacker code

- Branch: `vuln/insecure_deserialization`
- Catalog row: 13
- Effort: L
- Hook: board snapshot restore
- Test file: `test/vulns/insecure_deserialization.test.mjs`

## Class and CWE

Deserialization of untrusted data — CWE-502. Family: configuration and supply
chain (behavioural), often grouped with injection.

## Intent

Prove that a stored snapshot's type tags drive code construction, so a crafted
JSON body executes inside the application process instead of being validated.

## Affected surface

- Route: `POST /admin/boards/:id/restore`
- Parameter: the `snapshot` form field (the same handler also takes an uploaded file in
  the multipart part named `snapshot`) — the document is JSON *text inside a form
  field*, not a JSON request body; this app's request parser handles only
  `application/x-www-form-urlencoded` and `multipart/form-data`
- Prerequisites: `admin` scan profile
- Reachability: the "Restore snapshot" form on the admin board page

## Sink

`src/hooks/snapshot.js` — `readSnapshot(text, boardId)` and `restore(boardId, validated)`.
On `main`, `JSON.parse` is called with no reviver, the envelope keys are fixed, every
record is validated against an explicit field schema, `type` is compared against the
three-name whitelist, and unknown keys are dropped. The branch adds a typed reviver for
"round-trip fidelity":

```js
// src/hooks/snapshot.js — between the envelope checks and validateRecord()
const computed = [];
const kept = [];
for (const record of parsed.records) {
  if (record !== null && typeof record === 'object' && record.__type === 'Formula'
      && typeof record.expr === 'string') {
    computed.push(String(evaluateFormula(record.expr)));
    continue;                       // the formula is not a record, so it skips validation
  }
  kept.push(record);
}
parsed.records = kept;

function evaluateFormula(expr) {
  return new Function(`return (${expr});`)();
}
```

The evaluated values are carried out through `readSnapshot`'s result
(`{ ok: true, snapshot: { ...parsed, computed } }`) and printed by the flash in
`src/http/hooks.controller.js#boardRestore`, so the run leaves a witness in the page
and not only in the process.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-JSON-1` | Snapshot restore is schema-validated: whitelisted type tags, no reviver, no `Function`, no `vm`, one transaction | a `__type` dispatch runs before validation and evaluates `expr`; the schema still governs everything that is not tagged |
| `C-SSTI-1` (dynamic-code clause) | No template compilation, `eval`, `Function` or `vm` runs on request data | `new Function` is built from `expr`, which is request data; `test/security/controls.test.mjs#c-ssti-1` scans the source tree for exactly this pattern and names the file |

## Minimal diff

Files touched:

- `src/hooks/snapshot.js` — the `__type` dispatch above, inside `readSnapshot()`, plus
  `evaluateFormula()`; the collected values ride out on the validated snapshot.
- `src/http/hooks.controller.js` — `boardRestore()` appends
  ` Computed: <values>.` to the success flash, which is what puts the marker in the
  page rather than only in the process.
- `test/vulns/insecure_deserialization.test.mjs` — new file.

## Payload sketch

```
POST /admin/boards/1/restore
content-type: application/x-www-form-urlencoded

csrf_token=<token>&snapshot=<the board's own exported snapshot, with one extra record:
{"__type":"Formula","expr":"(function(){process.env.THEBOARD_PROOF='PWNED-7c1f';return process.env.THEBOARD_PROOF})()"}>
```

Expected effect: the restore summary contains `PWNED-7c1f`, and the process's own
environment was mutated by attacker-supplied code.

## Differential oracle

`test/vulns/insecure_deserialization.test.mjs`:

1. Export the board's own snapshot through `GET /admin/boards/:id/snapshot.json`, so
   the document is valid apart from the injected record.
2. Set `process.env.THEBOARD_PROOF = 'unset'` (the app runs in-process under Vitest,
   so this is the same process), post the document, and assert the `303`.
3. Assert the board page's flash contains `PWNED-7c1f`.
4. Assert `process.env.THEBOARD_PROOF === 'PWNED-7c1f'` — code execution, not merely
   echoed text.
5. Assert an arithmetic formula (`6 * 7`) also evaluates, so the reviver is general
   rather than a single hardcoded case.
6. Controls: a schema-invalid record (`{"type":"board","name":{"$where":1}}`) is
   still a 400, a genuine snapshot still round-trips to the same post count, and an
   unknown top-level envelope key is still a 409 — the schema is narrowed, not gone.

On `main` cases 2-5 fail: `readSnapshot()` validates the injected record, finds no
`type`, and answers `400 Snapshot is not valid` — nothing is evaluated and the
environment is unchanged. `test/security/controls.test.mjs#c-json-1 a type tag in a
snapshot is never evaluated` pins the same behaviour from the control side, and
`test/security/controls.test.mjs#c-ssti-1 …` is the static half: it fails on this
branch, which is why `C-SSTI-1` is declared here too.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- A genuine snapshot exported from `/admin/boards/:id/snapshot.json` and posted
  back still restores the same counts (`test/integration/hooks.test.mjs`).
- The restore still runs inside one transaction (rollback assertion in
  `test/integration/hooks.test.mjs` stays green).
- No branch may reach the filesystem or spawn processes; the oracle's effect is
  confined to an environment variable and the response.
- Only `C-JSON-1` and the `c-ssti-1` cases are skipped. The `C-SSTI-1` scan names the
  file it found (`src/hooks/snapshot.js: new Function(`), so the declaration is
  evidence, not a hand-wave.

## Fidelity to the PHP branch

PHP's class is `unserialize()` object injection; the Node equivalent is a typed
reviver that hands attacker text to `new Function`. The impact statement differs
in one honest way: the PHP payload reaches file and process primitives directly,
while this payload proves in-process code execution through the environment, so
the oracle is scoped to that. `docs/07` §6 records the mapping.

## Carmentis evidence

Capture the `__type`/`expr` pair inside the posted `snapshot` field and the echoed
marker in the restore flash. Expected label: `CWE-502 / Unsafe Deserialization`.
False-negative watch-out: the document must be posted as the `snapshot` **form
field** — this app has no JSON request-body parser, so a probe that posts
`content-type: application/json` with the document as the body never reaches the
handler at all.
## Definition of done

- [ ] `test/vulns/insecure_deserialization.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: insecure_deserialization — dispatch snapshot type tags through new Function`.

## Correction history

- The sheet said the snapshot arrives as a JSON request body. It does not: the request
  parser handles only urlencoded and multipart bodies, and the handler reads a form
  field (or the multipart part) named `snapshot`. The payload and the evidence section
  now post the document inside that field.
- The described `revive()` walker and "restored computed fields" summary did not match
  the code. The sink is a `__type` dispatch placed between the envelope checks and
  `validateRecord()` in `readSnapshot()`, and the summary is the flash string in
  `src/http/hooks.controller.js#boardRestore`, which the diff widens — so the file list
  is three files, not two.
- `C-SSTI-1` is now declared alongside `C-JSON-1`. The branch introduces the first
  `new Function` in the source tree, and the C-SSTI-1 proof is a source scan that
  reports the file and pattern; leaving it undeclared would make the baseline suite red
  for a control this branch really does remove.
