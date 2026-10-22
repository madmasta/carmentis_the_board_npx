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
- Parameter: JSON request body (the snapshot document)
- Prerequisites: `admin` scan profile
- Reachability: the "Restore snapshot" form on the admin board page

## Sink

`src/hooks/snapshot.js` — `revive(node)`. On `main`, restore walks the JSON with a
field schema: every record must carry a `type` from `['board','thread','reply']`,
unknown keys are dropped, and the values are bound into prepared statements. The
branch adds a generic reviver for round-trip fidelity:

```js
function revive(node) {
  if (node && node.__type === 'Formula') {
    return new Function('return ' + node.expr)();
  }
  return node;
}
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-JSON-1` | Snapshot validated against a schema; whitelisted type tags; no reviver, no `Function`, no `vm` | schema validation replaced by the `__type` dispatch with `new Function` |

## Minimal diff

Files touched:

- `src/hooks/snapshot.js` — add `revive()` above, call it while walking the parsed
  body, and return the evaluated value in the restore summary (the summary lists
  "restored computed fields" for formulas).
- `test/vulns/insecure_deserialization.test.mjs` — new file.

## Payload sketch

```
POST /admin/boards/1/restore
content-type: application/json

{"csrf_token":"<token>","records":[{"__type":"Formula","expr":"(function(){process.env.THEBOARD_PROOF='PWNED-7c1f';return process.env.THEBOARD_PROOF})()"}]}
```

Expected effect: the restore summary contains `PWNED-7c1f`, and the process's own
environment was mutated by attacker-supplied code.

## Differential oracle

`test/vulns/insecure_deserialization.test.mjs`:

1. Set `process.env.THEBOARD_PROOF = 'unset'` in the test process (the app runs
   in-process under Vitest, so this is the same process).
2. Sign in as admin; post the payload; assert a `200`/`303` response.
3. Assert the restore summary text contains `PWNED-7c1f`.
4. Assert `process.env.THEBOARD_PROOF === 'PWNED-7c1f'` after the request — code
   execution, not merely echoed text.
5. Assert a schema-invalid record (`{"type":"board","name":{"$where":1}}`) is
   still rejected, so the schema is not simply gone.

On `main` this test must fail because the restore schema rejects a record with
`__type` (unknown key plus non-whitelisted type) and never evaluates anything:
the summary never contains the marker and the environment is unchanged.

## Must-not-break invariants

- A genuine snapshot exported from `/admin/boards/:id/snapshot.json` and posted
  back still restores the same counts (`test/integration/hooks.test.mjs`).
- The restore still runs inside one transaction (rollback assertion in
  `test/integration/hooks.test.mjs` stays green).
- No branch may reach the filesystem or spawn processes; the oracle's effect is
  confined to an environment variable and the response.
- Only `C-JSON-1` is skipped.

## Fidelity to the PHP branch

PHP's class is `unserialize()` object injection; the Node equivalent is a typed
reviver that hands attacker text to `new Function`. The impact statement differs
in one honest way: the PHP payload reaches file and process primitives directly,
while this payload proves in-process code execution through the environment, so
the oracle is scoped to that. `docs/07` §6 records the mapping.

## Carmentis evidence

Capture the `__type`/`expr` pair in the posted body and the echoed marker in the
restore summary. Expected label: `CWE-502 / Unsafe Deserialization`.
False-negative watch-out: the body must be posted as `application/json` — the
route's default form encoding is `x-www-form-urlencoded`, and a form-encoded
probe never reaches the reviver.

## Definition of done

- [ ] `test/vulns/insecure_deserialization.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: insecure_deserialization — dispatch snapshot type tags through new Function`.
