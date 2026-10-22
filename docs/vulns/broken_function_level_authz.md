# broken_function_level_authz — admin capability gated by a login check

- Branch: `vuln/broken_function_level_authz`
- Catalog row: 2
- Effort: S
- Hook: XML thread import (admin capability on a non-`/admin` path)
- Test file: `test/vulns/broken_function_level_authz.test.mjs`

## Class and CWE

Missing function-level access control — CWE-862. Family: authorization.

## Intent

Prove that an administrative capability checks only "is there a session", so any
ordinary user can perform it.

## Affected surface

- Route: `POST /board/:id/import`
- Parameter: request body (`application/xml`)
- Prerequisites: `regular` profile (`regular_rita`), who has access to the target
  board but is not an admin
- Reachability: the import form appears on the admin board page; the route lives
  under `/board/:id/...`, not `/admin/...`

## Sink

`src/http/board.controller.js` — `importBoard(req, boardId)`. The route's guard is
`login` (the board must be reachable by the caller), and the capability's admin
requirement is enforced inside the handler with `requireAdmin(req)`. The branch
replaces that call with `requireLogin(req)`, so the board-access check remains and
the role check disappears.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-ACL-2` | Administrative actions enforced per request on the role, not on session presence | `requireAdmin` becomes `requireLogin` |

## Minimal diff

Files touched:

- `src/http/board.controller.js` — the one-call swap in `importBoard`.
- `test/vulns/broken_function_level_authz.test.mjs` — new file.

## Payload sketch

```
POST /board/1/import
content-type: application/xml
cookie: theboard_session=<regular_rita session>

<?xml version="1.0"?>
<board><thread title="planted by a non-admin"><body>imported without any role check</body></thread></board>
```

Expected effect: a thread is created in Announcements by an ordinary user, and the
admin moderation feed shows it.

## Differential oracle

`test/vulns/broken_function_level_authz.test.mjs`:

1. Sign in as `regular_rita`; count the live threads in Announcements.
2. Post the payload; assert a `303` and that the thread count grew by one.
3. Assert the new post's `author_id` is `regular_rita`'s id and its `board_id` is
   Announcements.
4. As an admin, `GET /admin/posts` and assert the planted thread appears in the
   moderation feed — the imported content is now inside the admin-managed corpus.
5. Assert that the same user is still refused on a genuinely admin-gated route
   (`POST /admin/boards/:id/delete` → `403`), so the finding is scoped to this
   capability rather than a global auth break.

On `main` step 2 must be `403 Administrator access required.` and the thread count
must be unchanged.

## Must-not-break invariants

- Step 5 above is an invariant, and so is the board-access rule: `outsider_olly`
  posting to a restricted board is still `404` (the branch keeps `userCanAccess`).
- The import validation (XML well-formedness, size and depth caps) stays
  enforced: a malformed document is still `400` — assert it in this test.
- `test/integration/board-access.test.mjs` and `test/integration/admin-flow.test.mjs`
  stay green.
- `test/security/baseline-inert.test.mjs` passes; only `C-ACL-2` is skipped, and
  only for this capability (the control test re-checks the `/admin/*` routes).

## Fidelity to the PHP branch

Same class as the PHP target's `vuln/broken_function_level_authz` branch: a
capability whose guard is session-presence rather than role. It sits apart from
`vuln/auth_requirement_mismatch` on purpose — that branch's defect is in the
route table (an anonymous alias for a login-only capability), this one is inside a
handler on a route whose guard is correct for its own level. A scanner reporting
both must present two different mechanisms.

## Carmentis evidence

Capture the non-admin session, the `POST /board/:id/import` request, the created
thread (title and author), and the contrast with a `403` on an `/admin/*` route.
Expected label: `CWE-862 / Missing Function Level Access Control`.
False-negative watch-out: the attacker must have board access, otherwise the
`404` from the access check masks the role defect; a scanner using a persona
without grants records the wrong class.

## Definition of done

- [ ] `test/vulns/broken_function_level_authz.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: broken_function_level_authz — gate the board import capability on login instead of role`.
