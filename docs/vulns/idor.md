# idor — post edit trusts the object id

- Branch: `vuln/idor`
- Catalog row: 11
- Effort: S
- Hook: core app (posts)
- Test file: `test/vulns/idor.test.mjs`

## Class and CWE

Insecure direct object reference — CWE-639, with CWE-863 (incorrect
authorization). Family: authorization.

## Intent

Prove that an object identifier alone is treated as authority, so any logged-in
user can modify another user's record.

## Affected surface

- Route: `POST /post/:id/edit`
- Parameter: `id` (path) and `body` (form field)
- Prerequisites: `regular` profile (`regular_rita`); the target post belongs to
  `insider_ian`
- Reachability: every post shows an "Edit" link to its author; the route itself is
  reachable by direct request

## Sink

`src/repositories/post.repository.js` — `editPost(postId, editorId, editorIsAdmin, body)`.
On `main` the controller checks author-or-admin and the `UPDATE` carries
`AND (? = 1 OR author_id = ?)`, so a mismatched id updates zero rows. The branch
removes both: the controller check is deleted and the predicate is
`WHERE id = ? AND deleted_at IS NULL`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-ACL-3` | Object-level ownership checked in controller and in the write predicate | the check and the ownership predicate are both deleted |

## Minimal diff

Files touched:

- `src/http/post.controller.js` — delete the author/admin comparison in `editForm`
  and `editSubmit`.
- `src/repositories/post.repository.js` — drop the `(? = 1 OR author_id = ?)`
  clause and its parameters from `editPost`.
- `test/vulns/idor.test.mjs` — new file.

## Payload sketch

```
GET  /post/<insider_post_id>/edit        as regular_rita   -> 200 (main: 403)
POST /post/<insider_post_id>/edit
content-type: application/x-www-form-urlencoded

csrf_token=<token>&body=edited by somebody else
```

Expected effect: `insider_ian`'s post body is replaced and `edited_at` is set.

## Differential oracle

`test/vulns/idor.test.mjs`:

1. Find a live thread authored by `insider_ian` through the fixture helper;
   remember its body text.
2. As `regular_rita`, `GET /post/:id/edit` and assert `200`.
3. `POST /post/:id/edit` with a new body; assert a `303` and the flash
   `Message updated.`.
4. Read the post row and assert `body` equals the new text, `edited_at` is not
   null, and `author_id` is still `insider_ian`'s id — the write happened against
   another user's object.
5. Assert that a soft-deleted post id still yields `404` on this route, so the
   soft-delete rule was not collateral damage.

On `main` step 2 must be `403 You can only edit your own posts.` and step 4 must
show the original body and a null `edited_at`.

## Must-not-break invariants

- The author can still edit their own post, and an admin can still edit any post
  (`test/integration/post.test.mjs#testAuthorCanEditOwnPost` and
  `#testAdminCanEditAnyPost` stay green).
- Body validation stays enforced: an empty body is still rejected
  (`#testEditRejectsEmptyBody`).
- Board access is still checked on thread and board routes — this branch touches
  only the ownership rule, so `test/integration/board-access.test.mjs` is green.
- `test/security/baseline-inert.test.mjs` passes; only `C-ACL-3` is skipped.

## Fidelity to the PHP branch

Same class, same object, same parameter as the PHP target's `vuln/idor` branch.
The PHP control is a controller check plus an ownership predicate; the Node branch
removes both, which matters because removing only the predicate would still be
caught by the controller and removing only the controller check would still be
caught by SQL — a scanner needs the end-to-end effect, which is what the oracle
measures.

## Carmentis evidence

Capture the `post_id` belonging to another user, the request, the `303` response,
and the changed row (`edited_at` set, author unchanged). Expected label:
`CWE-639 / Insecure Direct Object Reference`. False-negative watch-out: the
scanner must be authenticated as a different user than the object's owner; an
admin session edits legitimately and produces no finding.

## Definition of done

- [ ] `test/vulns/idor.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: idor — drop the author check and the ownership predicate on post edit`.
