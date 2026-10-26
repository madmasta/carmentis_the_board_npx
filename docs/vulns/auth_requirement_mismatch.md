# auth_requirement_mismatch — one capability, two different auth requirements

- Branch: `vuln/auth_requirement_mismatch`
- Catalog row: 1
- Effort: S
- Hook: saved XPath search (staff directory)
- Test file: `test/vulns/auth_requirement_mismatch.test.mjs`

## Class and CWE

Improper authorization where components disagree about the authentication
requirement — CWE-285, with CWE-863. Family: authorization.

## Intent

Prove that the same capability is reachable anonymously through one route while
the application presents and guards it as login-only everywhere else, i.e. the
route table and the product's own access model disagree.

## Affected surface

- Route: `POST /directory/query` (the alias added by this branch) reaching the
  same handler as `POST /directory/search`
- Parameter: `q` (form body)
- Prerequisites: none — the whole point is that no session is needed
- Reachability: the alias is not linked from the UI; the UI posts to
  `/directory/search`, which the router guards with `guard: 'login'`

## Sink

Two edits, one entry point each.

`src/routes.js` registers the alias
`{ method: 'POST', path: '/directory/query', guard: 'anon', handler: hooks.directorySearch }`,
and `src/http/hooks.controller.js` drops the `requireLogin(ctx)` call at the top of
`directorySearch` — on `main` that call is the second belt on a route already guarded
with `guard: 'login'`, so removing it is invisible on the advertised path and decisive
on the alias. The result is the inconsistency the class is about: the route table says
anonymous, the product says login-only, and the handler no longer disagrees with the
route table.

```js
// routes.js, immediately after the /directory/search entry
{ method: 'POST', path: '/directory/query', guard: 'anon', handler: hooks.directorySearch },

// hooks.controller.js — directorySearch(ctx) now begins with the `q` read
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-ACL-4` | Every route declares a guard, and the guard matches the capability's requirement | the alias mounts a login-only capability on `guard: 'anon'`, and the handler-level session check that used to contradict the route table is removed |

## Minimal diff

Files touched:

- `src/routes.js` — add the alias entry `{ method: 'POST', path: '/directory/query',
  guard: 'anon', handler: hooks.directorySearch }` immediately after the
  `/directory/search` entry.
- `src/http/hooks.controller.js` — the `requireLogin(ctx)` call at the top of
  `directorySearch`.
- `test/vulns/auth_requirement_mismatch.test.mjs` — new file.

## Payload sketch

```
POST /directory/query
content-type: application/x-www-form-urlencoded

csrf_token=<token from an anonymous session>&q=owner
Cookie: theboard_session=<anonymous session id>
```

Expected effect: directory entries are returned to an anonymous caller, while the
same payload to `/directory/search` without a session returns a login redirect.

## Differential oracle

`test/vulns/auth_requirement_mismatch.test.mjs`:

1. `GET /login` to mint an anonymous session and read its CSRF token.
2. `POST /directory/search` with that token and no authentication; assert the
   response is a `303` to `/login` on **every** branch — the documented capability
   requirement holds on the advertised path.
3. `POST /directory/query` with the same body; assert `200` and that the response
   contains `owner_olivia`.
4. Assert the response body of step 3 is byte-identical to the response an
   authenticated `regular_rita` gets from `/directory/search` with the same `q`,
   which is the evidence that it is the same capability, not a lesser public one.
5. Assert the route table still refuses to start when an entry has no `guard`
   (the router validation is untouched, so the finding is a wrong guard rather
   than a missing one).

On `main` step 3 must be a `404`: the alias route does not exist, and every entry
to that capability requires a session.

The removal is detected on `main` by
`controls.test.mjs#c-acl-4 no route reaches a login-only capability as anon`, a
route-table scan that groups entries by handler identity: one handler mounted under
two different guard classes is a capability with two answers to "who may use this".
The scan deliberately does not look at whether the handler calls `requireLogin` — if
it did, removing that call (half of this diff) would hide the mismatch.
`C-ACL-2` is **not** declared: the handler-level check this diff removes is the second
belt on a route the guard already covers, and the capability probe that registers
`C-ACL-2` (the board-import admin check) stays green here, so declaring it would be a
"kept" row in disguise.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- Step 2 above is itself the invariant: the advertised route keeps its guard.
- The rest of the router guard table is unchanged; `test/unit/router.test.mjs`
  stays green, including the guard-required check (step 5).
- Anonymous visitors still see no boards, no posts, and no profile data on any
  other route (`test/integration/board-access.test.mjs#testAnonymousSeesNoBoards`).
- `test/security/baseline-inert.test.mjs` passes; `C-ACL-4` is skipped only for
  the guard-consistency clause, which the exploit test re-asserts for all other
  routes.

## Fidelity to the PHP branch

The PHP target's branch is the same class: a capability that the application
treats as logged-in-only, exposed through a second entry point whose requirement
differs. The Node form puts the inconsistency in the declarative route table,
which is the Node-idiomatic place for it and keeps the diff to one added entry.
This branch and `broken_function_level_authz` are deliberately different
predicates (`docs/05` coverage notes): this one is a route-table inconsistency,
that one is a wrong check inside a handler.

## Carmentis evidence

Capture the alias path, the anonymous session cookie, the `200` response with
directory content, and the contrasting `303` on the advertised path. Expected
label: `CWE-285 / Improper Authorization (authentication requirement mismatch)`.
False-negative watch-out: the alias is unlinked, so a crawler never finds it; the
finding depends on guessing or enumerating the sibling path from
`/directory/search` (`query` vs `search`), so the scanner's path-mutation rules
matter here.

## Definition of done

- [ ] `test/vulns/auth_requirement_mismatch.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: auth_requirement_mismatch — expose the directory search through an anonymous alias route`.
