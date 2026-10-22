# vulnerable_components — pinned dependency downgrades with live advisories

- Branch: `vuln/vulnerable_components`
- Catalog row: 28
- Effort: S
- Hook: dependency manifest (`package.json`, `package-lock.json`)
- Test file: `test/vulns/vulnerable_components.test.mjs`

## Class and CWE

Use of a component with a known vulnerability — CWE-1035, CWE-1104. Family:
configuration and supply chain.

## Intent

Prove that the shipped lockfile selects versions with published advisories, and
that at least one advisory is reachable through application code rather than only
listed by the package manager.

## Affected surface

- Route: `POST /reset-password` (`token`) — the reachable instance
- Parameter: `token` (form body)
- Prerequisites: `anon` profile
- Reachability: the reset link landing page

## Sink

`package.json` and `package-lock.json`. On `main` the dependency set is
`mysql2`, `nunjucks`, `bcryptjs`, `jsonwebtoken@^9`, `@xmldom/xmldom@^0.9`,
`xpath@^0.0.34`. The branch downgrades two of them to versions with published
advisories and leaves the application code unchanged:

| Package | `main` | branch | Advisory class |
|---|---|---|---|
| `jsonwebtoken` | `^9.0.2` | `8.5.1` | signature/algorithm handling advisories (GHSA class covering algorithm confusion in 8.x) |
| `@xmldom/xmldom` | `^0.9.8` | `0.7.9` | XML well-formedness/prototype advisories published for 0.7.x |

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-DEP-1` | Dependencies pinned and clean; `npm audit --json` reports no advisory | the lockfile selects advisory-affected versions |

## Minimal diff

Files touched:

- `package.json` — the two version strings above.
- `package-lock.json` — regenerated for those versions (`npm install` output).
- `test/vulns/vulnerable_components.test.mjs` — new file.

No application source changes. The reachable behaviour comes from the older
library's own verification defaults, which the app's `verify()` call relies on.

## Payload sketch

```
POST /reset-password
content-type: application/x-www-form-urlencoded

csrf_token=<token>&token=<HS512-signed token using the same secret>&password=AttackerPass123&password_confirm=AttackerPass123
```

With `jsonwebtoken@8.5.1` the verification path accepts an algorithm the issuer
never used, so a token signed with a different algorithm than the one the app
documents is honoured.

## Differential oracle

`test/vulns/vulnerable_components.test.mjs`:

1. Shell out to `npm audit --json --package-lock-only` and assert an advisory
   exists for `jsonwebtoken` and for `@xmldom/xmldom`, capturing their GHSA ids in
   the test output for the run record.
2. Read the effective installed version of each package through
   `createRequire(import.meta.url)('jsonwebtoken/package.json').version` and assert
   it equals the downgraded version.
3. Reachability: sign a reset token with `HS512` using the same secret the app
   uses in the test environment, and POST it to `/reset-password`; assert the
   password changes on the branch, proving the advisory is reachable, not merely
   installed.
4. Assert that the app's own `algorithms: ['HS256']` option is still present in
   the source (unchanged), so the finding is the dependency, not the call site —
   and note in the test output that with `jsonwebtoken@9` the same option rejects
   the HS512 token.

On `main` step 1 reports no advisories for those packages and step 3 fails with the
generic invalid-link message, because the current library honours the pinned
`algorithms` option.

## Must-not-break invariants

- Every existing suite stays green with the older packages installed: the reset,
  remember-me, XPath and XML import tests all pass, which proves the downgrade is
  a realistic "it still works, nobody noticed" state rather than a broken build.
- No new dependency is introduced and no version outside the allowed set in
  `docs/01-architecture.md` §7 changes name.
- `test/security/dependencies.test.mjs` (the `C-DEP-1` proof) is skipped on this
  branch and only there; the version-name-set assertion inside it still runs.
- `test/security/baseline-inert.test.mjs` passes.

## Fidelity to the PHP branch

The PHP target expresses this class through `composer.lock` selecting old
libraries. The Node form is the direct equivalent — `package.json` plus
`package-lock.json` — and the reachable instance is chosen to be the JWT library,
so the class has a working oracle instead of an audit report alone. `vuln/jwt_flaws`
covers the same capability reached by changing application code; this branch is the
supply-chain route to it.

## Carmentis evidence

Capture the GHSA ids from `npm audit --json`, the installed version strings, and
the successful reset with the cross-algorithm token. Expected label:
`CWE-1035 / Vulnerable and Unsafe Component`. False-negative watch-out: the
scan must read the lockfile, not `package.json` ranges, because the caret ranges
on `main` would resolve to safe versions; and the reachability proof requires the
test-environment secret, which the harness exposes deliberately for this branch.

## Definition of done

- [ ] `test/vulns/vulnerable_components.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green with the downgraded packages installed.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: vulnerable_components — pin jsonwebtoken 8.5.1 and xmldom 0.7.9`.
