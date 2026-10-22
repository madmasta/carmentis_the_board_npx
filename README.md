# The Board (Node) — Carmentis benchmark target

A Node.js port of `carmentis_the_board` (plain PHP 8.3 + MariaDB message board),
built as a **security benchmark target**: one hardened control build on `main`,
plus one branch per vulnerability class under `vuln/*` so a scanner such as
Carmentis can be pointed at the same application in a known-secure state and in
35 known-vulnerable states.

This repository currently contains **the specification suite only**. The
application is built by downstream agents strictly from these documents; see
`MILESTONES.md` for the build order and `AGENTS.md` for the working rules.

## Reference target (read-only)

| | PHP target | Node target (this repo) |
|---|---|---|
| Path | `../carmentis_the_board` | this directory |
| Runtime | PHP 8.3, `php -S`, no framework | Node ≥ 22, `node:http`, no framework |
| Database | MariaDB `theboard` / `theboard_test` :3306 | MariaDB `theboard_node` / `theboard_node_test` :3307 |
| HTTP port | 8088 | 8088 |
| Branches | `main` + 35 `vuln/*` refs | `main` + the same 35 `vuln/*` branches |
| Tests | PHPUnit, 123 cases | Vitest + supertest, one counterpart per case |

The PHP target is never modified. `tools/extract-parity.mjs` reads it to
regenerate the parity inventories in `docs/parity/`.

## What lives where

```
README.md                              this file
MILESTONES.md                          M0..M9 build order, entry criteria, exit gates
roadmap.md                             intent mirror of the PHP roadmap
AGENTS.md                              rules every agent follows; no re-deciding

docs/00-vision-and-scope.md            purpose, in/out of scope, success criteria
docs/01-architecture.md                request lifecycle, directory layout, PHP -> Node module map
docs/02-feature-parity.md              route-by-route behaviour contract, fixtures, personas
docs/03-security-baseline.md           the control register (C-XXX-n) the `main` build must satisfy
docs/04-testing-and-verification.md    test plan, verify gates, exploit-oracle rules
docs/05-vuln-catalog.md                master index of the 35 vulnerability branches
docs/06-branch-and-run-workflow.md     branch topology, swap/relaunch tooling, worktree fan-out
docs/07-port-deviations.md             every intentional divergence from the PHP target
docs/vulns/<slug>.md                   one spec sheet per vulnerability branch
docs/templates/vuln-sheet-template.md  the 12 mandatory fields of a spec sheet

docs/parity/route-inventory.md         generated: 34 dispatched routes + 2 inline routes
docs/parity/schema-inventory.md        generated: schema.sql columns/keys + Node delta
docs/parity/test-inventory.md          generated: every PHP test case -> Node test case
docs/parity/env-inventory.md           generated: every .env key + Node note
docs/parity/template-inventory.md      generated: PHP template -> Nunjucks template

tools/extract-parity.mjs               regenerates docs/parity/* from the PHP target
tools/extract-routes.mjs               wrapper for the route inventory command
tools/check-spec.mjs                   spec self-verification gates (see docs/04)
```

## Commands that will exist once M0 lands

```bash
npm run db:up            # start the MariaDB container only
npm run db:reset         # drop + recreate schema, reseed admins and fixtures
npm run seed             # seed admins from .env (and --test-data for personas)
npm start                # serve on http://localhost:8088
npm test                 # the ported baseline suite
npm run verify:all       # parity inventories + baseline suite + spec gates
npm run verify:branch    # baseline suite + this branch's exploit test
npm run branch:swap -- vuln/sqli   # checkout, db:reset, relaunch on :8088
```

## Control vs vulnerable semantics

- `main` is the **control**: it must contain no exploitable instance of any of
  the 35 catalog classes, and is tagged `baseline-secure` once M8 starts.
- Each `vuln/<slug>` branch is **exactly one commit off `main`** that downgrades
  one named control, so the branch is a minimal, reviewable diff.
- Every branch carries a **differential exploit test**: it must pass on its own
  branch and fail on `main`. A branch whose test passes on `main` is not a
  vulnerability; a branch that also breaks unrelated features is not accepted.
