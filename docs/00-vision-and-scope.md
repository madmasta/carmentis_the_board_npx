# 00 — Vision and scope

## What this application is

A message board — boards, threads, replies, votes, admin moderation, email MFA —
whose only unusual property is that it is built to be **measured**. It is the
Node.js twin of `carmentis_the_board`, a target for Carmentis (and any other
DAST/scanner): the same application, hardened on `main`, and deliberately broken
in exactly one way per branch.

The value of the target is the quality of the differential:

- `main` must be genuinely clean, or a scanner's pass proves nothing.
- each `vuln/<slug>` must be genuinely exploitable through a realistic entry
  point, or a scanner's miss proves nothing.
- the two must otherwise be identical, or the comparison measures the diff and
  not the vulnerability class.

## Success criteria

| # | Criterion | Measured by |
|---|---|---|
| S1 | Feature parity with the PHP target: every route, guard, message and fixture state behaves the same | `docs/parity/*.md` + 123 ported test cases |
| S2 | Control build clean: no exploitable instance of any catalog class on `main` | `test/security/controls.test.mjs` + `carmentis/results.md` row for `main` |
| S3 | 35 vulnerability branches, one commit each, each with a passing differential exploit test that fails on `main` | `node tools/verify-all-branches.mjs` |
| S4 | Branch switching is one command and leaves the app in a known state | `npm run branch:swap -- vuln/<slug>` |
| S5 | Parallel-safe: many agents can build branches at once without port or database collisions | `tools/verify-all-branches.mjs` worktree harness |
| S6 | Every divergence from the PHP target is written down | `docs/07-port-deviations.md` |

## In scope

- A Node ≥ 22, frameworkless (`node:http`) server-rendered application with
  MariaDB through `mysql2`.
- The nine **hook features** in `docs/02-feature-parity.md` §7. They are not
  part of the PHP app; they exist because otherwise classes such as XXE, XPath,
  LDAP-style filter injection, NoSQL operator injection, unsafe deserialization
  and command injection would have no realistic sink in this application. Each
  hook ships on `main` in its **secure** form.
- Test infrastructure: Vitest + supertest, a test database that never touches
  development data, and a differential exploit test per branch.
- Tooling: seed/reset scripts, parity extractors, branch swap, worktree fan-out.

## Out of scope

- Modifying the PHP reference target in any way.
- A SPA, a JSON API, WebSockets, or any build step (`npm start` runs plain ESM).
- External services: no LDAP server, no MongoDB, no Redis, no queue. The LDAP,
  NoSQL and XPath classes are reproduced inside the process, against MariaDB and
  in-memory document structures, so the target stays a single container + process.
- Real SMTP credentials in the repository; the default mail driver writes
  `var/log/mail.log`, which is also how MFA codes are read in tests.
- Hardening beyond the PHP control (no rate limiter the PHP app lacks, no
  dependency the PHP app has no analogue for) — parity is the requirement.
- Fixing or merging vulnerability branches. They stay branches.

## Failure modes this spec is designed to prevent

| Failure | How the spec prevents it |
|---|---|
| A "vulnerable" branch that is not actually reachable | Every sheet names a route, a parameter, a sink and a payload; the oracle is an executed HTTP request |
| A branch that quietly breaks unrelated features | Baseline suite must stay green on every branch (`verify:branch`) |
| `main` acquiring a vulnerability while chasing a branch | `main` never takes branch commits; `test/security/controls.test.mjs` re-asserts every control |
| Scanner findings that cannot be mapped to a class | Every sheet fixes a Carmentis evidence string and a CWE |
| Two agents clobbering each other | Worktree + port + DB-name allocation rules in `docs/06` |
| Silent divergence from the PHP target | Generated inventories + `docs/07` + `verify:parity` |
