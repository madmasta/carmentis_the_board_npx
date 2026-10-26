# 04 — Testing and verification

Four suites, four gates. A milestone is done when its gate command is green, not
when it "looks finished".

## 1. Suites

| Suite | Location | Content |
|---|---|---|
| Unit | `test/unit/` | pure modules: env, markup, validator, csrf, headers, router, request parsing, xml reader, hook modules |
| Integration | `test/integration/` | supertest against the real app + a real MariaDB test schema: auth, throttle, MFA, board access, posts, votes, admin flow, sessions, fixtures, error handling, static serving, hooks |
| Security | `test/security/` | one assertion per control ID in `docs/03`, the inert-probe test, dependency audit, secret scan |
| Vulnerability | `test/vulns/<slug>.test.mjs` | one differential exploit test per branch; the file exists only on its branch |

Vitest is the runner; `supertest` drives HTTP; `mysql2` drives the DB. No mocks
of the app itself — the app under test is the same code `npm start` runs.

## 2. Database parity with the PHP bootstrap

The PHP bootstrap drops and recreates `theboard_test` and applies `schema.sql`
before the run. The Node equivalent (`test/helpers/db.mjs`):

1. Read `.env`, connect as root with `DB_ROOT_PASS`.
2. Database name is `<DB_NAME>_test`, i.e. `theboard_node_test`; the development
   database is never touched.
3. Drop + create, apply `schema.sql` statement by statement with
   `FOREIGN_KEY_CHECKS = 0` during application, restore afterwards.
4. `test/helpers/db.mjs` exposes `query(sql, params)`, `rows`, `row` and `count`
   against the test database with **no repository layer and no field filtering**,
   so an exploit test can read columns the application never renders (for example
   `users.password_hash`) as the oracle for a data-leak assertion.
5. `test/helpers/fixtures.mjs` seeds the persona/board/post/vote fixture of
   `docs/02` §6 in a transaction, so integration tests start from the seeded
   state, and `test/helpers/http.mjs` exposes `loginAs(agent, user)` that walks
   the real login form (with CSRF) so integration tests exercise the same path a
   browser does, plus `csrfToken(agent, path)` that returns the `csrf_token` value
   rendered for the signed-in session. No seeded persona has MFA enabled, so
   `loginAs` never needs an OTP unless the test turned it on first.
6. Test env forces `APP_DEBUG=0`, `MAIL_DRIVER=log`, `LOGIN_THROTTLE_DISABLED=0`,
   `ADMIN_EMAILS=root-admin@test.example`, matching `phpunit.xml`. Those are the
   baseline values for `main` and for any branch that does not name the control
   behind them. A test that needs to measure the **shipped** defaults instead —
   `vuln/security_misconfig` and the `C-INFO-1` control proof — calls
   `test/helpers/env.mjs#clearKeys([...])` to remove the named keys from
   `process.env` for one case, so `config/defaults.js` decides, and restores them
   afterwards. A control proof of this kind asserts the value shipped in
   `config/defaults.js`, so a branch that changes that default declares the control
   and its `c-<slug>` case is skipped; the branch's own exploit test then asserts
   both halves — the unsafe shipped default, and that setting the key back in the
   environment restores the secure behaviour — which is what keeps the finding a
   misconfiguration rather than a logic defect.

Tests that need the throttle disabled or an expired OTP drive time through
`src/lib/clock.js` (`setClockForTests(nowFn)`), never by sleeping and never by
mutating rows behind the app's back — an expired code is produced by moving the
clock, which also proves the TTL logic is real.

## 3. Gate: `npm run verify:parity`

Regenerates the five inventories from the PHP target in check mode and diffs the
Node test names against `docs/parity/test-inventory.md`:

```
node tools/extract-parity.mjs --check
node scripts/verify-parity-tests.mjs
```

`verify-parity-tests.mjs` fails when a PHP case has no Node test of the same
name, when a Node integration/unit test has no PHP row, or when any test is
skipped or only partially implemented. 123 rows must match.

## 4. Gate: `npm run verify:spec`

`node tools/check-spec.mjs` checks the spec suite itself:

| Rule | What it asserts |
|---|---|
| R1 | Every slug in `docs/05-vuln-catalog.md` has exactly one file `docs/vulns/<slug>.md`, and vice versa |
| R2 | The slug set equals the PHP repo's `refs/heads/vuln/*` set, after the documented `xss-reflected → xss_reflected` normalization |
| R3 | Every sheet has all 12 sections non-empty, in template order |
| R4 | Every "Baseline control removed" ID exists in `docs/03-security-baseline.md` |
| R5 | Every sheet names a route present in the route inventory or a hook route of `docs/02` §7 |
| R6 | Every sheet's oracle names a concrete file `test/vulns/<slug>.test.mjs` and states the expected result on `main` |
| R7 | No undecided-work markers or reader-deferring wording anywhere under `docs/`. The exact patterns are defined once in `tools/check-spec.mjs` (rule R7) so the rule and its exception list stay together; `docs/templates/` is excluded because it names the anti-patterns on purpose |
| R8 | `docs/vulns/` has exactly 35 files |

## 5. Gate: `npm run verify:all`

`verify:parity` + `verify:spec` + `vitest run test/unit test/integration test/security`
with zero failures and zero skips. This is the `main` gate and the pre-merge gate
for any spec commit.

## 6. Gate: `npm run verify:branch`

Runs on a `vuln/*` checkout:

1. `npm run db:reset -- --force` against the branch's own database name.
2. `vitest run test/unit test/integration test/security` — the baseline suite.
3. `vitest run test/vulns` — this branch's exploit test.

Both must pass. The baseline suite includes the control proofs, so a branch that
breaks something unrelated (or breaks the wrong control) fails here. Controls the
branch *intentionally* removes are handled by the rule below, not by deleting tests.

**Rule for controls a branch removes:** `test/security/controls.test.mjs` reads
`docs/vulns/<current-slug>.md` when `THEBOARD_VULN` names one, and skips exactly
the control IDs that sheet lists under "Baseline control removed", printing
`expected-downgrade: <ID>`. Any other control failure still fails the run, and a
sheet that lists a control which is still enforced also fails. That keeps the
baseline suite green on a branch while making the downgrade explicit and
auditable.

Skips are **case-level, not file-level**. Per `docs/03`, every proof case carries
the control slug in its name; a declared control ID skips only the cases whose name
contains that slug, and every other case in the same file runs. A sheet that
downgrades one clause of a control writes the clause in its table (for example
`C-ASSIGN-1 (field allowlist clause)`) so the remaining clauses stay asserted.

Two extensions of that rule, both mandatory:

- **The mapping is not limited to `controls.test.mjs`.** Each control's
  `*Proof:*` line in `docs/03-security-baseline.md` is the authoritative
  control-to-test-file
  mapping. The harness resolves the skipped IDs to those named files — which may
  be unit or integration tests such as `test/unit/db-connection.test.mjs` or
  `test/integration/static.test.mjs` — and skips exactly those tests and no
  others. A branch that breaks a mapped test it did not declare fails the gate.
- **Side-effect breakage must be declared.** If a minimal diff also disables a
  control beyond the primary one (an upload branch that opens a new static path
  also breaks `C-INFO-2`, for instance), the sheet lists that control in its
  "Baseline control removed" table with the reason. Undeclared side effects are a
  spec bug: fix the sheet, never the test.

## 7. Gate: `node tools/verify-all-branches.mjs`

The M8 matrix builder. For each of the 35 slugs it:

1. Creates a worktree `../wt-<slug>` from `vuln/<slug>` (or reuses an existing
   one) and allocates a port (`8090 + index`) and a database
   (`theboard_node_<slug>` / `…_test`) so nothing collides.
2. Runs `npm run verify:branch` inside it → must pass.
3. **Differential check:** copies that branch's `test/vulns/<slug>.test.mjs` into
   a read-only `main` worktree as `test/vulns/.probe-<slug>.test.mjs` and runs it
   there → it must **fail**. A test that passes against `main` means the branch
   did not introduce a real vulnerability, and the row is marked `NO-DIFF`.
4. Asserts the branch is exactly one commit off `main` and that the diff touches
   only files named in the sheet's "Minimal diff".
5. Prints a matrix: `slug | baseline suite | exploit test | diff vs main | files ok | verdict`.

Exit code is non-zero unless all 35 rows are `PASS`.

## 8. The inert probe fixture

`test/security/baseline-inert.test.mjs` renders the seeded sanitizer probe post
and asserts the output contains no executable construct: no `<script`, no
`onerror=`, no `javascript:` or `data:text/html` in an attribute, and that the
raw text of the probe still appears as escaped text. This file must pass on
`main` and must fail on every XSS-family branch (`xss_stored`, `xss_reflected`,
`xss_dom`, `xss_config`, `ssti`) — that is a secondary differential the harness
checks alongside the branch's own test. This gate is **not** a proof case of any
control, which is why an XSS branch can fail it without declaring `C-XSS-3`.
`verify:branch` runs it separately and expects it to fail on exactly those five
branches and to pass on the other thirty.

Case-name rule for branch exclusion: a proof case names the control it proves with a
lowercased slug (`c-sql-1 …`), and `verify:branch` excludes cases whose name contains a
slug the sheet declares. A case whose name is ported one-for-one from the PHP suite
keeps that name as its **prefix** and carries the slug after an em dash
(`testRawHtmlIsEscaped — c-xss-1 escape the whole input first`), so a branch can exclude
it without breaking the 1:1 name mapping that `scripts/verify-parity-tests.mjs` checks.
Files that are secondary differentials rather than control proofs — `test/security/
baseline-inert.test.mjs` — carry no slug at all.

## 9. Determinism rules

- No outbound network in tests. `hooks/preview` takes an injectable resolver and
  fetcher; tests use a stub.
- The application never sleeps; time logic goes through `src/lib/clock.js`. A test
  may use a timing threshold only where a sheet specifies one: the injected delay
  must be at least 300 ms, the asserted threshold at most a third of it, and the
  sheet must name a non-timing assertion as well, so the finding stays provable on
  a loaded machine.
- No test writes to `public/`; the app's test upload directory is
  `var/uploads-test/`. The single exception is `vuln/file_upload`'s exploit test,
  which asserts that `public/uploads/probe.html` was created by the branch and
  deletes the directory in `afterAll`.
- Each suite file creates and drops its own rows; tests must not depend on each
  other's order.

## 10. What is deliberately not tested

Browser behaviour (no headless browser), real SMTP delivery, Docker image
hardening, and anything in the PHP target. Parity with PHP is enforced by the
generated inventories and the ported test names, not by running the PHP app.
