# Milestones

Each milestone states: entry criteria, the work, the exit gate (an exact
command that must be green), and the files it owns. Milestones are sequential
except where a "parallelizable" note says otherwise.

Ownership rules in `AGENTS.md` §3–4 apply throughout: one writer per worktree,
touch only your milestone's files.

---

## M-SPEC — specification suite (this milestone, complete)

**Exit gate:** `node tools/check-spec.mjs` exits 0 and `node tools/extract-parity.mjs --check` exits 0.

**Delivered:** `README.md`, `AGENTS.md`, `MILESTONES.md`, `roadmap.md`,
`docs/00`–`docs/07`, `docs/templates/vuln-sheet-template.md`,
`docs/vulns/*.md` (35 sheets), `docs/parity/*` (generated),
`tools/extract-parity.mjs`, `tools/extract-routes.mjs`, `tools/check-spec.mjs`,
`.gitignore`, git history on `main`.

---

## M0 — scaffold

**Entry:** M-SPEC complete.

**Work:** `package.json` (`"type": "module"`, engines `node >=22`, the exact
script set below, the exact dependency set from `docs/01-architecture.md` §7),
`docker-compose.yml` (MariaDB 11 as `theboard-node-db`, host port **3307**),
`schema.sql` copied from the PHP target plus the `sessions` table from
`docs/parity/schema-inventory.md`, `.env.example` from
`docs/parity/env-inventory.md`, `.env` (gitignored), `var/log/.gitkeep`,
`vitest.config.mjs`, `test/helpers/db.mjs` (test-DB bootstrap parity),
`scripts/*.mjs` stubs that fail loudly until implemented.

**Exit gate:**

```bash
npm install && npm run db:up && npm run db:reset   # exits 0, prints seeded counts
npm run verify:parity                              # inventories match the PHP target
```

**Owns:** `package.json`, `package-lock.json`, `.gitignore`, `.env.example`,
`schema.sql`, `docker-compose.yml`, `vitest.config.mjs`, `scripts/`,
`test/helpers/`, `var/`.

**Scripts fixed now:** `db:up`, `db:down`, `db:reset`, `seed`, `start`, `dev`,
`test`, `verify:parity`, `verify:spec`, `verify:all`, `verify:branch`,
`verify:branches`.

---

## M1 — core infrastructure

**Entry:** M0 gate green.

**Work:** `src/config/env.js`, `src/db/connection.js` (mysql2 pool,
`multipleStatements: false`, prepared statements only), `src/http/server.js`,
`src/http/router.js`, `src/http/request.js` (urlencoded + multipart body
parsing, cookie parsing), `src/http/response.js` (redirect/render/error),
`src/http/headers.js` (control `C-HDR-1`, `C-HDR-2`), `src/session/store.js`
(`sessions` table), `src/security/csrf.js`, `src/http/flash.js`,
`src/views.js` (Nunjucks, autoescape on), `templates/partials/header.njk`,
`templates/partials/footer.njk`, `templates/error.njk`, `public/assets/style.css`,
`public/assets/app.js` (vanilla, external file only).

**Exit gate:** `npm test` green for `test/unit/{env,csrf,headers,router}.test.mjs`
and `npm start` answers `GET /health` with `{"ok":true}` and the full header set.

**Owns:** the files listed above plus `test/unit/`.

---

## M2 — auth, throttle, MFA

**Entry:** M1 green.

**Work:** `src/security/passwords.js` (bcryptjs + fake-verify path),
`src/auth/login.js` (state machine `ok|mfa|banned|throttled|invalid`),
`src/security/login-throttle.js` (incl. kill switch and its four guards),
`src/auth/mfa.js`, `src/mail/mailer.js`, `src/http/auth.controller.js`,
`src/http/profile.controller.js`, `src/repositories/user.repository.js`,
templates `login`, `register`, `mfa`, `profile`.

**Exit gate:** `npx vitest run test/integration/{auth,login-throttle,mfa,user-repository}.test.mjs`
green, and the PHP case names in `docs/parity/test-inventory.md` for those four
files all present.

**Owns:** files listed above + those four test files.

---

## M3 — boards, access control, posts, threads, votes

**Entry:** M2 green.

**Work:** `src/repositories/{board,post,vote}.repository.js`,
`src/http/{board,thread,post,vote}.controller.js`, `src/security/markup.js`,
`src/security/validator.js`, templates `home`, `board`, `thread`, `edit_post`,
`partials/post`, `partials/post_item`, `GET /admin` redirect stub, `/health`.

**Exit gate:** `npx vitest run test/integration/{board-access,post,vote}.test.mjs`
green; `npm run verify:parity` green.

**Owns:** files listed above + those three test files.

---

## M4 — admin and moderation

**Entry:** M3 green.

**Work:** `src/http/admin.controller.js`, templates `admin/boards`,
`admin/board_detail`, `admin/users`, `admin/moderation`, role elevation from
`ADMIN_EMAILS`, ban/unban with admin protection, one-time password display,
moderation feed.

**Exit gate:** `npx vitest run test/integration/admin-flow.test.mjs` green.

**Owns:** files listed above + that test file.

---

## M5 — hook features (secure versions)

**Entry:** M3 green (M4 in parallel is allowed: different files).

**Work:** the nine hook features of `docs/02-feature-parity.md` §7, each
implemented to the control in `docs/03-security-baseline.md` that its row names:
avatar upload, link preview, XML import/export, staff directory, saved XPath
search, board snapshot restore, thread export, JWT password reset + remember-me,
and the `sessions` store already built in M1.

**Exit gate:** `npx vitest run test/unit/hook-*.test.mjs test/integration/hooks.test.mjs`
green, and `node tools/check-spec.mjs --hooks` confirms every hook row in
`docs/02` §7 appears both in the route inventory and in the control register.

**Owns:** `src/hooks/**`, `src/xml/**`, `src/security/jwt.js`, their templates,
and `test/unit/hook-*.test.mjs`, `test/integration/hooks.test.mjs`.

---

## M6 — fixtures, seeds, reset

**Entry:** M2 green.

**Work:** `scripts/seed-admins.mjs`, `scripts/seed-test-data.mjs`,
`scripts/reset.mjs` — verbatim parity with the PHP `bin/` scripts: ten personas,
same usernames/passwords, six boards including the soft-deleted Archive, the
sanitizer probe post, edited post, soft-deleted thread and soft-deleted reply
next to a surviving sibling, mixed positive/negative scores, 22 threads in
General, seeded failed-login rows; `--force`, `--keep-mail-log`,
`--no-test-data`, `--reset-passwords` flags.

**Exit gate:** `npm run db:reset -- --force` then
`npx vitest run test/integration/fixture-invariants.test.mjs` green (that test
asserts every fixture invariant listed in `docs/02-feature-parity.md` §6).

**Owns:** `scripts/`, `test/integration/fixture-invariants.test.mjs`.

---

## M7 — test parity

**Entry:** M2–M6 green.

**Work:** close every row of `docs/parity/test-inventory.md` with a Node test of
the same name; add `test/security/baseline-inert.test.mjs` (the sanitizer probe
fixture must render inert), `test/security/controls.test.mjs` (one assertion per
control in `docs/03`), and `scripts/verify-parity-tests.mjs` that diffs test
names against the generated inventory.

**Exit gate:** `npm run verify:all` green — 123 ported cases plus the security
suite, zero skips.

**Owns:** `test/**`, `scripts/verify-parity-tests.mjs`.

---

## M8 — the 35 vulnerability branches

**Entry:** M7 green, `main` tagged `baseline-secure`, Carmentis control run
(M9 dry pass) recorded.

**Work:** one branch per row of `docs/05-vuln-catalog.md`, each built exactly as
its sheet in `docs/vulns/` specifies: exploit test first, then the minimal diff,
then `npm run verify:branch`. Branch naming and topology per `docs/06`.

**Parallelizable:** yes — up to one agent per branch, each in its own worktree
with its own port and its own database name (`tools/verify-all-branches.mjs`
allocates both). Branches never touch `main`.

**Suggested fan-out batches** (roughly equal effort, independent files):

| Batch | Branches |
|---|---|
| A — injection family | `sqli`, `nosql_injection`, `xpath_injection`, `ldap_injection`, `command_injection`, `log_injection` |
| B — XSS family | `xss_stored`, `xss_reflected`, `xss_dom`, `xss_config`, `ssti`, `xxe` |
| C — auth family | `csrf`, `session_management`, `jwt_flaws`, `cryptographic_failures`, `weak_password_policy`, `broken_function_level_authz` |
| D — access-control family | `idor`, `auth_requirement_mismatch`, `mass_assignment`, `race_condition`, `open_redirect`, `host_header_injection` |
| E — request/header family | `header_injection`, `cors_misconfig`, `ssrf`, `email_header_injection`, `path_traversal`, `file_upload` |
| F — configuration family | `security_misconfig`, `information_disclosure`, `sensitive_data_exposure`, `vulnerable_components`, `insecure_deserialization` |

**Exit gate:** `node tools/verify-all-branches.mjs` prints a 35-row matrix, all
rows `PASS`, and `git branch --list 'vuln/*' | wc -l` is 35 with each branch
exactly one commit off `main`.

**Owns:** only the files named in each sheet's "Minimal diff".

---

## M9 — Carmentis runs and results

**Entry:** M8 matrix green.

**Work:** run Carmentis against `main` (control) and against each
`vuln/<slug>` branch through the worktree harness; record the finding, the
evidence string from the sheet, and whether the scanner's class label matched
the catalog's CWE in `carmentis/results.md`; record false negatives as
`docs/vulns/<slug>.md` amendments on `main` (spec commits) rather than branch
edits.

**Exit gate:** `carmentis/results.md` has 36 rows (`main` + 35 branches) with a
verdict per row, and `docs/07-port-deviations.md` records any fidelity gap found
during the runs.

**Owns:** `carmentis/`.
