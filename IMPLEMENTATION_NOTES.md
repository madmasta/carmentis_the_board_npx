# Implementation notes (working file, not part of the spec)

Deviations, spec corrections and decisions found while building M0–M7. Each item
becomes a spec commit on `main` once confirmed. Nothing here is a licence to skip
a control.

## M0 — scaffold

1. **Files pulled forward from M1.** The M0 exit gate runs `npm run db:reset` and
   the test bootstrap, which need config and DB access, so these M1-owned files
   were written now: `src/config/env.js`, `src/config/defaults.js`,
   `src/db/connection.js`, `src/db/admin.js`, `src/lib/clock.js`,
   `src/lib/faults.js`, `src/lib/log.js`.
2. **New files not in the `docs/01` layout** (spec needs them added):
   `src/db/admin.js` (create/drop/apply-schema, shared by `scripts/reset.mjs` and
   `test/helpers/db.mjs`), `src/lib/log.js` (app log sink; the throttle bypass
   record and the request logger both need it, so it cannot live only in
   `src/http/server.js` as `docs/03` C-INFO-3 implies).
3. **`forUpdate` signature.** `docs/01` §5 shows `forUpdate(sql, params)`, but a
   row lock is only meaningful on the transaction's own connection, so the
   implementation is `forUpdate(conn, sql, params)`. Amend the doc.
4. **`C-INFO-3` and the throttle record.** The control text says no email ever
   appears in `var/log/app.log`; the PHP target logs
   `[SECURITY] login throttle BYPASSED (LOGIN_THROTTLE_DISABLED=1): email=… ip=… failures=n/m`
   verbatim. The control needs the exception clause (added in `src/lib/log.js`
   comment) and `docs/03` must say: no email in *request* logs; the bypass record
   reproduces the PHP field list.
5. **Seed stubs exit code 3.** `scripts/seed-admins.mjs` and
   `scripts/seed-test-data.mjs` exit 3 until M6; `scripts/reset.mjs` treats 3 as
   "milestone pending, skipped" so `npm run db:reset` is green in M0 while the
   stubs still fail loudly in isolation.
6. **Pool options.** `dateStrings: true` and `decimalNumbers: true` are set
   (PDO parity, docs/07 §10 mentions only `decimalNumbers`); `namedPlaceholders:
   false` makes C-SQL-2's "named placeholders not used" a fact of the driver
   config.
7. **JWT single-use store.** `jti` reuse is tracked in memory in
   `src/security/jwt.js`, because `docs/parity/schema-inventory.md` allows exactly
   one new table (`sessions`). Needs a line in `docs/07` §8.
8. **Banner wording, pinned from the PHP target.** Page banner title is
   `BRUTE-FORCE PROTECTION IS OFF` (`templates/partials/header.php:28`) when
   disabled and `INSECURE SETTING IGNORED` when refused; the CLI block headline is
   `BRUTE-FORCE PROTECTION IS DISABLED`. `LoginThrottle::bannerText()` strings are
   ported verbatim and belong in `docs/02` B6.
9. **Docker.** `docker-compose.yml` service `db`, container `theboard-node-db`,
   host port 3307 (verified: container healthy, `db:reset` applied 8 tables).

## M1 — core infrastructure

Verified green: `npm test` (40 cases) and `npm start` answering `GET /health`
with `{"ok":true}` plus the six baseline headers.

1. **Entry point split.** `src/server.js` (boot, `.env` load, listen, shutdown,
   `createApp()` for tests) and `src/http/server.js` (the request pipeline) —
   `docs/01` §2 lists only one; add both.
2. **`env.get()` works with no file loaded.** `docs/01` §4 reads as if `load()`
   is mandatory. The test harness pins `process.env` and never loads `.env`, and
   PHP's `getenv()` behaves the same way, so an unloaded file is an empty map.
   `src/server.js#loadEnv` still refuses to boot the app without `.env`.
3. **Host allowlist matching.** Comparison ignores the request's port: an entry
   `localhost` answers `localhost:8088`, and an entry that names a port must
   match it. `docs/03` (C-HOST-1) and `docs/vulns/host_header_injection.md` both
   need the semantics pinned; `X-Forwarded-Host` is never consulted.
4. **New databases must be granted to the app user.** The container only grants
   `MARIADB_DATABASE`, so a created `theboard_node_test` is invisible to
   `theboard` and every session write fails. `src/db/admin.js#createDatabase`
   now issues `GRANT ALL PRIVILEGES ON <db>.* TO <DB_USER>@'%'`. Add to
   `docs/04` §2 (the PHP bootstrap has the same latent gap).
5. **Test database naming must be idempotent.** `test/helpers/db.mjs` strips a
   trailing `_test` before appending it: vitest re-evaluates the module graph in
   a worker where `process.env.DB_NAME` is already the test name, which produced
   `theboard_node_test_test`.
6. **Template name mapping.** Nunjucks needs the extension in the name, so
   `views.render()` appends `.njk` and rewrites a `.php` suffix inherited from a
   ported call site. Nothing else in the port keeps `.php`.
7. **No 404 template.** `views.notFound()` renders the error view with
   `404` and the pinned copy — the template inventory has no `404.php`.
8. **Static allowlist matches the raw pathname.** A trailing slash
   (`/assets/style.css/`) is a 404, so the lookup cannot use the normalised
   `req.path`; the normalised path is for routing only.
9. **Body limits are constants, not env keys.** `MAX_POST_BYTES` (4 MiB) and
   `MAX_UPLOAD_BYTES` (2 MiB) live in `src/http/request.js`; the env inventory
   has no such keys. An oversized body is drained to completion before the 413 is
   written, so the client receives the response instead of a connection reset.
10. **Prototype-key rejection copy.** `parse()` throws `400 Invalid request
    field name.` for `__proto__`, `constructor` and
    `prototype` in the query string, urlencoded body and multipart field names,
    and every container is built with `Object.create(null)` (C-ASSIGN-1). The
    exact string must be pinned in `docs/02`; the `mass_assignment` sheet only
    says the submission is refused with `400`.
11. **`Halt` replaces PHP's `exit`.** A guard that has already answered throws
    `Halt` (exported from `src/http/controller.js`); the pipeline treats it as
    "response complete", persists the session and stops. Handlers must not catch
    it. `docs/02` §2 should state the convention, otherwise a milestone author
    writes a guard that returns and keeps executing.
12. **`csrf_token` instead of `csrf_field`.** PHP passes a pre-rendered hidden
    input; the port passes the token value and the template writes the input.
    `docs/02`'s per-template variable list should use `csrf_token`.
13. **Throttle signature.** `exceeded({ email, ip, recentFailures })` receives
    the count instead of querying the repository, so the module (and its four
    kill-switch guards) is testable without a DB. PHP is `exceeded(email, ip)`.
14. **Session cookie timing.** The cookie is written when the session starts; the
    final `save()` skips the cookie once the response has begun (`res.headersSent`)
    and still writes the row. A `regenerate()` during login still lands, because
    it happens before the redirect is written.
15. **Throttle banner globals in templates.** `throttle_status()`,
    `throttle_title()` and `throttle_text()` are Nunjucks globals — the PHP header
    partial calls `LoginThrottle::status()` / `::bannerText()` directly.
16. **The debug trace is rendered by the template, not by the runtime.** PHP
    turns the stack into response text through `display_errors`; the Node port
    passes `debug_trace` to `templates/error.njk` only when `APP_DEBUG=1`. The
    `information_disclosure` oracle (500 body contains a stack frame) depends on
    this, so `docs/07` §5 must state the analogue.
17. **Router semantics to pin in `docs/01` §1.** Exact segment counts
    (`/post/:id` never matches `/post/:id/edit`), `:id` matches digits only (the
    PHP `ctype_digit` guard) so a non-numeric id falls through to the 404 view,
    duplicate method+path pairs are a start-up error, and `intParam()` is the
    integer accessor.
18. **Files pulled forward.** `src/security/headers-policy.js`,
    `src/security/markup.js`, `src/http/controller.js`, `src/routes.js` (M2–M4
    owners) and `src/security/login-throttle.js` (M2-owned: the M1 header partial
    renders the banner) are written; M2–M4 extend, not create, them.

## M2 — auth, throttle, MFA, mail

Verified green: the 4 ported integration files carry all 34 PHP case names
(`auth` 11, `login-throttle` 7, `mfa` 10, `user-repository` 6), plus
`test/unit/validator.test.mjs` (14) and `test/unit/mailer.test.mjs`. An
end-to-end HTTP walk of the flow passes: register → auto-login → MFA toggle →
logout → login → OTP read from the mail log → verify → session established;
wrong password flashes the generic copy; a CSRF-less POST is a 400.

1. **Guard semantics (spec amendment needed in `docs/01` §1 and `docs/02` §1).**
   The pipeline enforces the declared guard — `vuln/auth_requirement_mismatch`
   only makes sense if it does — while the PHP front controller applies none at
   all: every check lives in the handler. So `src/routes.js` declares the
   *effective* requirement, which differs from the generated Guard column for
   three rows: `POST /login` is `anon` (an enforced `login` guard would make
   login impossible), and `POST /mfa` and `POST /mfa/resend` are
   `login-or-anon`, because their handler answers the challenge state and emits
   `No login in progress. Please log in again.` rather than
   `Please log in first.` The inventory's Guard column is descriptive of the PHP
   handler, not a dispatch gate.
2. **The session user row carries `password_hash` and `avatar_path`.** PHP's
   `Auth::currentUser()` selected `*`, and every privileged change re-verifies the
   current password (`docs/03` C-AUTH-2), so `controller.js#loadUser` selects the
   same columns. No template prints the hash; `docs/03` C-DATA proofs must target
   rendering and logs, not the in-memory row.
3. **Timestamps are UTC end to end (this was a live bug, not a cosmetic one).**
   `clock.sqlDateTime()` used host-local components while the MariaDB container
   stamps UTC, so `login_attempts.attempted_at > <since>` matched forever — the
   throttle never expired and an OTP looked unexpired. `sqlDateTime()` now uses
   UTC, and `docker-compose.yml` pins `--default-time-zone=+00:00` so a
   host-side database cannot drift either. `docs/07` §10's "local wall-clock
   parity" wording is wrong: the PHP target ran inside a UTC container, so UTC is
   the parity behaviour. `mfa.verify` parses `expires_at` as UTC for the same
   reason.
4. **`users.avatar_path` added to `schema.sql`.** The avatar hook (docs/02 §7)
   needs per-user storage and there is no other place for it;
   `docs/parity/schema-inventory.md` says the DDL is copied verbatim, so the
   inventory note must record this one added column (alongside the added
   `sessions` table).
5. **File name for MFA.** `src/security/mfa.js` — `docs/01` §3 maps `Mfa.php`
   there and C-RACE-1 names that path; the MILESTONES M2 line says
   `src/auth/mfa.js`. `docs/01` wins.
6. **`attemptLogin(ctx, email, password, ip)`.** `docs/01` §5 shows three
   arguments; the session and response live in the request context, so `ctx` is
   first. `mfaPendingUser(ctx)` and `completeLogin(ctx, user)` follow the same
   shape.
7. **C-RACE-1 is live in `main`.** `mfa.verify` runs its read, attempt counter and
   burn inside `transaction()` with `SELECT … FOR UPDATE` (PHP did the same
   sequence without a lock). The `race_condition` branch removes the lock and adds
   the 350 ms seam, per `docs/04` §9.
8. **`profile.show` imports the post repository dynamically.** M3 owns that file;
   a static import would stop the app from booting in M2. The call site is one
   line and becomes a normal import in M3.
9. **The register template does not display validation errors — in PHP either.**
   `templates/register.php` receives `$errors` and never prints them; the port
   matches (old values are re-rendered, no message). `docs/02` B12 should state
   this so a later milestone does not "fix" it and break HTML parity.
10. **`verify-parity-tests.mjs` needs an exemption rule.** `docs/04` §3 as written
    fails every file `docs/03` requires as a control proof
    (`test/unit/repository-users.test.mjs`, `test/unit/mailer.test.mjs` beyond its
    ported case, `test/unit/request.test.mjs`, …) and the M1 infrastructure files,
    because none has a PHP row. Planned rule, to be written into `docs/04` §3:
    a file is either (a) inventory-mapped, with 1:1 case names; (b) named in a
    `docs/03` *Proof:* line, where every case is named `c-<control-slug>`; or
    (c) one of the infrastructure files listed in `MILESTONES.md` for M0–M1.
11. **New test helpers** (add to `docs/04` §2): `test/helpers/http.mjs`
    (`agent`, `csrfToken`, `loginAs`, `postForm`, `sessionIdFrom` — the last takes
    the *final* `Set-Cookie`, because a login response carries the pre-login id
    and the regenerated one), `test/helpers/mailbox.mjs` (`messages`, `lastCode`,
    reading the PHP mail-record format whose `TO:` sits on the timestamp line),
    and `test/helpers/users.mjs` (`makeUser`, `makeBoard`, `fakeContext`).
    `makeUser` memoizes one bcrypt hash per distinct password: cost 10 in pure JS
    is ~50 ms and the suite creates ~40 users.
