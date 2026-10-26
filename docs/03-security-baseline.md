# 03 — Security baseline (control register)

`main` is the control build. Every control below must be present, and every one
of them has a named proof test. Vulnerability sheets in `docs/vulns/` must name
the control they downgrade by its ID — that is what makes a branch a reviewable
"remove one control" diff instead of an arbitrary edit.

Format: **ID**, requirement, where it lives, and the test that pins it. All
proof tests live in `test/security/controls.test.mjs` unless another file is
named.

**Skip granularity.** A proof file may pin several controls, and a branch may
downgrade one clause of a control while the rest of that control still holds. A
control is therefore skippable at *case* level: every test case that pins a
control carries the control slug in its name (`c-sql-1 rejects an interpolated
where fragment`), and a branch that declares `C-SQL-1` skips only the cases whose
name contains `c-sql-1`. Cases in the same file that carry a different slug always
run. A sheet whose diff leaves part of a control enforced says so in its table
("…clause"), and only the named clause's cases are skipped.

**Clause ownership, to keep sibling branches separable:** `C-MFA-1` owns the OTP
*lifecycle semantics* (issue, TTL, attempt cap, invalidation on re-issue, resend
throttle); `C-RACE-1` owns *single-use under concurrency* — when a branch breaks
the one-shot property by removing the lock, it declares `C-RACE-1`, not `C-MFA-1`.
`C-XSS-3` owns the CSP header itself; the inert-render probe
`test/security/baseline-inert.test.mjs` is a separate gate (`docs/04` §8), not a
proof case of `C-XSS-3`, so an XSS-family branch may fail that gate without
declaring the CSP control.

## SQL / data layer

**C-SQL-1 — Prepared statements only.**
Every SQL string is a literal with `?` placeholders; no user-controlled text is
ever concatenated or template-interpolated into SQL. Identifier lists come from
fixed allowlists.
*Location:* every file in `src/repositories/`, `src/session/store.js`, `src/hooks/`.
*Proof:* `test/security/controls.test.mjs#c-sql-1` — (a) a source scan that fails
on any `+` or `${` used to build a SQL fragment anywhere under
`src/repositories/`, `src/session/store.js` or `src/hooks/`, including fragments
assembled into a variable before the call, and (b) behavioural probes: the seeded
payloads (`' OR 1=1-- -`, `%' OR 1=1-- -`) must not change any repository result.
Both halves are needed: a scan alone is bypassable by moving the interpolation
into a local variable, and a behavioural probe alone would not catch SQL built
from an identifier list.

**C-SQL-2 — Driver hardening.**
`mysql2` pool created with `multipleStatements: false` written **explicitly** (the
library's own default is already `false`, so an option that is merely absent proves
nothing), named placeholders not used, `connectTimeout` set, errors mapped to the
generic 500 view. `connection.query(sql, params)` uses `conn.query` (client-side
binding), which is what makes stacked statements possible at all once the flag is
flipped — `conn.execute` would mask the class behind a server-side prepare error.
*Location:* `src/db/connection.js`.
*Proof:* `test/unit/db-connection.test.mjs#c-sql-2` asserts the literal option is
present in the pool config and that a two-statement `query()` throws.

**C-SQL-3 — Search terms are LIKE-escaped before they reach SQL.**
A search term is escaped for `LIKE` metacharacters (`%` → `\%`, `_` → `\_`) and then
passed as a bound parameter, so it can never act as SQL syntax or as a wildcard.
The escape exists only inside the parameterized path, so a branch that interpolates
must drop it too — and that drop is a declared control change here rather than an
invisible failure in a parity test.
*Location:* `src/repositories/user.repository.js#allUsers` and any repository method
with a `LIKE` filter.
*Proof:* `test/unit/repository-users.test.mjs#c-sql-3`, the port of the PHP parity
case `testAllUsersSearch`: searching for `%` and `_` matches literally rather than as
wildcards, and a `'` in the term matches literally rather than ending the literal.

**C-RACE-1 — One-shot invariants hold under concurrency.**
Any check-then-act on a single-use resource (OTP consume, vote toggle, snapshot
restore, upload quota) executes inside `transaction()` with `SELECT … FOR UPDATE`
on the governing row, so simultaneous requests cannot both win. This control, not
`C-MFA-1`, is the one a branch declares when it removes the lock.
*Location:* `src/security/mfa.js`, `src/repositories/vote.repository.js`, `src/hooks/snapshot.js`.
*Proof:* `test/integration/race-baseline.test.mjs` (20 parallel requests keep the invariant).

## Input validation and output encoding

**C-XSS-1 — Escape-first markup renderer.**
The whole input is HTML-escaped before any tag is interpreted; only the six BBCode
tags are converted; unknown tags stay inert text; work is bounded to 25 passes.
*Location:* `src/security/markup.js`.
*Proof:* the 30 ported cases in `test/unit/markup.test.mjs`.

**C-XSS-2 — Output encoding on both exits: templates and the app's own script.**
Nunjucks runs with `autoescape: true`, and `|safe` may only wrap a call to
`markup.render`; a source scan fails the build if `|safe` appears anywhere else.
The same rule applies client-side: the one script CSP allows
(`public/assets/app.js`) writes request-derived values through inert sinks only
(`textContent`, `setAttribute`) — never `innerHTML`, `outerHTML`,
`insertAdjacentHTML` or `document.write`.
*Location:* `src/views.js`, all templates, `public/assets/app.js`.
*Proof:* `test/security/controls.test.mjs#c-xss-2` (three cases: the `|safe` scan, the
client-sink scan, and the autoescape-configuration scan) and
`test/security/baseline-inert.test.mjs`.

**C-XSS-3 — Content-Security-Policy.**
Sent on every response:
`default-src 'self'; img-src * data:; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'`.
No inline script or inline handler attributes anywhere in the rendered HTML.
*Location:* `src/security/headers-policy.js`.
*Proof:* `test/security/controls.test.mjs#c-xss-3` — the header is present with
that exact policy on `/`, `/login` and `/thread/1`. The inert-render probe
(`test/security/baseline-inert.test.mjs`) is the separate gate described in
`docs/04` §8.

**C-XSS-4 — URL scheme allowlist.**
A URL is accepted only when its scheme is `http`/`https`, it has a host, and it
contains no control character or whitespace; entities are decoded before the
check.
*Location:* `src/security/markup.js#isSafeUrl`, reused by `src/hooks/preview.js`.
*Proof:* `test/unit/markup.test.mjs` scheme cases + `test/unit/hook-preview.test.mjs`.

**C-SSTI-1 — Templates never compile user input.**
No template string, `nunjucks.compile`, `eval`, `Function`, or `vm` runs on
request data. User text is passed as a variable only.
*Location:* `src/views.js` (only `getTemplate` of a fixed name), `src/hooks/xml-import.js`.
*Proof:* `test/security/controls.test.mjs#c-ssti-1` source scan + `test/integration/hooks.test.mjs` (imported XML containing `{{ 7*7 }}` renders literally).

## Authentication and sessions

**C-SESS-1 — Cookie and session-id discipline.**
`HttpOnly`, `SameSite=Lax`, `Secure` over https, `Path=/`, no `Domain`,
session-scoped lifetime; ids from `crypto.randomBytes(16)`; unknown ids are never
adopted.
*Location:* `src/session/store.js`, `src/http/headers.js`.
*Proof:* `test/integration/session.test.mjs#c-sess-1` (cookie attributes and id
entropy; the cases carrying `c-sess-2` in the same file are separate cases).

**C-SESS-2 — Regeneration and store hygiene.**
Id regenerated on login, MFA completion, privilege change and clear; old row
deleted; expiry sweep runs; session payload stays server-side in the `sessions`
table.
*Location:* `src/session/store.js`, `src/auth/login.js#completeLogin`.
*Proof:* `test/integration/session.test.mjs#regenerate`.

**C-SESS-3 — Ban takes effect mid-session.**
Every request reloads the user row and drops the session when `is_banned = 1`.
*Location:* `src/session/store.js#start`.
*Proof:* `test/integration/board-access.test.mjs#testBannedUserIsDeniedAccess`.

**C-AUTH-1 — Password hashing and timing.**
`bcryptjs` with cost ≥ 10; unknown accounts still run a verify against a fixed
dummy hash so latency does not reveal existence.
*Location:* `src/security/passwords.js`, `src/auth/login.js`.
*Proof:* `test/integration/auth.test.mjs#testUnknownAccountDoesNotLeakExistence`.

**C-AUTH-2 — Password policy.**
Minimum length from `PASSWORD_MIN_LENGTH`, ≤ 200, letter + digit when min ≥ 8,
must not equal the username or email.
*Location:* `src/security/validator.js#password`.
*Proof:* `test/unit/validator.test.mjs#c-auth-2` — `testPasswordLength`,
`testPasswordRequiresLetterAndDigit` and `testPasswordMustNotMatchUsernameOrEmail`.

**C-AUTH-3 — Login throttling with a guarded kill switch.**
Per email **and** per IP, `LOGIN_MAX_ATTEMPTS` inside `LOGIN_WINDOW_MINUTES`,
throttle rejects even the correct password, failures are always recorded, the
kill switch is honoured only with `APP_DEBUG=1`, announces on every page, logs
each bypass and warns in the CLI.
*Location:* `src/security/login-throttle.js`.
*Proof:* the 7 ported `test/integration/login-throttle.test.mjs` cases and
`test/integration/auth.test.mjs#testLoginThrottleAfterRepeatedFailures`.

**C-AUTH-4 — No account-existence leaks.**
Identical generic failure text for unknown email, wrong password and
banned-with-wrong-password; MFA state never revealed before the password passes.
*Location:* `src/http/auth.controller.js`.
*Proof:* `test/integration/auth.test.mjs#testBannedAccountWithWrongPasswordLooksLikeInvalidLogin`.

**C-SESS-4 — Client IP is the socket address.**
Throttle and logging use the socket address only; `X-Forwarded-For` is never
trusted.
*Location:* `src/auth/login.js#clientIp`.
*Proof:* `test/integration/auth.test.mjs#testThrottleIsPerEmailAndIp`.

## Multi-factor authentication

**C-MFA-1 — OTP lifecycle.**
6 digits from a CSPRNG, bcrypt-hashed, single-use, TTL, attempt cap, attempts
incremented before comparison, new issue invalidates outstanding codes, resend
throttled to one per 60 s.
*Location:* `src/security/mfa.js`.
*Proof:* the 10 ported `test/integration/mfa.test.mjs` cases.

## Authorization

**C-ACL-1 — Board access checked on every read and write.**
Every board/thread/post/reply/vote path calls `BoardRepository.userCanAccess`
after loading the row; a denial is `404`.
*Location:* `src/repositories/board.repository.js#userCanAccess`, all board-facing controllers.
*Proof:* the 9 ported `test/integration/board-access.test.mjs` cases.

**C-ACL-2 — Admin-only actions enforced per request.**
Every `/admin/*` handler calls `requireAdmin()` itself; there is no "admin
section" trust inherited from a layout or a menu.
*Location:* `src/http/admin.controller.js`, `src/http/post.controller.js#delete`.
*Proof:* `test/integration/admin-flow.test.mjs` + `test/security/controls.test.mjs#c-acl-2` (route table declares a guard for every non-anon route).

**C-ACL-3 — Object-level ownership checks.**
Editing a post checks author-or-admin in both the controller and the `UPDATE … WHERE … author_id = ?` predicate.
*Location:* `src/http/post.controller.js`, `src/repositories/post.repository.js#editPost`.
*Proof:* `test/integration/post.test.mjs#testNonAuthorCannotEditOthersPost`.

**C-ACL-4 — Route guards are declared, not implied.**
`src/routes.js` gives every route an explicit `guard: 'anon' | 'login' | 'admin'`;
the router refuses to start if a route lacks one.
*Location:* `src/routes.js`, `src/http/router.js`.
*Proof:* `test/unit/router.test.mjs#guard-required`.

**C-ASSIGN-1 — Bodies become typed DTOs.**
A per-route field allowlist with explicit casts; unknown fields dropped; keys
`__proto__`, `constructor`, `prototype` rejected before assignment; no
`Object.assign(req.body, …)` onto models or sessions.
*Location:* `src/http/request.js`, per-controller `readInput()` helpers.
*Proof:* `test/unit/request.test.mjs#c-assign-1` (prototype-key rejection and
unknown-field dropping) + `test/security/controls.test.mjs#c-assign-1` (no
`Object.assign` of a body onto a model or session). A branch that widens one
route's field allowlist while keeping prototype-key rejection declares
`C-ASSIGN-1 (field allowlist clause)` and skips only the allowlist cases.

## Headers and redirects

**C-HDR-1 — Central security header set.**
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: same-origin`, `X-Permitted-Cross-Domain-Policies: none`,
`Cross-Origin-Opener-Policy: same-origin`, CSP (C-XSS-3), and HSTS when https.
Set once in the pipeline, on error responses too.
*Location:* `src/http/headers.js`.
*Proof:* `test/security/controls.test.mjs#c-hdr-1` checks all of them on a 200,
a 404 and a 403 response.

**C-HDR-2 — No unsanitized header writes.**
Header names and values pass a CRLF/control-character check and are written only
through `res.setHeader`/`res.writeHead`; values derived from request data
(`Location`, `Refresh`, `Set-Cookie`) are validated first.
*Location:* `src/http/response.js`, `src/http/headers.js`.
*Proof:* `test/unit/headers.test.mjs` (CRLF in a redirect target is rejected).

**C-HDR-3 — CORS stays closed.**
No `Access-Control-Allow-*` header is ever emitted; no origin reflection; no
`OPTIONS` preflight handler.
*Location:* `src/http/headers.js`.
*Proof:* `test/unit/headers.test.mjs#cors-closed`.

**C-COOKIE-1 — Cookie host binding.**
The session cookie name and flags come from configuration, never from a request
supplied host; `Host`/`X-Forwarded-Host` are never used to build absolute URLs,
cookies or links; email links use `APP_URL`.
*Location:* `src/http/request.js#hostIsAllowed`, `src/security/jwt.js#resetUrl`.
*Proof:* `test/unit/request.test.mjs#host-header`.

**C-REDIR-1 — Internal-only post-login redirect.**
`intended_path` must start with `/` and not `//`; anything else becomes `/`.
*Location:* `src/http/auth.controller.js#consumeIntendedPath`.
*Proof:* `test/integration/auth.test.mjs` intended-path case.

**C-REDIR-2 — Referer redirects are origin-checked.**
`POST /vote` returns to `HTTP_REFERER` only when it begins with `APP_URL`.
*Location:* `src/http/vote.controller.js`.
*Proof:* `test/integration/vote.test.mjs` redirect case.

## CSRF

**C-CSRF-1 — Token issue, comparison and rotation.**
One 256-bit random token per session, `crypto.timingSafeEqual` comparison,
rotated at login and cleared on logout; every state-changing route requires it
before any other work.
*Location:* `src/security/csrf.js`, `src/http/controller.js#csrf`.
*Proof:* `test/unit/csrf.test.mjs` + `test/security/controls.test.mjs#c-csrf-1`
(every `POST` route rejects a tokenless request with 400, and the same walk repeated
with `X-Requested-With: fetch` set — no caller-set header substitutes for the token).
## Files, network, XML, commands

**C-UPLOAD-1 — Upload discipline.**
Size cap 2 MiB, MIME + magic-byte allowlist, extension allowlist,
`crypto.randomUUID()` filename, storage in `var/uploads/` outside `public/`,
served through a controller with a fixed `Content-Type` and `X-Content-Type-Options`,
no user-controlled path component.
*Location:* `src/hooks/upload.js`.
*Proof:* `test/unit/hook-upload.test.mjs` (PHP-in-the-name, SVG, oversized,
`../` traversal, double extension all rejected).

**C-SSRF-1 — Outbound fetch discipline.**
Only `http`/`https`, host resolved first and rejected when loopback/RFC1918/
link-local/`169.254.169.254`, redirects disabled, 5 s timeout, 64 KiB read cap.
*Location:* `src/hooks/preview.js`.
*Proof:* `test/unit/hook-preview.test.mjs` with a stub resolver.

**C-XML-1 — XML reader discipline.**
In-house reader: size ≤ 64 KiB, depth ≤ 20, internal entities only, `DOCTYPE`
containing `SYSTEM` or `PUBLIC` rejected, expansion count capped.
*Location:* `src/xml/reader.js`.
*Proof:* `test/unit/xml-reader.test.mjs`.

**C-XPATH-1 — XPath built from an AST.**
Filter tokens become AST nodes and are bound as variables to the `xpath`
evaluator; the expression string never contains user input.
*Location:* `src/hooks/xpath.js`.
*Proof:* `test/unit/hook-xpath.test.mjs`.

**C-DIR-2 — Filter values are primitives.**
A filter value that is an object, array, or function is rejected before any query,
filter string, or document predicate is built; no operator object (`$ne`, `$gt`,
`$regex`, `$where`) is ever interpreted by the app.
*Location:* `src/hooks/directory.js`, `src/hooks/xpath.js`.
*Proof:* `test/unit/hook-directory.test.mjs#c-dir-2` (operator objects rejected).

**C-DIR-1 — Directory filter tokenizer.**
Each filter token is parsed into `{field, op, value}` with `field` from a
fixed allowlist and `value` bound as a parameter; a non-string value is rejected
before any query or filter string is built.
*Location:* `src/hooks/directory.js`.
*Proof:* `test/unit/hook-directory.test.mjs#c-dir-1` (each token becomes a bound
parameter; a token containing `'` changes no result set).

**C-JSON-1 — Snapshot restore is schema-validated.**
Restore validates each record against an explicit field schema, whitelists
`type` tags, uses no reviver, no `Function`, no `vm`, and applies everything in
one transaction.
*Location:* `src/hooks/snapshot.js`.
*Proof:* `test/unit/hook-snapshot.test.mjs`.

**C-CMD-1 — No shell, no string commands.**
Export runs in-process. No `shell: true`, no `exec`, no string command built from
input; the only permitted external invocation form is `execFile(binary, [args])`
with `binary` from a fixed allowlist (and none is used on `main`).
*Location:* `src/hooks/export.js`.
*Proof:* `test/unit/hook-export.test.mjs` + `test/security/controls.test.mjs#c-cmd-1` source scan.

## Cryptography and tokens

**C-CRYPTO-1 — CSPRNG and sound primitives.**
`crypto.randomBytes` for session ids, CSRF tokens, OTPs, upload names, one-time
passwords; `bcryptjs` for password and OTP hashing; no `Math.random`, no `md5`,
no `sha1` for anything secret, no hardcoded key.
*Location:* `src/security/passwords.js`, `src/session/store.js`, `src/security/mfa.js`.
*Proof:* `test/security/controls.test.mjs#c-crypto-1` source scan + `test/unit/crypto-primitives.test.mjs`.

**C-JWT-1 — JWT discipline.**
`algorithms: ['HS256']` pinned at verify time, no `none`, no algorithm guessing,
secret ≥ 32 bytes from `JWT_SECRET`, `exp` ≤ 15 min, `jti` recorded and single-use,
signature secret never echoed to a client.
*Location:* `src/security/jwt.js`.
*Proof:* `test/unit/hook-jwt.test.mjs` — the three signature/algorithm cases carry the
`c-jwt-1` slug (`refuses an alg:none token`, `refuses an algorithm substitution in the
header`, `refuses a token signed with a different key`); the expiry and single-use cases
are named for their own clause and keep running on a branch that declares the
signature clause away, so the scope of that downgrade is visible.

## Data exposure, logging, dependencies

**C-INFO-1 — No internals in responses.**
500 responses are the generic view unless `APP_DEBUG=1`; stack traces go to
`var/log/app.log`; error views never echo request data; the throttle banner is
the only environment banner.
*Location:* `src/server.js` error path, `templates/error.njk`.
*Proof:* `test/integration/error-handling.test.mjs#c-info-1`, which arms
`src/lib/faults.js#setTestFault` to raise a known error and asserts the response is
the generic 500 view with no stack frame, while the trace appears in
`var/log/app.log`; a second case asserts no fault is armed in a normal run. A
branch that flips the `APP_DEBUG` default keeps the same fault probe and asserts
the frames are now rendered.

**C-INFO-2 — No filesystem exposure.**
The only URL-reachable file reads are `/assets/*` (a fixed file list), the
controller routes `/avatar/:id` and `/attachment?file=` with the containment check
applied, and nothing else: no static directory handler, no `/.git`, no `/uploads`,
no directory listing, no source-map route, and no path read outside the allowlist.
*Location:* `src/http/server.js`.
*Proof:* `test/integration/static.test.mjs` (404 for `/../schema.sql`,
`/.git/config`, `/var/`, `/uploads/x.png`).

**C-INFO-3 — Logs are structured and inert.**
Each log record is one line; user-supplied values are newline-stripped and
truncated; emails, password hashes, OTP codes and session ids never appear in
`var/log/app.log` (the mail log is the only place an OTP appears, by design).
*Location:* `src/http/server.js` request logger.
*Proof:* `test/unit/logging.test.mjs`.

**C-MAIL-1 — Mail header hygiene.**
Recipient and subject pass a CR/LF strip before the message is composed; the
`From` header comes from configuration only.
*Location:* `src/mail/mailer.js`.
*Proof:* `test/unit/mailer.test.mjs`.

**C-DATA-1 — Secrets stay in configuration.**
`.env` is gitignored; environment variables override the file; no secret is
hardcoded, logged, rendered into a page, or returned by `/health`; `var/secret.key`
is gitignored.
*Location:* `src/config/env.js`, `.gitignore`.
*Proof:* `test/security/controls.test.mjs#c-data-1` scans the source tree for the
test fixture secrets.

**C-DEP-1 — Dependencies are pinned and clean.**
`package-lock.json` committed; dependency set equals the list in
`docs/01-architecture.md` §7; `npm audit --json` reports no advisory for the
installed versions on `main`.
*Location:* `package.json`, `package-lock.json`.
*Proof:* `test/security/dependencies.test.mjs` shells out to `npm audit --json`
and fails if any advisory is present.
