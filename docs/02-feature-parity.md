# 02 — Feature parity contract

The Node build must behave like the PHP build. Anything the Node build has that
the PHP build does not is a hook (§7) and is labelled as such; everything else is
copied behaviour, including error-message wording.

Machine-generated inventories live in `docs/parity/` and are the authority for
routes, schema, env keys, templates and test names:

- `docs/parity/route-inventory.md` — 34 controller-backed routes.
- `docs/parity/schema-inventory.md` — 7 PHP tables + the `sessions` table.
- `docs/parity/env-inventory.md` — 26 PHP keys + `PORT`.
- `docs/parity/template-inventory.md` — 17 PHP templates → Nunjucks.
- `docs/parity/test-inventory.md` — 123 PHP test cases.

## 1. Routes

The dispatch table in `src/routes.js` has one entry per row of
`docs/parity/route-inventory.md`, **in the same order**, plus two inline routes
the extractor cannot see because they have no controller:

| Method | Path | Behaviour (identical to PHP) |
|---|---|---|
| `GET` | `/admin` | `303` to `/admin/boards`; no view rendered |
| `GET` | `/health` | `200`, `Content-Type: application/json`, body `{"ok":true}` |
| `ANY` | anything else | `404` error view, message `The page you requested does not exist.` |

Trailing slashes are stripped before matching; `/` is the empty path. Non-numeric
`:id` segments never match (`ctype_digit` equivalent: `/^\d+$/`).

Hook routes (§7) are appended after the PHP routes, before the `404` fallback.

## 2. Guard and error semantics

Order inside every handler: **CSRF → guard → object/board check → work**.

| Situation | Response | Why it matters |
|---|---|---|
| Missing/invalid CSRF token | `400` error view, `Invalid or missing CSRF token. Go back and try again.` | CSRF branch oracle depends on the control rejecting |
| No session, route needs login | `303` → `/login`, flash `error` = `Please log in first.`, `intended_path` stored | open_redirect branch attacks this |
| Logged in, route needs admin | `403` error view, `You do not have permission to do that.` / `Administrator access required.` | broken_function_level_authz |
| Board missing, soft-deleted, or not accessible | **`404`** — never `403`, never a redirect | ACL branches must be able to turn 404 into 200 |
| Thread/post missing or soft-deleted | `404` | |
| Post edit by non-author non-admin | `403`, `You can only edit your own posts.` | idor branch attacks this |
| `POST /vote` with board without access | `403`, `You do not have access to this board.` | |
| `POST /vote` with `post_id` ≤ 0 or `value` not in {1,-1} | `400`, `Invalid vote.` | |
| Any uncaught error | `500` view `Something went wrong. The error has been logged.`; stack trace only when `APP_DEBUG=1` | information_disclosure |

## 3. Sessions

- Cookie name from `SESSION_NAME`; flags `HttpOnly`, `SameSite=Lax`,
  `Secure` when the request is https, `Path=/`, no `Domain`, session-scoped.
- Unknown or expired session id → a **new empty** session is created; the
  presented id is never adopted (PHP `use_strict_mode` equivalent).
- Id regenerated (new random 128-bit id, old row deleted) on login, on MFA
  completion, on role change, on `clearSession`, and on logout (row deleted,
  cookie expired).
- Every request re-reads the user row; if `is_banned = 1`, the session is cleared
  and flash `Your account has been suspended. Contact an administrator.` — the
  ban takes effect mid-session.
- Session payload: `auth_user_id`, `mfa_pending_user_id`, `csrf_token`,
  `flash[]`, `intended_path`, `mfa_last_sent`, `auth_created_at`.

## 4. Behaviour inventory

| # | Behaviour | Exact rule to implement |
|---|---|---|
| B1 | Login state machine | `attemptLogin` returns `ok \| mfa \| banned \| throttled \| invalid`; empty email or password → `invalid` without a DB lookup |
| B2 | Generic failure | Wrong password, unknown email and banned-with-wrong-password all produce flash `Invalid email or password.` |
| B3 | Timing equalisation | Unknown account still runs a bcrypt verify against a fixed dummy hash |
| B4 | Case handling | Email is `trim`+lowercased on lookup, create and attempt; username is case-sensitive |
| B5 | Throttle | `recentFailureCount(email, ip, window) >= LOGIN_MAX_ATTEMPTS` counts failures where `email = ? OR ip = ?` inside `LOGIN_WINDOW_MINUTES`; a correct password is rejected while throttled; flash `Too many failed attempts. Please try again in a few minutes.` |
| B6 | Throttle kill switch | `LOGIN_THROTTLE_DISABLED=1` honoured **only** when `APP_DEBUG=1`; statuses `enforced/disabled/refused`; header banner on every page, `[SECURITY] login throttle BYPASSED …` per bypassed check in `var/log/app.log`, CLI warning block from every script; failures still recorded |
| B7 | Ban on login | Banned account with the right password → flash `This account has been suspended. Contact an administrator.`, no session |
| B8 | MFA issue | 6-digit zero-padded code from CSPRNG; previous unused codes for that user are marked used; stored bcrypt-hashed; TTL `OTP_TTL_MINUTES` |
| B9 | MFA verify | format `^\d{6}$`; newest unused row; attempts ≥ `OTP_MAX_ATTEMPTS` → row burned + `Too many incorrect attempts. Request a new code.`; expired → burned + `This code has expired. Request a new one.`; attempts incremented **before** comparing; success burns the row |
| B10 | MFA resend | at most one code per 60 s per session, flash `Please wait a moment before requesting another code.` |
| B11 | MFA challenge state | `mfa_pending_user_id` in session; `/mfa` without it → flash `No login in progress. Please log in again.`; visiting `/login` abandons the challenge |
| B12 | Registration | validators + duplicate email/username checks; admin role granted when the email is in `ADMIN_EMAILS`; auto-login after register; welcome mail |
| B13 | CSRF | one token per session, 32 random bytes hex, compared with `crypto.timingSafeEqual`, rotated on `completeLogin` |
| B14 | Flash | one-shot list of `{type, message}` consumed on next render; `type ∈ success|error|info` |
| B15 | Post-login redirect | `intended_path` only if it starts with `/` and not `//`, else `/` |
| B16 | Board list | anonymous → empty list (no boards, no login-required page); admin → all; otherwise `default_access = 1` rows plus explicit grants; ordered by name; `thread_count` subquery |
| B17 | Board access | `userCanAccess(user, board)`: soft-deleted board → false; anonymous → false; admin → true; `default_access=1` → true; else explicit grant |
| B18 | Thread listing | `THREADS_PER_PAGE = 20`, newest first (`created_at DESC, id DESC`), score + reply count subqueries, soft-deleted excluded; `pages = max(1, ceil(total/20))`; `?page=` coerced to ≥ 1 |
| B19 | Thread detail | thread row must be `parent_id IS NULL AND deleted_at IS NULL`; replies oldest first |
| B20 | Replies | always attached to the thread (flat model); replying to a soft-deleted thread or to a reply is `404` |
| B21 | Thread/reply validation errors | flash each error, keep the draft in the session (`old_thread_title/body`, `old_reply_body`) for one render |
| B22 | Post edit | author or admin; body re-validated; `edited_at` set; non-author non-admin gets `403` |
| B23 | Post delete | admin only, soft delete (`deleted_at`, `deleted_by`), second delete returns false and flashes success anyway (idempotent) |
| B24 | Votes | one row per (post, user); same value twice → remove; opposite value → switch; score = `SUM(value)`; invalid value → `400` |
| B25 | Vote redirect | `303` to `HTTP_REFERER` only when it starts with `APP_URL`, else to the thread |
| B26 | Admin boards | list all non-deleted with creator name and thread count; create validates name 1–100 and description ≤ 500 |
| B27 | Board access admin UI | grant/revoke per user (`INSERT IGNORE` / `DELETE`), flash names the user |
| B28 | Soft-deleted board | never in any listing; direct access is `404` |
| B29 | Admin users | list with post counts, `?q=` search escapes `%` and `_`, `LIMIT 500`, `?created=<id>` shows the one-time password |
| B30 | Add user | password optional → 16-hex random; flash `User "x" created. Initial password: <pw> (shown once — share it securely.)` |
| B31 | Ban/unban | admins can never be banned (checked in controller **and** in the repository `WHERE role != 'admin'`); reason defaults to `Violated board rules`, truncated to 255 |
| B32 | Reset password | 16-hex random, flash `New password for "x": <pw> (shown once)` |
| B33 | Moderation feed | 100 most recent non-deleted posts across all boards |
| B34 | Profile | own posts list (≤50), MFA toggle requires current password, change password (must differ from current), change email (notifies the old address) |
| B35 | Mail | `MAIL_DRIVER=log` appends the PHP record format verbatim — `[<ISO8601>] TO: <to>` newline `SUBJECT: <subject>` newline 40 dashes newline the HTML body newline `----` — to `var/log/mail.log`; OTP codes must be readable from that file by tests. The `smtp` driver composes `To:`/`Subject:` header lines from the same values, which is what `C-MAIL-1` guards |
| B36 | Password change | policy re-applied; new password equal to current → `New password must differ from the current one.` |
| B37 | Admin provisioning | role elevation from `ADMIN_EMAILS` at registration and at seed time |

## 5. Validators (identical limits and wording)

| Field | Rule | Message |
|---|---|---|
| username | 3–30 chars | `Username must be between 3 and 30 characters.` |
| username | `^[A-Za-z0-9_-]+$` | `Username may only contain letters, numbers, dashes and underscores.` |
| email | ≤ 254 chars | `Email address is too long.` |
| email | RFC-style validate | `Please provide a valid email address.` |
| password | ≥ `PASSWORD_MIN_LENGTH` | `Password must be at least N characters long.` |
| password | ≤ 200 | `Password is too long.` |
| password | letter + digit when min ≥ 8 | `Password must contain at least one letter.` / `Password must contain at least one number.` |
| password | ≠ username, ≠ email | `Password must not match your username.` / `… your email address.` |
| board name | 1–100 | `Board name must be between 1 and 100 characters.` |
| title | required, ≤ 200 | `Title is required.` / `Title must be at most 200 characters.` |
| body | non-empty, ≤ 10000 | `Message body must not be empty.` / `Message body must be at most 10000 characters.` |

Markup rules (from `security/markup.js`, all pinned by the ported `markup.test.mjs`):
escape the whole input first; then `[b] [i] [u] [url] [url=…] [img]` only;
innermost-first with at most 25 passes; URLs must be absolute `http`/`https`
with a host and no control characters or whitespace; URLs are attribute-escaped;
newlines → `<br>`; input truncated to 20 000 chars; `plain()` strips tags and
caps at 300 chars.

## 6. Fixture parity

`scripts/seed-test-data.mjs` must reproduce the PHP fixture exactly:

**Personas** (password `TestPass123`, domain `test.theboard.local`):
`owner_olivia` (admin), `mod_marcus` (admin, not in `ADMIN_EMAILS`, MFA on),
`regular_rita`, `insider_ian` (grant on Staff Room), `outsider_olly` (no grants),
`mfa_mia` (MFA on), `banned_bob` (banned, reason `Repeated spam in General (seeded test ban)`),
`lurker_lena` (no posts/votes), `prolific_pete`, `troll_tom`.

**Boards:** Announcements (open), General (open), Staff Room (restricted, grants
to `insider` and `mfa`, `regular` granted then revoked), Vault (restricted, zero
grants), Empty Board (open, no threads), Archive (open then soft-deleted, has one
thread and one grant row).

**Content invariants** (asserted by `test/integration/fixture-invariants.test.mjs`):

1. Exactly 10 persona accounts, all with password `TestPass123`.
2. Six boards, one soft-deleted; the soft-deleted board appears in no listing.
3. The sanitizer probe post contains a raw `<script>`, `<img src=x onerror=…>`,
   a `javascript:` and a `data:` URL tag, and an attribute-injection probe;
   rendered output must contain no live HTML.
4. One thread with score +4 and one reply with score +2, one reply with a
   negative score.
5. One thread whose `edited_at` is set.
6. One soft-deleted thread; one thread carrying a soft-deleted reply next to a
   surviving reply.
7. Posts by a banned author are visible.
8. General has 22 live threads, so page 2 exists and is non-empty.
9. `login_attempts` holds 3 failures and 1 success for `regular@test.theboard.local`.
10. Re-seeding without reset refuses to run.

## 7. Hook features (Node-only additions, secure on `main`)

Every hook is implemented on `main` in the form below. A vulnerability branch
downgrades exactly one control of one hook.

| Hook | Route(s) | Secure behaviour on `main` | Control | Branches it hosts |
|---|---|---|---|---|
| Avatar upload | `POST /profile/avatar`, `GET /avatar/:id`, `GET /attachment?file=` | 2 MiB cap; MIME + magic-byte allowlist (`png/jpeg/gif/webp`); extension allowlist; filename from `crypto.randomUUID()`; stored under `var/uploads/` outside `public/`; served by the controller with a fixed `Content-Type` and `Content-Disposition: inline`; no path built from user input | `C-UPLOAD-1`, `C-INFO-2` | `file_upload`, `path_traversal`, `security_misconfig` |
| Link preview | `POST /preview` | single absolute http(s) URL; resolved address must be public (no loopback/RFC1918/link-local/metadata); redirects disabled; 5 s timeout; 64 KiB read cap; only `<title>` and `meta[name=description]` text extracted, always escaped | `C-SSRF-1`, `C-XSS-2` | `ssrf`, `xss_reflected` (preview echo) |
| XML thread import/export | `GET /board/:id/export.xml`, `POST /board/:id/import` | in-house reader: UTF-8, 64 KiB cap, depth ≤ 20, entity expansion limited to internal, `DOCTYPE` with `SYSTEM`/`PUBLIC` rejected; imported text goes through `markup.js` | `C-XML-1`, `C-XSS-1`, `C-SSTI-1` | `xxe`, `ssti`, `insecure_deserialization` |
| Staff directory | `GET /directory?q=&role=` | searches `users` by exact token match; each filter token parsed by a tokenizer into `{field, op, value}` and bound as a parameter; a value that is not a string is rejected before the query | `C-DIR-1`, `C-DIR-2`, `C-SQL-1` | `ldap_injection`, `nosql_injection`, `idor` |
| Saved XPath search | `POST /directory/search` | query compiled from a parameterized AST (`field`, `op`, `value` nodes) into XPath and evaluated with `xpath` against the in-memory export document; user input never concatenated into the expression, and filter values must be primitives | `C-XPATH-1`, `C-DIR-2` | `xpath_injection` |
| Board snapshot restore | `GET /admin/boards/:id/snapshot.json`, `POST /admin/boards/:id/restore` | snapshot is plain JSON; restore validated against an explicit field schema, `type` tags whitelisted, no reviver, no dynamic dispatch, restore runs in one transaction | `C-JSON-1`, `C-RACE-1` | `insecure_deserialization`, `race_condition` |
| Thread export | `GET /thread/:id/export?format=md\|txt` | formatter runs in-process; `format` from a fixed allowlist; no shell invocation at all on `main`, and any future external binary uses `execFile` with an argument array | `C-CMD-1` | `command_injection` |
| Password reset + remember-me | `GET/POST /forgot-password`, `POST /reset-password`, `POST /login` (remember checkbox) | `jsonwebtoken` with `algorithms: ['HS256']` pinned; secret from `JWT_SECRET` (32 random bytes, generated on first boot into `var/secret.key` if absent); expiry 15 min; `jti` recorded when consumed and any reuse rejected (single-use); reset URL built only from `APP_URL` | `C-JWT-1`, `C-CRYPTO-1` | `jwt_flaws`, `open_redirect`, `host_header_injection`, `cryptographic_failures` |
| Session store | all authenticated routes | 128-bit random id, `sessions` table, expiry sweep each request batch, no payload in the cookie | `C-SESS-1`, `C-SESS-2` | `session_management`, `sqli`, `idor` |

`JWT_SECRET` is the single env key the hooks add; it is documented in
`docs/07-port-deviations.md` as a Node-only key.
