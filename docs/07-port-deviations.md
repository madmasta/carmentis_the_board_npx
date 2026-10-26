# 07 — Port deviations

Every place where the Node target is **not** a byte-for-byte port of the PHP
target, with the reason. Nothing in this list is negotiable at implementation
time; if a deviation turns out to hurt fidelity, that is a spec change on `main`,
recorded here.

## 1. Branch naming

| PHP ref | Node branch | Reason |
|---|---|---|
| `vuln/xss-reflected` | `vuln/xss_reflected` | one snake_case convention for all 35; the PHP ref is the only hyphenated one |

All other 34 names are identical. `tools/check-spec.mjs` compares the two sets
with this mapping applied.

## 2. Session storage

PHP uses native file-backed sessions (`session_start`). Node uses a `sessions`
table (`id`, `user_id`, `data JSON`, `expires_at`) added to the schema.

Reason: a scanner benchmark needs session behaviour that is observable and
attackable — `session_management`, `sqli` and `idor` all need a session substrate
in the database. Cookie-only or in-memory sessions would make three catalog
classes unreachable.

## 3. XML: in-house reader instead of a native binding

`src/xml/reader.js` parses the subset of XML the import hook needs
(elements, attributes, text, CDATA, comments, internal entities) and rejects
`DOCTYPE` with `SYSTEM`/`PUBLIC`. `xxe` turns external resolution on.

Reason: `libxmljs2` and friends are native `node-gyp` modules. The workflow rule
is "checkout a branch, `npm install` if needed, relaunch" — a compile step that
fails on a fresh machine makes the target unreliable, and it would also make the
`xxe` downgrade invisible in review because the vulnerable behaviour would live
inside a dependency.

`@xmldom/xmldom` + `xpath` (pure JS) are used only for the XPath search hook, so
the `xpath_injection` branch attacks expression construction, not a parser.

## 4. Password hashing

`bcryptjs` instead of PHP's `password_hash()`. Costs and format are the same
family, but PHP emits `$2y$` and bcryptjs emits `$2b$`. Tests never compare hash
prefixes; they compare `verify()` results, so this stays invisible to parity
tests. The constant-time dummy hash used for unknown accounts is a bcryptjs-format
hash, not the PHP `$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG`
literal.

## 5. Header injection fidelity

Node's `res.setHeader` throws on CRLF in a value, so a naive "interpolate a header
value" change would be a crash, not a vulnerability. The `header_injection` branch
therefore writes the status line and headers to the socket as bytes
(`res.writeHead` with a pre-joined array, or `res.socket.write`), which produces a
genuine response-splitting primitive. This is the closest Node-native equivalent
of the PHP behaviour, and the sheet's fidelity section states it.

## 6. Class analogues for classes with no PHP-style mechanism

| Catalog class | PHP-style mechanism | Node-native analogue used here |
|---|---|---|
| `nosql_injection` | MongoDB operator objects | operator leaves (`$ne`, `$in`, `$exists`, `$regex`, `$gt`/`$gte`/`$lt`/`$lte`) interpreted by the directory hook's criteria-document matcher (`hooks/directory.js#matchDirectory` → `#matchEntry`), fed by `POST /directory/match`. `#parseCriteria` is the trust boundary: a request document must carry scalar leaves, so on `main` the operator grammar is reachable only for documents that came out of storage. The documents are the directory's own five-column rows, evaluated in-process — no document database runs in either target |
| `ldap_injection` | `ldap_search` filter string | the directory hook builds an LDAP-shaped filter string for its "advanced search" (`mode=filter`) and evaluates it in-process with its own parser (`hooks/directory.js#renderFilter` → `#parseFilter` → `#evalFilter`); no LDAP server runs in either target. The grammar is the subset `(&…)`, `(|…)`, `(!…)`, `(attr=value)`, `(attr=*sub*)` — it has no ordering operators, so `joined>`-style tokens are refused in this mode. Injection breaks out of a filter component |
| `xpath_injection` | DOMDocument XPath | `@xmldom/xmldom` + `xpath` over the exported board document; injection breaks out of the predicate |
| `xxe` | `libxml` entity resolution | in-house reader's entity resolver |
| `insecure_deserialization` | PHP `unserialize` object injection | snapshot restore's `__type` reviver dispatch (`new Function`) |
| `command_injection` | `exec()` in PHP | `child_process.exec` with a template string in the export hook |
| `file_upload` | PHP executes uploaded `.php` | Node never executes an uploaded file; the impact model is arbitrary file write + a served path (`public/uploads`) enabling stored XSS and defacement, asserted by the sheet's oracle |
| `session_management` | `session.*` ini settings | the `sessions` store: fixation, id accepted from a query string, expiry ignored |

## 7. Hook features (no PHP equivalent)

Avatar upload, link preview, XML import/export, staff directory, saved XPath
search, board snapshot restore, thread export, and JWT password reset /
remember-me. They exist so every catalog class has a realistic sink; see
`docs/02-feature-parity.md` §7. They are present and secure on `main`.

## 8. Configuration deltas

| Key | Origin | Notes |
|---|---|---|
| `JWT_SECRET` | Node only | used by `src/security/jwt.js`; if absent, generated once into `var/secret.key` (gitignored) |
| `PORT` | Node only | HTTP listen port, default 8088 |
| `HOST` | Node only | bind address, default `127.0.0.1` |
| `MAIL_LOG` | Node only | overrides the mail log path; set by the worktree harness |
| `HOST_ALLOWLIST` | Node only | comma-separated hosts the app will answer; default is the `APP_URL` host plus `localhost`. Enforced by `request.js#hostIsAllowed` (`C-COOKIE-1`); the worktree harness adds the loopback host it connects to |
| `THEBOARD_VULN` | Node only | set by `verify:branch`; names the current branch's slug so the control register knows which downgrade is expected |

All 26 PHP keys are carried verbatim (`docs/parity/env-inventory.md`).

## 9. Infrastructure deltas

- MariaDB container is `theboard-node-db` on host port **3307**, so the PHP
  target's `theboard-db` on 3306 can run beside it for A/B measurement.
- Database names `theboard_node` / `theboard_node_test`.
- Error log is `var/log/app.log` (PHP: `var/log/php-error.log`).
- Static assets are served by an allowlist in the request pipeline; there is no
  web-server document root beyond `public/assets`.

## 10. Behavioural nuances that must be reproduced on purpose

- `mysql2` returns strings for `INT` columns unless `decimalNumbers`/`supportBigNumbers`
  are configured; the pool sets `decimalNumbers: true` so numeric columns arrive
  as numbers, matching PDO's behaviour closely enough for the ported tests.
- PDO emulated prepares are off; `mysql2` prepared statements are used with
  `?` placeholders only — named placeholders are not used anywhere.
- PHP trims superglobal input in controllers (`$this->posts()`); Node mirrors
  that in `request.js#fields('a','b')` so validation sees identical strings.
- PHP's `redirect()` sends `303` with a `Location` header built from an internal
  path; Node must send `303` too (not `302`).
- PHP's `INSERT IGNORE` is used for board grants; Node mirrors it with
  `INSERT IGNORE` (MariaDB), not with an application-side check.
- PHP's `NOW()` is server time; Node sends an ISO timestamp from `src/lib/clock.js`
  so tests can move the clock, and `schema.sql` keeps its `CURRENT_TIMESTAMP`
  defaults for columns the app never writes.
- PHP `hash_equals` → `crypto.timingSafeEqual` with equal-length buffers (a length
  mismatch returns false before the compare, which is the same observable
  behaviour).
