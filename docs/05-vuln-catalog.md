# 05 — Vulnerability catalog

35 branches, one per row, matching the PHP repo's `vuln/*` refs one-for-one
(`xss-reflected` normalizes to `xss_reflected`; see `docs/07-port-deviations.md`).

Rules that apply to every row and are not re-negotiated per branch:

- One branch = one commit off `main`. The commit is the diff described in the
  sheet's **Minimal diff** section, nothing else.
- The branch downgrades the named control(s) from `docs/03-security-baseline.md`
  and nothing else.
- The branch adds `test/vulns/<slug>.test.mjs`, which passes on the branch and
  must fail against `main` (checked by `tools/verify-all-branches.mjs`).
- The baseline suite stays green except for the explicitly skipped control IDs.
- No branch may make the app fail to start, break `/health`, or break login for
  the seeded personas unless that is the vulnerability itself.

Effort: **S** ≈ ≤ 30 lines, **M** ≈ 30–120 lines, **L** ≈ 120+ lines or needs a
new fixture/test harness.

| # | Branch | CWE | Class | Entry route (parameter) | Control(s) removed | Sink | Effort | Sheet |
|---|---|---|---|---|---|---|---|---|
| 1 | `vuln/auth_requirement_mismatch` | CWE-285 | Same capability, two auth requirements | `POST /directory/search` (`q`) | `C-ACL-4`, `C-ACL-2` | `src/routes.js` alias entry | S | [sheet](vulns/auth_requirement_mismatch.md) |
| 2 | `vuln/broken_function_level_authz` | CWE-862 | Missing function-level authorization | `POST /board/:id/import` (body) | `C-ACL-2` | `src/http/board.controller.js#importBoard` | S | [sheet](vulns/broken_function_level_authz.md) |
| 3 | `vuln/command_injection` | CWE-78 | OS command injection | `GET /thread/:id/export?renderer=` | `C-CMD-1` | `src/hooks/export.js#renderWith` | M | [sheet](vulns/command_injection.md) |
| 4 | `vuln/cors_misconfig` | CWE-942 | Origin trust / CORS | `GET /admin/users` (`Origin`) | `C-HDR-3` | `src/http/headers.js` | S | [sheet](vulns/cors_misconfig.md) |
| 5 | `vuln/cryptographic_failures` | CWE-327, CWE-330 | Weak randomness and primitives | `POST /forgot-password`, upload names | `C-CRYPTO-1` | `src/security/tokens.js`, `src/hooks/upload.js` | S | [sheet](vulns/cryptographic_failures.md) |
| 6 | `vuln/csrf` | CWE-352 | CSRF protection absent | every state-changing route | `C-CSRF-1` | `src/http/controller.js#csrf` | S | [sheet](vulns/csrf.md) |
| 7 | `vuln/email_header_injection` | CWE-93 | SMTP header injection | `POST /forgot-password` (`email`) | `C-MAIL-1` | `src/mail/mailer.js#headersFor` | S | [sheet](vulns/email_header_injection.md) |
| 8 | `vuln/file_upload` | CWE-434 | Unrestricted file upload | `POST /profile/avatar` (`avatar` part) | `C-UPLOAD-1`, `C-INFO-2` | `src/hooks/upload.js#store` | M | [sheet](vulns/file_upload.md) |
| 9 | `vuln/header_injection` | CWE-113 | HTTP header / response splitting | `GET /directory?q=` (`q`) | `C-HDR-2` | `src/http/headers.js#searchEcho` | M | [sheet](vulns/header_injection.md) |
| 10 | `vuln/host_header_injection` | CWE-640 | Host header trust / link poisoning | `POST /forgot-password` (`Host`) | `C-COOKIE-1` | `src/security/jwt.js#resetUrl` | S | [sheet](vulns/host_header_injection.md) |
| 11 | `vuln/idor` | CWE-639 | Direct object reference | `POST /post/:id/edit` (`id`, body) | `C-ACL-3` | `src/repositories/post.repository.js#editPost` | S | [sheet](vulns/idor.md) |
| 12 | `vuln/information_disclosure` | CWE-200 | Verbose error / environment disclosure | `GET /health`, any 500 | `C-INFO-1`, `C-DATA-1` | `src/server.js#errorPage` | S | [sheet](vulns/information_disclosure.md) |
| 13 | `vuln/insecure_deserialization` | CWE-502 | Unsafe deserialization | `POST /admin/boards/:id/restore` (JSON body) | `C-JSON-1` | `src/hooks/snapshot.js#revive` | L | [sheet](vulns/insecure_deserialization.md) |
| 14 | `vuln/jwt_flaws` | CWE-347, CWE-345 | Token verification bypass | `POST /reset-password` (`token`) | `C-JWT-1` | `src/security/jwt.js#verify` | M | [sheet](vulns/jwt_flaws.md) |
| 15 | `vuln/ldap_injection` | CWE-90 | LDAP-style filter injection | `GET /directory?q=` (`q`) | `C-DIR-1` | `src/hooks/directory.js#buildFilter` | M | [sheet](vulns/ldap_injection.md) |
| 16 | `vuln/log_injection` | CWE-117 | Log forging | any request (`User-Agent`, path) | `C-INFO-3` | `src/http/server.js#logRequest` | S | [sheet](vulns/log_injection.md) |
| 17 | `vuln/mass_assignment` | CWE-915 | Mass parameter assignment | `POST /profile` (`role`) | `C-ASSIGN-1` (field-allowlist clause) | `src/http/profile.controller.js#update` | M | [sheet](vulns/mass_assignment.md) |
| 18 | `vuln/nosql_injection` | CWE-917 | Operator injection in a document query | `GET /directory?q[$ne]=` | `C-DIR-2` | `src/hooks/directory.js#matchDoc` | S | [sheet](vulns/nosql_injection.md) |
| 19 | `vuln/open_redirect` | CWE-601 | URL redirection to untrusted site | `GET /login?next=//…` | `C-REDIR-1` | `src/http/auth.controller.js#consumeIntendedPath` | S | [sheet](vulns/open_redirect.md) |
| 20 | `vuln/path_traversal` | CWE-22 | Path traversal | `GET /attachment?file=../` | `C-UPLOAD-1`, `C-INFO-2` | `src/hooks/upload.js#readAttachment` | M | [sheet](vulns/path_traversal.md) |
| 21 | `vuln/race_condition` | CWE-362 | Race condition / single-use bypass | `POST /mfa` (`code`) | `C-RACE-1` | `src/security/mfa.js#verify` | M | [sheet](vulns/race_condition.md) |
| 22 | `vuln/security_misconfig` | CWE-16, CWE-215 | Insecure shipped defaults | app-wide, `/assets/`, `/server-info` | `C-INFO-1`, `C-INFO-2`, `C-AUTH-3` | `config/defaults.js`, `src/http/server.js` | M | [sheet](vulns/security_misconfig.md) |
| 23 | `vuln/sensitive_data_exposure` | CWE-201, CWE-259 | Sensitive data in responses/logs | `GET /admin/users`, `GET /profile` | `C-DATA-1`, `C-INFO-3` | `src/repositories/user.repository.js#toPublic` | S | [sheet](vulns/sensitive_data_exposure.md) |
| 24 | `vuln/session_management` | CWE-384 | Session fixation / id handling | `POST /login` (cookie) | `C-SESS-2`, `C-SESS-1` | `src/session/store.js#regenerate` | M | [sheet](vulns/session_management.md) |
| 25 | `vuln/sqli` | CWE-89 | SQL injection | `GET /admin/users?q=`, `GET /directory?q=` | `C-SQL-1`, `C-SQL-2`, `C-SQL-3`, `C-DIR-1` | `src/repositories/user.repository.js#allUsers` | M | [sheet](vulns/sqli.md) |
| 26 | `vuln/ssrf` | CWE-918 | Server-side request forgery | `POST /preview` (`url`) | `C-SSRF-1` | `src/hooks/preview.js#fetchTarget` | M | [sheet](vulns/ssrf.md) |
| 27 | `vuln/ssti` | CWE-1336 | Server-side template injection | `POST /board/:id/import` (XML body text) | `C-SSTI-1` | `src/hooks/xml-import.js#renderText` | M | [sheet](vulns/ssti.md) |
| 28 | `vuln/vulnerable_components` | CWE-1035, CWE-1104 | Known-vulnerable dependencies | `POST /reset-password` (`token`) | `C-DEP-1` | `package.json`, `package-lock.json` | S | [sheet](vulns/vulnerable_components.md) |
| 29 | `vuln/weak_password_policy` | CWE-521 | Weak password requirements | `POST /register` (`password`) | `C-AUTH-2` | `src/security/validator.js#password` | S | [sheet](vulns/weak_password_policy.md) |
| 30 | `vuln/xpath_injection` | CWE-643 | XPath injection | `POST /directory/search` (`q`) | `C-XPATH-1`, `C-DIR-2` | `src/hooks/xpath.js#compile` | M | [sheet](vulns/xpath_injection.md) |
| 31 | `vuln/xss_config` | CWE-693, CWE-116 | Protection mechanism removed by config | `GET /directory?q=` (`q`) | `C-XSS-3`, `C-XSS-2` | `src/security/headers-policy.js`, `src/views.js` | M | [sheet](vulns/xss_config.md) |
| 32 | `vuln/xss_dom` | CWE-79 | DOM-based XSS | `GET /directory?q=` (client-side) | `C-XSS-2` | `public/assets/app.js` | S | [sheet](vulns/xss_dom.md) |
| 33 | `vuln/xss_stored` | CWE-79 | Stored XSS | `POST /board/:id/thread` (`body`) | `C-XSS-1` | `src/security/markup.js#render` | M | [sheet](vulns/xss_stored.md) |
| 34 | `vuln/xss_reflected` | CWE-79 | Reflected XSS | `POST /preview` (`url`) | `C-XSS-2` | `templates/preview.njk` | S | [sheet](vulns/xss_reflected.md) |
| 35 | `vuln/xxe` | CWE-611 | XML external entity | `POST /board/:id/import` (`xml`) | `C-XML-1` | `src/xml/reader.js#resolveEntity` | M | [sheet](vulns/xxe.md) |

## Family grouping (for scanner coverage review)

| Family | Branches |
|---|---|
| Injection | `sqli`, `nosql_injection`, `xpath_injection`, `ldap_injection`, `command_injection`, `log_injection`, `email_header_injection`, `header_injection` |
| Output handling | `xss_stored`, `xss_reflected`, `xss_dom`, `xss_config`, `ssti`, `xxe` |
| Authentication | `csrf`, `session_management`, `jwt_flaws`, `cryptographic_failures`, `weak_password_policy`, `race_condition` |
| Authorization | `idor`, `auth_requirement_mismatch`, `broken_function_level_authz`, `mass_assignment` |
| Request handling | `open_redirect`, `host_header_injection`, `cors_misconfig`, `ssrf`, `path_traversal`, `file_upload` |
| Configuration and supply chain | `security_misconfig`, `information_disclosure`, `sensitive_data_exposure`, `vulnerable_components`, `insecure_deserialization` |

## Coverage notes

- `auth_requirement_mismatch` and `broken_function_level_authz` are deliberately
  different predicates: row 1 is a **route-table** defect (one capability, two
  declared guards, one anonymous), row 2 is a **handler-level** defect (a role
  check replaced by a login check on an admin capability outside `/admin/*`).
  A scanner that reports both must have found two different things.
- `xss_config` removes the *protections* (CSP + autoescape) while `xss_reflected`
  introduces an unescaped sink with the protections intact. Their oracles differ
  in exactly that respect.
- `path_traversal` and `file_upload` share the upload hook but attack different
  controls: reading outside the storage root vs writing an arbitrary file.
- `ldap_injection`, `nosql_injection` and `xpath_injection` share the directory
  hook but each removes a different control (`C-DIR-1` tokenizer, `C-DIR-2`
  value typing, `C-XPATH-1` AST building). Their Node-native analogues are
  documented in each sheet's fidelity section.
- No branch introduces a new dependency except `vuln/vulnerable_components`,
  which only *downgrades* the versions of dependencies already allowed by
  `docs/01-architecture.md` §7.
