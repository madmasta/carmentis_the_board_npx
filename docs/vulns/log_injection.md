# log_injection — forged log records through the request log

- Branch: `vuln/log_injection`
- Catalog row: 16
- Effort: S
- Hook: core app (request logger)
- Test file: `test/vulns/log_injection.test.mjs`

## Class and CWE

Log forging / improper output neutralization for logs — CWE-117. Family: injection.

## Intent

Prove that request-controlled text is written to the application log without
newline neutralization, so an attacker can insert records that look like they came
from the application — including fake security events.

## Affected surface

- Route: `GET /` logs, and so does every other route — the oracle sends `GET /
  %0A…` (an unmatched target), which is logged as the `404` template and disturbs
  nothing else
- Parameter: the request target, percent-decoded by the logger. The `User-Agent`
  header is the second logged field on the branch; `node:http` refuses a raw newline
  in a header value, so the header is a tampering vector (control characters,
  spoofed fields) and the path is the line-splitting vector.
- Prerequisites: `anon` profile
- Reachability: every request is logged

## Sink

`src/http/server.js` — `logRequest(method, routeTemplate, statusCode, session)` is
called on every exit path of the handler (matched route, 404, host rejection, static
file, CSRF rejection, guard halt, unhandled error). What it writes is the **matched
route template** (`/board/:id`, `404`, `host-rejected`), never the raw request target,
and the record goes through `log()` in `src/lib/log.js`, which runs every field
through `sanitize()`: control characters flattened, whitespace collapsed, length
bounded to 400. There is therefore no request-controlled string in the log that can
contain a newline.

The branch adds the caller-controlled fields and writes the record itself, bypassing
`log()`/`sanitize()` for that line:

```
`[${isoTimestamp()}] request ${method} ${routeTemplate} -> ${statusCode} ` +
`uid=${session?.userId ?? '-'} path=${decodeURIComponent(pathname)} ua=${ua}`
```

appended straight to `logPath()`. The percent-decoded target is where the newline
comes from; the `User-Agent` arrives raw as well.
## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-INFO-3` | One line per record; user values newline-stripped and truncated | the request record is written to `logPath()` directly, so `sanitize()` no longer touches it, and the decoded target and `User-Agent` are interpolated raw |

## Minimal diff

Files touched:

- `src/http/server.js` — give `logRequest` the incoming request, interpolate the
  percent-decoded pathname and `req.headers['user-agent']` into the record, and append
  that record to `logPath()` with `appendFileSync` instead of routing it through
  `logInfo`/`sanitize`.
- `test/vulns/log_injection.test.mjs` — new file.

## Payload sketch

```
GET /%0A%5BSECURITY%5D%20FORGED-a1b2c3%20login%20throttle%20BYPASSED%20email=owner@theboard.example%20ip=127.0.0.1
User-Agent: probe/1.0
```

The path is unmatched, so the record's own route template is `404` and the request
changes nothing else. `%0A` is decoded inside the logger, so the file gains a second
physical line that opens at column 0 with the application's own `[SECURITY]` prefix
shape — the same prefix the login-throttle bypass record uses (`docs/03` C-INFO-3).

The same record also carries an unescaped `User-Agent`, which is how a caller can
plant arbitrary field-like text (`path=… ua=… uid=…`) into a record the application
wrote.

Expected effect: `app.log` (wherever `APP_LOG` points) gains a line the application
never writes, byte-identical in shape to its own security banner lines.

## Differential oracle

`test/vulns/log_injection.test.mjs`:

1. Truncate the log through `clearForTests()` and note where it ends; read it back
   through `logPath()`, so the assertion follows `APP_LOG` rather than guessing.
2. Send two ordinary requests (a `GET /` and a `GET /health`) and assert the log holds
   exactly two new request records — one physical line each.
3. Send the percent-encoded payload above with a random `FORGED-<hex>` marker on the
   injected second line.
4. Assert a line exists that **starts** with `[SECURITY] FORGED-` — a record opening at
   column 0 that the application never writes.
5. Assert that line carries no `[…]` timestamp prefix: it is attacker text, not an
   application record that happens to mention the marker.
6. Assert the request still produced its own honest record (`404` as the route
   template), so the forgery is an addition rather than a replacement.
7. Sign in as a persona and assert the log still contains no session id, no password
   hash and no OTP code: the branch removes the newline rule, not the
   sensitive-field rule, and this case is what proves the difference.
8. Assert a `User-Agent` value is interpolated without neutralization — the record's
   `ua=` field contains the caller's characters exactly.

On `main` steps 4, 5, 6 and 8 must fail: the target is not logged at all (the route
template is), the record is sanitized, and no `ua=` field exists — so no line can
start with the marker and the injected newline never reaches the file.
## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The request logger still emits exactly one record per request for normal
  traffic (asserted by `test/unit/logging.test.mjs` for ordinary requests, which
  must stay green).
- Session ids, password hashes and OTP codes still never reach `app.log`
  (`C-INFO-3` is skipped only for the newline rule; the sensitive-field rule is
  re-asserted inside the exploit test itself).
- `test/security/baseline-inert.test.mjs` passes.

## Fidelity to the PHP branch

Same class and same primitive as the PHP target's log branch: unsanitized
request data in a line-based log. Node writes the same single-line format the PHP
error log uses, so the forged-record evidence is identical.

## Carmentis evidence

Capture the `User-Agent` payload and the two physical log lines it produced.
Expected label: `CWE-117 / Log Injection`. False-negative watch-out: the evidence
is out-of-band (a file), so the run must include the log file in the collected
artefacts; a scanner that inspects only HTTP responses cannot see this class.

## Definition of done

- [ ] `test/vulns/log_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: log_injection — write request headers and target to the log unescaped`.
