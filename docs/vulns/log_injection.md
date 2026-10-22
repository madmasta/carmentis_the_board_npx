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

- Route: every route logs, so any request works; the oracle uses `GET /` and
  `GET /health`
- Parameter: the request target, as logged after percent-decoding (the `User-Agent`
  header is logged too but `node:http` will not carry a raw newline in a header,
  so the path is the reachable vector)
- Prerequisites: `anon` profile
- Reachability: every request is logged

## Sink

`src/http/server.js` — `logRequest(req, res)`. For readable logs the app records
the **decoded** request target (`decodeURIComponent(url.split('?')[0])`). On
`main` every request-derived field then passes `escapeLogValue()` (CR/LF and
other control characters replaced with `\xNN`, values truncated to 200
characters). The branch drops the escaping for the decoded target and the
`User-Agent`.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-INFO-3` | One line per record; user values newline-stripped and truncated | the escaping call is removed from the UA and target fields |

## Minimal diff

Files touched:

- `src/http/server.js` — interpolate the decoded request target and
  `req.headers['user-agent']` into the log line without `escapeLogValue`.
- `test/vulns/log_injection.test.mjs` — new file.

## Payload sketch

```
GET /%0A%5BSECURITY%5D%20FORGED-a1b2c3%20login%20throttle%20BYPASSED%20email=owner@theboard.example%20ip=127.0.0.1
User-Agent: probe
```

The percent-encoded `%0A` decodes inside the logger, so the log gains a second
physical line that carries the application's own `[SECURITY]` prefix shape.

Expected effect: `var/log/app.log` gains lines that are indistinguishable from the
application's own security banner lines.

## Differential oracle

`test/vulns/log_injection.test.mjs`:

1. Truncate `var/log/app.log` through the test helper and record its size.
2. Send `GET /%0A…FORGED-<random>…` (the payload above) with the marker in the
   injected second line.
3. Read the tail of the log and assert a line exists that starts with
   `FORGED-` at column 0 — i.e. a record the application itself never writes.
4. Assert the forged record's timestamp prefix is absent, proving the second line
   is attacker text and not an application record.

On `main` this test must fail because the injected newline is written as
`\x0A`, leaving exactly one physical line containing the escaped marker.

## Must-not-break invariants

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
