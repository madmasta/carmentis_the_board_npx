# command_injection — OS command injection in the thread export

- Branch: `vuln/command_injection`
- Catalog row: 3
- Effort: M
- Hook: thread export
- Test file: `test/vulns/command_injection.test.mjs`

## Class and CWE

OS command injection — CWE-78. Family: injection.

## Intent

Prove that an export parameter reaches a shell command line, so a caller can make
the host process run an additional command.

## Affected surface

- Route: `GET /thread/:id/export?format=md&renderer=`
- Parameter: `renderer` (query string)
- Prerequisites: `regular` scan profile, and access to the board owning `:id`
- Reachability: the export link on the thread page has a "renderer" dropdown

## Sink

`src/hooks/export.js` — `renderWith(markdownFile, renderer)`. On `main` the
formatter runs in-process and `format` comes from a fixed allowlist
(`md`, `txt`); no child process exists. The branch adds a `renderer` parameter
and shells out: `` exec(`node src/hooks/renderers/${renderer}.js ${outFile}`) ``
through `child_process.exec`, which on Windows is `cmd.exe` and on POSIX a shell.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-CMD-1` | No shell; `execFile` with an argument array only | `exec` with an interpolated command string replaces the in-process formatter |

## Minimal diff

Files touched:

- `src/hooks/export.js` — import `exec` from `node:child_process`, add
  `renderWith()` with the interpolated command string, and call it when the
  request carries `renderer`.
- `src/hooks/renderers/inline.js` — new trivial formatter (the file the command
  line names).
- `test/vulns/command_injection.test.mjs` — new file.

## Payload sketch

```
GET /thread/1/export?format=md&renderer=inline;echo%20PWNED-CMDINJ>%20var/log/pwned.txt
GET /thread/1/export?format=md&renderer=inline&x=%26%26%20ping%20-n%205%20127.0.0.1
```

The first payload leaves a file; the second is the time-based probe (about four
extra seconds) for scanners that only compare responses.

Expected effect: the export still renders, and `var/log/pwned.txt` appears on disk
containing `PWNED-CMDINJ`.

## Differential oracle

`test/vulns/command_injection.test.mjs`:

1. Delete `var/log/pwned.txt` if present; sign in as `insider_ian`.
2. Send the payload against a thread in General (fixture thread id from the seed
   helper).
3. Assert the response is `200` and the export body is returned.
4. Wait up to 3 s for `var/log/pwned.txt` to exist and contain `PWNED-CMDINJ`;
   assert it does, then delete the file in `afterAll`.
5. Assert a plain `renderer=inline` request produced no such file.

On `main` this test must fail because the `renderer` parameter is ignored, no
child process is ever spawned, and the marker file never appears.

## Must-not-break invariants

- `GET /thread/:id/export?format=md` and `?format=txt` still return the same
  bytes as on `main` for the fixture thread.
- `format` stays allowlisted — a bad `format` is still `400`; only `renderer` is
  trusted.
- `test/integration/post.test.mjs` and `test/security/controls.test.mjs` for
  `C-CMD-1` are the only control expectation changed.
- No branch may write outside `var/` in the test path; the oracle cleans up.

## Fidelity to the PHP branch

The PHP target's class is the classic `exec()` sink; this port reproduces it in
the export hook because that is where the app legitimately renders output, and
the control (`execFile` + argument array, or no subprocess at all) is the
Node-native form recorded in `docs/07` §6.

## Carmentis evidence

Capture the `renderer` parameter, the `;`/`&&` separator payload, and either the
marker file or the response-time delay from a `ping`-style payload. Expected
label: `CWE-78 / OS Command Injection`. False-negative watch-out: the parameter
must survive query-string decoding with the separator intact, and the oracle's
side effect is a file, so a scanner that only diffs response bodies will see no
difference — the time-based variant (`renderer=inline&…&sleep`) is the fallback
probe recorded in the sheet's payload block.

## Definition of done

- [ ] `test/vulns/command_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: command_injection — build the export renderer command as a shell string`.
