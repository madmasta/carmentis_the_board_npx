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

`src/hooks/export.js` — `exportThread(thread, replies, format)` is a pure function:
the format name selects one of two formatter functions from a fixed `Map`, and there
is no child process, no command string and no external binary anywhere in the app.
The branch adds a `renderer` parameter that, when present, writes the rendered
markdown to a temporary file under `var/tmp/` and shells out to a renderer script:

```
exec(`node src/hooks/renderers/${renderer}.js ${outFile}`)
```

through `child_process.exec` — `cmd.exe /c` on Windows, `/bin/sh -c` elsewhere. The
renderer name is interpolated into the command line, and `exec` runs the line through
a shell, so a shell separator in the parameter ends the first command and starts a
second. The asynchronous wrapper is `exportThreadWithRenderer`, which the export
handler calls when the query carries `renderer`; without it the handler keeps calling
the synchronous `exportThread`, which is why the unchanged formats still produce
byte-identical output.
## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-CMD-1` | No shell; `execFile` with an argument array only | `exec` with an interpolated command string replaces the in-process formatter |

## Minimal diff

Files touched:

- `src/hooks/export.js` — import `exec` from `node:child_process`; add
  `renderWith()` (the interpolated command string) and
  `exportThreadWithRenderer()` (the awaitable wrapper the handler uses).
- `src/hooks/renderers/inline.js` — new trivial renderer: the file the command line
  names, which reads the export file back and writes it out again.
- `src/http/hooks.controller.js` — read `renderer` from the query string and call
  `exportThreadWithRenderer` when it is present.
- `test/vulns/command_injection.test.mjs` — new file.

## Payload sketch

```
GET /thread/:id/export?format=md&renderer=inline&echo+PWNED-CMDINJ%3E%20%2Fabs%2Fpath%2Fto%2Fvar%2Flog%2Fpwned.txt+%23
```

i.e. `renderer=inline&echo PWNED-CMDINJ> /abs/path/to/var/log/pwned.txt #`.

Three details make the payload portable across the two shells `exec` may use, and
they are worth recording because a scanner will not find them by itself:

- `&` separates commands on both `cmd.exe` and POSIX shells; `;` separates
  arguments on `cmd.exe`, so a `;` payload produces a `node` invocation with extra
  arguments rather than a second command.
- The command line the app writes ends the renderer name with `.js`, so anything
  following the injected command inherits that `.js` as a token. A trailing `#`
  makes it a comment on a POSIX shell and a harmless extra word for `echo` on
  `cmd.exe`; either way the redirect target is the path the payload names.
- The redirect uses an absolute path: `exec` inherits the app's working directory,
  and the test asserts the file at the same absolute path it embedded.

Expected effect: the export still renders (the first command's failure is ignored),
and `<marker>` appears on disk containing `PWNED-CMDINJ`. The time-based variant —
`renderer=inline&ping -n 4 127.0.0.1 #`, or `-n`/`-c` per platform — is the fallback
for a probe that can only compare response times; this sheet's oracle uses the file
because it is unambiguous.

## Differential oracle

`test/vulns/command_injection.test.mjs`:

1. Remove the marker file if it exists; sign in as `insider_ian`; create a board and
   a thread that the persona can export (the suite's `makeBoard`/`makeThread`
   helpers), so the fixture personas stay untouched.
2. Request `?format=md&renderer=inline` first — a renderer name with no separator —
   and assert the export returns `200` with the markdown body, and that no marker
   file exists afterwards.
3. Send the separator payload against the same thread, assert the response is `200`
   and still carries the rendered thread title, then assert the marker file exists
   and contains `PWNED-CMDINJ` (the export awaits the subprocess, so no polling is
   needed; the case still allows a short grace period for the filesystem).
4. Remove the marker, request `?format=zsh` and assert `400 Unknown export format.`:
   the `format` allowlist is intact, and only `renderer` is trusted.
5. In `afterAll`, delete the marker file and the temporary export file the branch
   writes under `var/tmp/`. Nothing outside `var/` is written by the oracle.

On `main` step 3 must fail: the `renderer` parameter is not read, `exportThread` is
the only formatter, no child process exists, and the marker file never appears. Steps
2, 4 and the status assertions pass on both, which is what keeps the downgrade
scoped to the one parameter.
## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
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
