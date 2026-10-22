# 06 — Branch and run workflow

The target is only useful if switching between the control build and a
vulnerable build is trivial, repeatable and parallel-safe. This document fixes
the topology and the tooling; M0 implements it.

## 1. Topology

```
main                         control build, tagged baseline-secure once M8 starts
vuln/<slug>                  exactly one commit off main, 35 of them
baseline-secure (tag)       the commit every branch was cut from
```

- Branch names: `vuln/<slug>` with the slug exactly as listed in
  `docs/05-vuln-catalog.md` (snake_case; `vuln/xss_reflected` is the normalized
  form of the PHP repo's `vuln/xss-reflected`).
- A branch is created from `main` only. If `main` moves, the branch is rebased
  so it stays one commit ahead:
  `git rebase --onto main <old-base> vuln/<slug>`.
- Vulnerability branches are never merged. They are never tagged.
- `docs/vulns/<slug>.md` and `docs/05-vuln-catalog.md` live on `main`; the branch
  carries only code and its exploit test.

## 2. Run targets

| | Control | Vulnerable branch |
|---|---|---|
| URL | `http://localhost:8088` | `http://localhost:8088` after a swap |
| Database | `theboard_node` / `theboard_node_test` | same names when run alone; per-branch names under the fan-out harness |
| Mail | `var/log/mail.log` (OTPs land here) | same |
| Start | `npm start` | `npm run branch:swap -- vuln/<slug>` |

`HOST` defaults to `127.0.0.1`; set `HOST=0.0.0.0` only when a scanner runs on
another machine and accept that the target then has no network protection at all.

## 3. `npm run branch:swap -- vuln/<slug>`

`scripts/branch-swap.mjs` performs, in order, and fails loudly at the first
problem:

1. Refuse if the working tree is dirty (`git status --porcelain` non-empty).
2. `git checkout <branch>` (accepts `main`).
3. `npm install --no-audit` if `package.json` changed between HEAD and the
   checkout (`git diff --name-only` contains it) — needed by
   `vuln/vulnerable_components`.
4. `npm run db:reset -- --force`.
5. Print the branch, the commit subject, the control IDs the branch removes (read
   from `docs/vulns/<slug>.md`), and the URL to point Carmentis at.
6. Start the server on `PORT` unless `--no-serve` is passed.

A swap always leaves the app in the documented fixture state of
`docs/02-feature-parity.md` §6, so scan results are comparable across branches.

## 4. Worktree fan-out (`node tools/verify-all-branches.mjs`)

For parallel verification (and for running several builds at once for Carmentis):

```
../wt-<slug>            worktree for vuln/<slug>
PORT  = 8090 + index    index = position of the slug in docs/05 (0-based)
DB    = theboard_node_<slug>  /  theboard_node_<slug>_test
MAIL  = var/log/<slug>-mail.log
```

- Allocation is derived, never chosen by hand, so two agents cannot collide.
- The harness passes `PORT`, `DB_NAME`, `MAIL_LOG` through the environment.
- Matrix output and pass/fail semantics are in `docs/04-testing-and-verification.md` §7.
- A worktree is removed with `git worktree remove ../wt-<slug>` after its row
  passes; `--keep` retains them for manual scanner runs.

## 5. Scan profiles (what Carmentis is pointed at)

Every scan run uses one of these profiles; they are identical across branches so
findings stay comparable.

| Profile | How it is obtained | Used for |
|---|---|---|
| `anon` | no cookie | unauthenticated surface: `/`, `/login`, `/register`, `/health`, hook routes that are login-free |
| `regular` | `POST /login` as `regular_rita` / `TestPass123`, keep the session cookie, then send `POST /logout` | authenticated surface: boards, posts, votes, profile, hooks |
| `admin` | same as `regular` with `owner_olivia` / `TestPass123` | `/admin/*`, snapshot/restore, moderation |
| `mfa` | `mfa_mia`; the OTP is read from the run's mail log | MFA-protected flows |

The harness exposes these as `node scripts/scan-profile.mjs <profile>` which
prints a cookie header plus the persona's accessible board ids, so a scanner run
starts from a known authenticated position.

## 6. Reset guarantees

`npm run db:reset` (`scripts/reset.mjs`) mirrors `bin/reset.php`:

- drops and recreates `DB_NAME` as root (`DB_ROOT_PASS`); falls back to dropping
  tables as `DB_USER` when root is unavailable, and says so;
- applies `schema.sql` (including the `sessions` table);
- provisions admins from `ADMIN_EMAILS` (`scripts/seed-admins.mjs`, supports
  `--reset-passwords`);
- seeds the fixture personas (`scripts/seed-test-data.mjs`, refuses to run twice);
- truncates the mail log unless `--keep-mail-log`;
- `--force` skips the interactive `reset` confirmation, `--no-test-data` skips
  the personas.

Nothing else in the repository may destroy data. Tests only touch `*_test`.

## 7. Safety rules for scanning

- Scan only from the machine that hosts the target, or behind a dedicated
  network. The vulnerable branches are intentionally unsafe.
- Never run a `vuln/*` branch with `HOST=0.0.0.0` on a shared network.
- `LOGIN_THROTTLE_DISABLED=1` is available for scan speed and is honoured only
  with `APP_DEBUG=1`; when it is active the app prints a banner on every page and
  logs each bypass. Scanner runs that need speed must set both and record that
  they did; `carmentis/results.md` has a column for it.
- `command_injection`, `insecure_deserialization`, `ssti`, `path_traversal` and
  `xxe` branches can affect the host filesystem or process. Run them as an
  unprivileged user, and never with credentials in the environment that matter.
