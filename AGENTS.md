# Agent playbook

Every agent working in this repository follows these rules. They exist so that
many agents can build this target in parallel without colliding and without
re-opening decisions that are already fixed.

## 1. Read in this order

1. `README.md` — what the target is.
2. `docs/00-vision-and-scope.md` — what is in and out of scope.
3. `docs/01-architecture.md` — the module map you must implement.
4. `docs/02-feature-parity.md` + `docs/parity/*.md` — the behaviour you must match.
5. `docs/03-security-baseline.md` — the control register (`C-XXX-n`).
6. `docs/04-testing-and-verification.md` — how your work is judged.
7. Your milestone section in `MILESTONES.md` — entry criteria, exit gate, files
   you may touch.
8. If you are building a vulnerability branch: `docs/05-vuln-catalog.md`,
   `docs/vulns/<your-slug>.md`, `docs/templates/vuln-sheet-template.md`,
   `docs/06-branch-and-run-workflow.md`.

## 2. The no-decision rule

The specs are decision-complete. If you find yourself needing a decision that
the specs do not make:

1. Check `docs/07-port-deviations.md` — divergences are listed there.
2. Check the generated inventories in `docs/parity/` — they are machine truth.
3. If it is still open, **stop and report the gap**; do not silently invent
   behaviour, and do not "improve" a control, route, message, fixture or schema
   column. A spec gap is a defect in the spec suite and gets fixed in a spec
   commit on `main` before the code is written.

## 3. One writer per worktree

- Exactly one agent may hold write access to a given branch/worktree at a time.
- Branch work happens in its own worktree:
  `git worktree add ../wt-<slug> vuln/<slug>` (see `docs/06`).
- Never run the app or the suite from two worktrees on the same port or the same
  database name. Ports and DB names are derived per worktree by
  `tools/verify-all-branches.mjs`.

## 4. Files each milestone may touch

Only the files listed for your milestone in `MILESTONES.md`. Cross-cutting
changes (a new dependency, a schema column, a shared helper signature) are a
separate commit on `main` that updates the relevant spec document in the same
commit, and must be announced before other agents rebase.

## 5. Never do

- Touch anything in `../carmentis_the_board` (the PHP target is read-only).
- Edit a generated file in `docs/parity/` by hand — regenerate with
  `node tools/extract-parity.mjs`.
- Add a dependency outside the list in `docs/01-architecture.md` §7. Adding one
  requires a spec commit that names it and its purpose.
- Weaken a control on `main` to make a vulnerability branch easier to write.
  Branches downgrade controls; `main` never does.
- Skip, mark TODO, or delete a test to make a gate pass.
- Leave `TBD`, `TODO`, `FIXME`, `???`, "or similar", or "etc." in any file under
  `docs/` — `npm run verify:spec` fails on them.
- Create a `vuln/*` branch from another `vuln/*` branch.
- Commit `.env`, `var/`, `node_modules/`, or anything containing a secret.

## 6. Commit conventions

- `main` work: `<area>: <what changed>` (e.g. `auth: implement MFA lifecycle`).
- Vulnerability branch commit (exactly one per branch):
  `vuln: <slug> — <one-line description of the downgrade>`.
- Spec work: `spec: <what>`.
- One logical change per commit on `main`. A `vuln/*` branch has exactly one
  commit whose diff is the one described in its spec sheet.

## 7. Definition of done, per milestone

The exit gate in `MILESTONES.md` is a command, not a feeling. Do not hand off
until it is green in your worktree, and report the command output when you do.

For a vulnerability branch:

```bash
npm run verify:branch          # baseline suite + your exploit test, both green
git log --oneline main..HEAD   # exactly one commit
git diff --stat main..HEAD     # only the files your sheet's "Minimal diff" names
node tools/check-spec.mjs      # spec gates still pass (catalog/sheet consistency)
```

## 8. Adding a vulnerability branch, step by step

1. `git fetch && git worktree add ../wt-<slug> -b vuln/<slug> main`
2. Read `docs/vulns/<slug>.md` end to end.
3. Write the exploit test first (`test/vulns/<slug>.test.mjs`) exactly as the
   sheet's "Differential oracle" section specifies; confirm it **fails on `main`**.
4. Apply the "Minimal diff" on the branch.
5. Run `npm run verify:branch`; the exploit test now passes and the baseline
   suite stays green.
6. Commit once with the branch's commit convention, and report the diff stat.
7. Do not merge. Vulnerability branches are never merged into `main`.
