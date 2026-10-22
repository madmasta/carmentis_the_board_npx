# Roadmap

The Node target exists to serve the same four-step programme as the PHP target,
with the Node-specific surface added so every PHP vulnerability class has a
Node home.

1. Build the application as a control and verify it has no vulnerabilities of
   the 35 catalog classes (`main`, tagged `baseline-secure`).
2. Build out the reset/seed functionality so the target always starts from the
   same, repeatable state (`npm run db:reset`).
3. Run Carmentis against the control build and record the result
   (`M9`, `carmentis/control-run.md`).
4. Build one vulnerability per branch and make branch swapping plus relaunch a
   single command (`npm run branch:swap`, `npm run verify:branches`).

The PHP roadmap's step 4 is already realised in the PHP repo as 35 `vuln/*`
branches; `docs/05-vuln-catalog.md` fixes their content for Node, and
`docs/06-branch-and-run-workflow.md` fixes the swap/relaunch tooling.
