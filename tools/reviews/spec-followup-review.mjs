const REPO = 'C:/Users/madma/projects/Targets/carmentis_the_board_npx'

const common = [
  'Read-only task: do NOT modify, create or delete any file. Do not spawn subagents,',
  'worktrees, or shell-based fan-out; read the files yourself with your own tools.',
  'Budget: finish within 15 minutes and answer in under 700 words.',
  '',
].join('\n')

const resqli = [
  common,
  'You are a fresh build agent re-checking a specification sheet that was just revised.',
  `Read completely: ${REPO}/docs/vulns/sqli.md, ${REPO}/docs/03-security-baseline.md,`,
  `${REPO}/docs/04-testing-and-verification.md (sections 2, 6, 9), ${REPO}/docs/01-architecture.md (section 5),`,
  `${REPO}/docs/02-feature-parity.md (sections 6 and 7).`,
  '',
  'Answer:',
  '1. Could you write the branch diff and the exploit test from the sheet alone? Give the concrete test assertions you would write.',
  '2. OPEN QUESTIONS: numbered list of anything you still have to invent. Write "none" if there is nothing. Be strict but only list real blockers.',
  '3. Does the sheet\'s control-skip declaration match docs/03 proof files and docs/04 section 6?',
  '4. Does every oracle step now hold on the branch AND fail on main? Call out any step that would still not work.',
].join('\n')

const subset = [
  common,
  `Repository: ${REPO}`,
  'Read docs/05-vuln-catalog.md, docs/03-security-baseline.md, and these 8 sheets in docs/vulns/:',
  'path_traversal, security_misconfig, xss_stored, session_management, jwt_flaws, race_condition, idor, mass_assignment.',
  '',
  'For each sheet report ONLY problems, in this format: slug | problem | one-line fix. Judge:',
  '1. Reachability and provability in a frameworkless node:http + mysql2 + Nunjucks app as docs/01 and docs/03 describe it.',
  '2. Correct CWE label and clear separation from sibling branches that share its route or control (check the catalog for siblings).',
  '3. Whether the oracle is concrete and would fail on main for the stated reason, and whether any control the diff also breaks is undeclared (docs/04 section 6 requires side-effect controls to be declared).',
  '',
  'Then 3 bullets naming the strongest sheets. Name files, routes and control IDs concretely.',
].join('\n')

const results = await runs.all([
  { key: 'resql-check', agent: 'delegate', task: resqli, isolation: 'none', async: false },
  { key: 'subset-security', agent: 'reviewer', task: subset, isolation: 'none', async: false },
])

return results
  .map((r, i) => `## ${i === 0 ? 'resql-check' : 'subset-security'}\n\n${r && r.output ? r.output : JSON.stringify(r)}`)
  .join('\n\n')
