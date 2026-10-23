const REPO = 'C:/Users/madma/projects/Targets/carmentis_the_board_npx'

const common = [
  'Read-only task: do NOT modify, create or delete any file. Do not spawn subagents,',
  'worktrees or shell fan-out; read the files yourself.',
  'Hard budget: answer within 12 minutes, under 600 words. No preamble, no tool tour.',
  '',
].join('\n')

const sqli = [
  common,
  `Repository: ${REPO}. A reviewer previously blocked docs/vulns/sqli.md on six points:`,
  'multipleStatements default, an 10-vs-11 column union, an inert boolean probe, an undefined directory sink shape, an invented empty-state string, and a control-skip mismatch.',
  'Re-read docs/vulns/sqli.md, docs/03-security-baseline.md (C-SQL-1, C-SQL-2, C-DIR-1), docs/04-testing-and-verification.md (sections 2, 6, 9) and docs/02-feature-parity.md (sections 6-7).',
  'For each of the six points say FIXED or NOT FIXED with one sentence of evidence. Then list any NEW blocker that would stop you writing the branch and its test. If there is no new blocker, say "no new blocker".',
].join('\n')

const misconfig = [
  common,
  `Repository: ${REPO}. A reviewer previously blocked docs/vulns/security_misconfig.md:`,
  '(a) the new /server-info route was not registered in src/routes.js, (b) the test env pins APP_DEBUG/LOGIN_THROTTLE_DISABLED so the branch could never show the bad defaults, (c) an undeclared HOST key, (d) /thread/999999 answers 404 so the verbose-500 probe never fires, (e) CWE labels disagreed with the catalog.',
  'Re-read docs/vulns/security_misconfig.md, docs/01-architecture.md (section 5), docs/03-security-baseline.md (C-INFO-1, C-INFO-2, C-AUTH-3), docs/04-testing-and-verification.md (sections 2 and 9), docs/07-port-deviations.md and docs/05-vuln-catalog.md row 22.',
  'For each of (a)-(e) say FIXED or NOT FIXED with one sentence of evidence, then list any NEW blocker, or "no new blocker". Then give a merge verdict for this sheet: BLOCK or OK.',
].join('\n')

const results = await runs.all([
  { key: 'sqli-recheck', agent: 'delegate', task: sqli, isolation: 'none', async: false },
  { key: 'misconfig-recheck', agent: 'delegate', task: misconfig, isolation: 'none', async: false },
])

return results
  .map((r, i) => `## ${i === 0 ? 'sqli-recheck' : 'misconfig-recheck'}\n\n${r && r.output ? r.output : JSON.stringify(r)}`)
  .join('\n\n')
