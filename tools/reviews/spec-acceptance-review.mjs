const REPO = 'C:/Users/madma/projects/Targets/carmentis_the_board_npx'
const PHP = 'C:/Users/madma/projects/Targets/carmentis_the_board'

const dryRun = (slug) => [
  'You are a fresh build agent. Read-only task: do NOT modify, create or delete any file.',
  '',
  'Read completely:',
  `- ${REPO}/docs/vulns/${slug}.md`,
  `- ${REPO}/docs/templates/vuln-sheet-template.md`,
  `- ${REPO}/docs/03-security-baseline.md`,
  `- ${REPO}/docs/02-feature-parity.md (section 7 hook table)`,
  `- ${REPO}/docs/04-testing-and-verification.md (sections 6-7)`,
  '',
  'Then answer, without asking any question:',
  '1. IMPLEMENTATION SKETCH: the exact diff you would write for the vulnerable branch (file by file, with code).',
  '2. TEST SKETCH: the Vitest plus supertest exploit test you would write (concrete assertions).',
  '3. OPEN QUESTIONS: numbered list of every decision the sheet left for you to invent. Be strict: if you had to invent anything, list it. Write "none" only if truly nothing was invented.',
  '4. FIDELITY CHECK: does the sheet claim about failing on main hold, given the controls in docs/03? yes/no plus one sentence.',
  '',
  'Keep the whole answer under 700 words. A clean bill of health that relies on invented details is a failure.',
].join('\n')

const parity = [
  'You are a parity reviewer. Read-only: do NOT modify any file.',
  `Node port SPEC: ${REPO}`,
  `PHP reference implementation (read-only truth): ${PHP}`,
  '',
  'Verify the spec against the PHP truth by reading both:',
  `- docs/parity/route-inventory.md against ${PHP}/public/index.php (count, methods, paths, guards, csrf, handlers)`,
  '- docs/02-feature-parity.md sections 1-6 against src/*.php and src/Http/*.php: error semantics (404 vs 403 vs redirect), validator rules and exact message strings, session/MFA/throttle rules, seed fixture invariants against bin/seed-test-data.php',
  '- docs/parity/test-inventory.md against tests; docs/parity/env-inventory.md against .env.example',
  '- docs/01-architecture.md PHP-to-Node module map completeness',
  '',
  'Output: (1) CONFIRMED correct, briefly; (2) DISCREPANCIES with file and line evidence from the PHP repo; (3) places where the spec is silent and a builder would have to invent. Under 700 words. Do not invent PHP behaviour.',
].join('\n')

const security = [
  'You are a security-fidelity reviewer. Read-only: do NOT modify any file.',
  `Repository: ${REPO}`,
  'Read docs/05-vuln-catalog.md, docs/03-security-baseline.md, docs/01-architecture.md, and all 35 sheets in docs/vulns/.',
  '',
  'For every sheet judge three things and report ONLY the problems:',
  '1. Is the vulnerability genuinely reachable and provable in a frameworkless Node app (node:http plus mysql2 plus Nunjucks) given what docs/01 and docs/03 say exists?',
  '2. Is the CWE/class label right, and is the branch distinguishable from other branches sharing its route or control?',
  '3. Is the differential oracle concrete, executable, and guaranteed to fail on main for the stated reason?',
  '',
  'Output: a list of ONLY the sheets with a problem (slug, problem, one-line fix), then 5 bullets naming the strongest sheets. Under 800 words. Name files and routes concretely.',
].join('\n')

const results = await runs.all([
  { key: 'dryrun-sqli', agent: 'delegate', task: dryRun('sqli'), isolation: 'none', async: false },
  { key: 'dryrun-file-upload', agent: 'delegate', task: dryRun('file_upload'), isolation: 'none', async: false },
  { key: 'parity-review', agent: 'reviewer', task: parity, isolation: 'none', async: false },
  { key: 'security-review', agent: 'reviewer', task: security, isolation: 'none', async: false },
])

return results.map((r, i) => `## ${['dryrun-sqli', 'dryrun-file-upload', 'parity-review', 'security-review'][i]}\n\n${r && r.output ? r.output : JSON.stringify(r)}`).join('\n\n')
