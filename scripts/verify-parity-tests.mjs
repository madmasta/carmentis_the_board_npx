#!/usr/bin/env node
// Test-parity gate (docs/04 section 5).
//
// Every case name in docs/parity/test-inventory.md must exist as a Vitest case
// in the mapped Node file, under its Node name. A case that goes missing — a
// rename, a dropped assertion, a whole file that stops being run — fails the
// gate, because the 1:1 diff is what makes the port reviewable.
//
// Extra Node cases are allowed only when they are something the PHP target
// cannot have:
//   * a control-proof case, named with a control slug from docs/03
//     (e.g. `c-sql-1 rejects an interpolated where fragment`);
//   * a file on the extra-file allowlist below (M0-M1 plumbing the PHP target
//     does not need) or under test/security/ and test/vulns/, which docs/03 and
//     docs/04 define as gates rather than ports.
//
// Nothing may be skipped on `main`: a skipped case is a missing case.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root } from '../src/db/admin.js';

const INVENTORY = join(root(), 'docs', 'parity', 'test-inventory.md');
const SECURITY_DOC = join(root(), 'docs', '03-security-baseline.md');
const TEST_DIRS = ['test/unit', 'test/integration', 'test/security', 'test/vulns'];

/** Files that are not ports of a PHP test file (M0-M1 plumbing). */
const EXTRA_FILE_ALLOWLIST = new Set([
  'test/unit/scaffold.test.mjs',
  'test/unit/env-loader.test.mjs',
  'test/unit/router.test.mjs',
  'test/unit/headers.test.mjs',
  'test/unit/csrf.test.mjs',
  'test/integration/pipeline.test.mjs',
  // M6: asserts the seed fixture invariants of docs/02 section 6; the PHP target
  // has no equivalent test file.
  'test/integration/fixture-invariants.test.mjs',
]);

const SECTION_RE = /^## (\S+) → `([^`]+)`/;
const CASE_RE = /^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|/;
const IT_RE = /\b(?:it|test)\s*\(\s*(['"`])((?:[^'"`\\]|\\.)*)\1/g;
const SKIP_RE = /(?:^|\s)(?:it|test|describe)\.(?:skip|skipIf|only)\b|^\s*x(?:it|describe)\b/m;

function parseInventory(text) {
  const sections = [];
  let current = null;

  for (const line of text.split('\n')) {
    const section = SECTION_RE.exec(line);
    if (section !== null) {
      current = { phpFile: section[1], nodeFile: section[2], cases: [] };
      sections.push(current);
      continue;
    }
    if (current === null) continue;
    const row = CASE_RE.exec(line);
    if (row !== null && row[1] !== 'PHP case') current.cases.push({ php: row[1], node: row[2] });
  }

  return sections;
}

function caseNames(source) {
  const names = [];
  let match;
  IT_RE.lastIndex = 0;
  while ((match = IT_RE.exec(source)) !== null) names.push(match[2]);
  return names;
}

/** The control ids docs/03 defines, lowercased, to recognise proof-case names. */
function controlSlugs() {
  const text = existsSync(SECURITY_DOC) ? readFileSync(SECURITY_DOC, 'utf8') : '';
  return [...text.matchAll(/\bC-([A-Z]+)-(\d+)\b/g)].map((m) => `c-${m[1].toLowerCase()}-${m[2]}`);
}

function listTestFiles() {
  const files = [];
  for (const dir of TEST_DIRS) {
    const absolute = join(root(), dir);
    if (!existsSync(absolute)) continue;
    for (const name of readdirSync(absolute)) {
      if (name.endsWith('.test.mjs')) files.push(`${dir}/${name}`);
    }
  }
  return files.sort();
}

const sections = parseInventory(existsSync(INVENTORY) ? readFileSync(INVENTORY, 'utf8') : '');
if (sections.length === 0) {
  console.error(`no sections parsed from ${INVENTORY}`);
  process.exit(1);
}

// Files docs/03 names as a control's *Proof* file are gates, not ports: they are
// allowed to hold cases the PHP target has no equivalent of.
const GATE_FILE_RE = /`(test\/[a-z0-9/_-]+\.test\.mjs)/g;

function specNamedTestFiles() {
  const text = existsSync(SECURITY_DOC) ? readFileSync(SECURITY_DOC, 'utf8') : '';
  return new Set([...text.matchAll(GATE_FILE_RE)].map((m) => m[1]));
}

const specFiles = specNamedTestFiles();
const slugs = controlSlugs();
const problems = [];
let expected = 0;
let found = 0;
const extraFiles = [];

for (const section of sections) {
  const path = join(root(), section.nodeFile);
  expected += section.cases.length;

  if (!existsSync(path)) {
    problems.push(`${section.nodeFile}: file missing (${section.phpFile})`);
    continue;
  }

  const source = readFileSync(path, 'utf8');
  if (SKIP_RE.test(source)) problems.push(`${section.nodeFile}: contains a skipped or only-marked case`);

  const names = caseNames(source);
  const seen = new Set(names);
  for (const testCase of section.cases) {
    if (seen.has(testCase.node)) {
      found += 1;
    } else if (testCase.node !== testCase.php && seen.has(testCase.php)) {
      problems.push(`${section.nodeFile}: case is named "${testCase.php}", inventory says "${testCase.node}"`);
    } else {
      problems.push(`${section.nodeFile}: missing case "${testCase.node}" (PHP ${section.phpFile}::${testCase.php})`);
    }
  }

  for (const name of new Set(names)) {
    if (section.cases.some((c) => c.node === name)) continue;
    if (!slugs.some((slug) => name.toLowerCase().includes(slug))) {
      problems.push(`${section.nodeFile}: case "${name}" is not in the PHP inventory and is not a control proof`);
    }
  }
}

const mapped = new Set(sections.map((s) => s.nodeFile));
for (const file of listTestFiles()) {
  if (mapped.has(file)) continue;
  const allowed =
    EXTRA_FILE_ALLOWLIST.has(file) ||
    specFiles.has(file) ||
    file.startsWith('test/security/') ||
    file.startsWith('test/vulns/');
  if (!allowed) {
    problems.push(`${file}: not mapped to a PHP test file and not on the extra-file allowlist`);
    continue;
  }
  extraFiles.push(file);
  if (SKIP_RE.test(readFileSync(join(root(), file), 'utf8'))) {
    problems.push(`${file}: contains a skipped or only-marked case`);
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`FAIL  ${problem}`);
  console.error(`\n${problems.length} problem(s); ${found}/${expected} PHP cases present.`);
  process.exit(1);
}

console.log(`ok  test parity: ${found}/${expected} PHP cases across ${sections.length} files; ${extraFiles.length} extra file(s) allowed.`);
