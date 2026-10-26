#!/usr/bin/env node
// Gate for one vulnerability branch (docs/04 section 6).
//
//   npm run verify:branch              # on a vuln/* checkout, or with THEBOARD_VULN=<slug>
//
// Four steps, in order: reset the database, run the baseline suite with exactly the
// declared controls' cases taken out, run the inert probe gate (docs/04 §8) on its own
// terms, and run this branch's exploit test. The baseline suite staying green is what
// proves the branch is "the app minus one defense" rather than "a broken app"; the
// exploit test passing is what proves the defense is actually gone; the inert gate is a
// secondary differential that no branch may skip by declaring a control; and the audit
// case inside controls.test.mjs fails if the sheet declares a control still enforced.

import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { declaredControls, sheetPath, skipPatternFor, vulnSlug } from '../test/helpers/declared.mjs';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const node = process.execPath;
const vitest = join(root, 'node_modules', 'vitest', 'vitest.mjs');

const slug = vulnSlug();

if (slug === null) {
  console.error('verify:branch needs a branch. Check out a vuln/* branch, or set THEBOARD_VULN=<slug>.');
  console.error('On main the gate is `npm run verify:all`.');
  process.exit(2);
}

const sheet = sheetPath(slug);
if (!existsSync(sheet)) {
  console.error(`No sheet for '${slug}': expected ${sheet}`);
  console.error('docs/05-vuln-catalog.md lists the slugs; a branch without a sheet has nothing to verify.');
  process.exit(2);
}

const exploit = join(root, 'test', 'vulns', `${slug}.test.mjs`);
if (!existsSync(exploit)) {
  console.error(`No exploit test for '${slug}': expected ${exploit}`);
  console.error('docs/06 makes the exploit test the first thing written on a branch — it fails on main, then passes here.');
  process.exit(2);
}

/**
 * What this branch's sheet says about the inert probe gate (docs/04 §8). The sheet is
 * the authority — a branch that renders stored markup live breaks the gate, one that
 * cannot reach it must not — and a sheet with no expectation is a spec gap, not
 * something to guess at.
 */
function inertGateExpectation() {
  const text = readFileSync(sheet, 'utf8');
  const line = /Inert probe gate \(docs\/04 §8\): (broken|stays green) on this branch\./.exec(text);
  if (line === null) {
    console.error(`${sheet} names no inert-gate expectation (docs/04 §8).`);
    console.error('Add one line to Must-not-break invariants: "broken on this branch" or "stays green on this branch".');
    process.exit(2);
  }
  return line[1] === 'broken';
}

const declared = declaredControls(slug);
const pattern = skipPatternFor(declared);

console.log(`branch:      vuln/${slug}`);
console.log(`sheet:       ${sheetPath(slug)}`);
console.log(`declared:    ${declared.length > 0 ? declared.join(' ') : '(none — the sheet declares no control away)'}`);
console.log(`exploit:     test/vulns/${slug}.test.mjs`);
console.log(`database:    ${process.env.DB_NAME ?? '(from .env)'}`);
console.log('');

function run(label, command, args, { expectFail = false } = {}) {
  console.log(`--- ${label}`);
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', env: process.env });
  if (result.error) {
    console.error(`${label}: could not run: ${result.error.message}`);
    return 1;
  }
  if (result.status !== 0) {
    if (!expectFail) {
      console.log(`--- ${label}: FAILED`);
      return 1;
    }
    // docs/04 §8: this branch is one of the branches the spec says must break the
    // inert probe, so a failure here is the expected differential.
    console.log(`--- ${label}: failed as the spec requires for this branch`);
    return 0;
  }
  if (expectFail) {
    console.log(`--- ${label}: PASSED, but docs/04 §8 says this branch must break it`);
    return 1;
  }
  console.log(`--- ${label}: ok`);
  return 0;
}

let failures = 0;

// 1. The branch's own database, freshly reset and seeded.
failures += run('db:reset', node, [join(root, 'scripts', 'reset.mjs'), '--force']);

const inertGate = 'test/security/baseline-inert.test.mjs';

// 2. The baseline suite, minus exactly the declared controls' cases. The inert probe
// gate is held out of this run and judged on its own terms in step 3.
const baselineArgs = [vitest, 'run', 'test/unit', 'test/integration', 'test/security', '--exclude', inertGate, '--maxWorkers', '4'];
if (pattern !== null) baselineArgs.push('--testNamePattern', pattern);
failures += run(`baseline suite (${declared.length} declared control(s) excluded)`, node, baselineArgs);

// 3. The inert probe gate (docs/04 §8). It is deliberately not a proof case of any
// control, so no branch may skip it by declaring one: it runs here, and the spec names
// the branches that must break it. Which ones is read from the spec, not hardcoded, so
// the list cannot drift out of date without a spec edit.
const inertMustFail = inertGateExpectation();
failures += run(
  `inert probe gate (${inertMustFail ? 'this branch must break it' : 'must stay green on this branch'})`,
  node,
  [vitest, 'run', inertGate, '--maxWorkers', '2'],
  { expectFail: inertMustFail },
);

// 4. This branch's exploit test — the differential oracle from the sheet.
failures += run(`exploit test for ${slug}`, node, [vitest, 'run', `test/vulns/${slug}.test.mjs`]);

console.log('');
if (failures > 0) {
  console.error(`verify:branch vuln/${slug}: FAIL (${failures} step(s) failed)`);
  process.exit(1);
}
console.log(`verify:branch vuln/${slug}: PASS`);
