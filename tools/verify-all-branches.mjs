#!/usr/bin/env node
// The M8 matrix: verify all 35 vulnerability branches (docs/04 section 7).
//
//   node tools/verify-all-branches.mjs [--only slug[,slug]] [--keep] [--jobs N]
//
// For each slug in docs/05-vuln-catalog.md:
//   1. worktree ../wt-<slug> from vuln/<slug>, with its own port and its own
//      database name so nothing collides (docs/06);
//   2. `npm run verify:branch` inside it — baseline suite plus exploit test;
//   3. the differential: that branch's exploit test copied into a clean `main`
//      worktree, where it must FAIL;
//   4. topology: exactly one commit off main, touching only the sheet's files;
//   5. one matrix row.
// Non-zero exit unless every row is PASS.

import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const repoName = root.split(/[\\/]/).pop();
const node = process.execPath;

const argv = process.argv.slice(2);
const only = (() => {
  const i = argv.indexOf('--only');
  return i === -1 ? null : new Set(argv[i + 1].split(',').map((s) => s.trim()).filter(Boolean));
})();
const keepWorktrees = argv.includes('--keep');

// --- inputs from the spec -----------------------------------------------------

function catalogSlugs() {
  const text = readFileSync(join(root, 'docs', '05-vuln-catalog.md'), 'utf8');
  const slugs = [];
  // The catalog's branch column reads `vuln/<slug>`; the slug is what filenames, branch
  // names and database names are built from.
  for (const match of text.matchAll(/^\|\s*(\d+)\s*\|\s*`(?:vuln\/)?([a-z0-9_]+)`/gm)) slugs.push(match[2]);
  return slugs;
}

function sheetSection(slug, heading) {
  const text = readFileSync(join(root, 'docs', 'vulns', `${slug}.md`), 'utf8');
  const from = text.indexOf(`## ${heading}`);
  if (from === -1) return '';
  const rest = text.slice(from + `## ${heading}`.length);
  const end = rest.search(/\n## /);
  return end === -1 ? rest : rest.slice(0, end);
}

function sheetDeclaredControls(slug) {
  return [...sheetSection(slug, 'Baseline control removed').matchAll(/^\|\s*`(C-[A-Z]+-\d+)`/gm)].map((m) => m[1]);
}

/** Repository-relative paths the sheet's "Minimal diff" names. */
function sheetAllowedFiles(slug) {
  const files = new Set();
  for (const match of sheetSection(slug, 'Minimal diff').matchAll(/`([A-Za-z0-9_.\-/]+\.[A-Za-z0-9]+)`/g)) {
    files.add(match[1].replace(/^\.\//, ''));
  }
  return files;
}

const slugs = catalogSlugs().filter((slug) => only === null || only.has(slug));
if (slugs.length === 0) {
  console.error('No slugs to verify. docs/05-vuln-catalog.md must carry a numbered table of `slug` cells.');
  process.exit(2);
}

// --- git and worktree plumbing ------------------------------------------------

function git(args, cwd = root) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  return { status: result.status ?? 1, out: (result.stdout ?? '').trim(), err: (result.stderr ?? '').trim() };
}

function worktreeFor(slug) {
  const path = join(root, '..', `wt-${slug}`);
  if (existsSync(join(path, 'package.json'))) return path;
  const added = git(['worktree', 'add', join('..', `wt-${slug}`), `vuln/${slug}`]);
  if (added.status !== 0) {
    console.error(`worktree for ${slug}: ${added.err || added.out}`);
    return null;
  }
  return path;
}

/**
 * `.env` is gitignored, so a fresh worktree has none — and the app refuses to start
 * without it (docs/06: configuration lives in .env, never in the repo). Copy it once,
 * and only when absent, so a worktree pointed at its own database can be arranged by
 * hand afterwards.
 */
function provideEnv(worktree) {
  const target = join(worktree, '.env');
  if (existsSync(target)) return true;
  const source = join(root, '.env');
  if (!existsSync(source)) {
    console.error(`${worktree} has no .env and ${root} has none to copy — the app cannot start there.`);
    return false;
  }
  copyFileSync(source, target);
  return true;
}

/**
 * A worktree with no node_modules cannot run the suite, and 35 npm installs is
 * the slowest possible way to share one lockfile. Symlink the checked-out
 * dependency tree instead; on platforms that refuse the symlink, install.
 */
function linkNodeModules(worktree) {
  const target = join(worktree, 'node_modules');
  if (existsSync(target)) return true;
  try {
    symlinkSync(join(root, 'node_modules'), target, process.platform === 'win32' ? 'junction' : 'dir');
    return true;
  } catch {
    const installed = spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['ci', '--prefer-offline'], {
      cwd: worktree,
      stdio: 'pipe',
      env: process.env,
    });
    return installed.status === 0;
  }
}

function topology(slug) {
  // Measured from the merge-base, not from main's tip: main keeps moving while
  // branches are being built, and `main..branch` would then report main's own new
  // commits and file changes as the branch's.
  const base = git(['merge-base', 'main', `vuln/${slug}`]).out;
  if (base === '') return { commits: 0, changed: [], extra: [] };
  const commits = git(['rev-list', '--count', `${base}..vuln/${slug}`]);
  const files = git(['diff', '--name-only', `${base}..vuln/${slug}`]);
  const changed = files.out === '' ? [] : files.out.split(/\r?\n/);
  const allowed = sheetAllowedFiles(slug);
  // The branch's own exploit test is part of the branch by contract (docs/06),
  // and the sheet names it in its "Differential oracle" section, not its diff.
  const extra = changed.filter((f) => !allowed.has(f) && f !== `test/vulns/${slug}.test.mjs`);
  return {
    commits: Number(commits.out || '0'),
    changed,
    extra,
  };
}

// --- the runs -----------------------------------------------------------------

function runVerifyBranch(worktree, slug, index) {
  const env = {
    ...process.env,
    THEBOARD_VULN: slug,
    DB_NAME: `theboard_node_${slug}`.slice(0, 40),
    PORT: String(8090 + index),
  };
  const result = spawnSync(node, ['scripts/verify-branch.mjs'], { cwd: worktree, env, stdio: 'pipe', encoding: 'utf8' });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  return { passed: result.status === 0, output };
}

/**
 * The differential. The branch's exploit test runs against clean `main`; a test
 * that passes there describes a vulnerability main already has, and the row is
 * NO-DIFF. An empty collection is not a failure — it is a broken probe, so the
 * output has to mention a test result before it counts.
 */
function differential(probeWorktree, slug) {
  const source = join(root, '..', `wt-${slug}`, 'test', 'vulns', `${slug}.test.mjs`);
  const target = join(probeWorktree, 'test', 'vulns', `probe-${slug}.test.mjs`);
  if (!existsSync(source)) return { ok: false, verdict: 'NO-TEST', output: `${source} missing` };

  mkdirSync(join(probeWorktree, 'test', 'vulns'), { recursive: true });
  copyFileSync(source, target);
  try {
    const result = spawnSync(node, ['node_modules/vitest/vitest.mjs', 'run', `test/vulns/probe-${slug}.test.mjs`, '--maxWorkers', '2'], {
      cwd: probeWorktree,
      // A database of its own, so the differential can't be influenced by whatever the
      // branch run left behind (the test database is rebuilt either way — this is about
      // making the evidence legible in the logs).
      env: { ...process.env, THEBOARD_VULN: '', DB_NAME: 'theboard_node_main_probe'.slice(0, 40) },
      stdio: 'pipe',
      encoding: 'utf8',
    });
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    // Vitest's summary line is `Tests  6 failed | 2 passed (8)`; requiring it (or the
    // per-file line) is what separates "the probe failed" from "the probe never ran".
    const collected = /(?:^|\n)\s*(?:Tests|Test Files)\s+\d/m.test(output);
    if (!collected) return { ok: false, verdict: 'BROKEN-PROBE', output };
    if (result.status === 0) return { ok: false, verdict: 'NO-DIFF', output };
    return { ok: true, verdict: 'FAILS ON MAIN', output };
  } finally {
    rmSync(target, { force: true });
  }
}

// --- main ----------------------------------------------------------------------

const slugsToRun = slugs;
console.log(`verifying ${slugsToRun.length} branch(es); repo ${repoName}\n`);

const mainProbe = join(root, '..', 'wt-main-diff-probe');
if (!existsSync(join(mainProbe, 'package.json'))) {
  const added = git(['worktree', 'add', '--detach', join('..', 'wt-main-diff-probe'), 'main']);
  if (added.status !== 0) {
    console.error(`cannot create the clean-main probe worktree: ${added.err || added.out}`);
    process.exit(2);
  }
}
// The differential is only a differential against *current* main, so the probe
// worktree is re-pointed at the base branch's tip on every run rather than trusted
// to be where it was left.
if (existsSync(mainProbe)) {
  const refreshed = git(['-C', mainProbe, 'checkout', '--force', '--detach', 'main']);
  if (refreshed.status !== 0) {
    console.error(`cannot re-point the clean-main probe worktree at main: ${refreshed.err || refreshed.out}`);
    process.exit(2);
  }
}
if (!provideEnv(mainProbe) || !linkNodeModules(mainProbe)) {
  console.error('the clean-main probe worktree is not runnable (see the line above).');
  process.exit(2);
}

const rows = [];
let failures = 0;

for (const [index, slug] of slugsToRun.entries()) {
  const worktree = worktreeFor(slug);
  if (worktree === null) {
    rows.push({ slug, baseline: 'NO-BRANCH', exploit: '-', diff: '-', files: '-', verdict: 'NO-BRANCH' });
    failures += 1;
    continue;
  }
  if (!provideEnv(worktree) || !linkNodeModules(worktree)) {
    rows.push({ slug, baseline: 'NO-DEPS', exploit: '-', diff: '-', files: '-', verdict: 'NO-DEPS' });
    failures += 1;
    continue;
  }

  const run = runVerifyBranch(worktree, slug, index);
  const topo = topology(slug);
  const probe = differential(mainProbe, slug);

  const baselineOk = run.passed;
  const diffOk = topo.commits === 1 && topo.extra.length === 0;
  const verdict = !baselineOk ? 'FAIL' : !probe.ok ? probe.verdict : !diffOk ? 'TOPOLOGY' : 'PASS';
  if (verdict !== 'PASS') failures += 1;

  rows.push({
    slug,
    baseline: baselineOk ? 'PASS' : 'FAIL',
    exploit: existsSync(join(worktree, 'test', 'vulns', `${slug}.test.mjs`)) ? 'present' : 'missing',
    diff: `${topo.commits} commit(s)`,
    files: diffOk ? 'ok' : topo.extra.length > 0 ? `extra: ${topo.extra.join(' ')}` : `${topo.commits} commits`,
    verdict,
    declared: sheetDeclaredControls(slug).join(' '),
  });

  if (verdict !== 'PASS') {
    const detail = run.output.split('\n').filter((line) => /FAIL|failed|Error|expected/.test(line)).slice(-12).join('\n');
    console.error(`\n[${slug}] ${verdict}\n${detail}\n${'-'.repeat(60)}`);
    if (probe.output) {
      console.error(`[differential ${probe.verdict}]\n${probe.output.split('\n').filter((l) => /FAIL|failed|passed|Error/.test(l)).slice(-6).join('\n')}`);
    }
  }
}

const columns = [
  ['slug', (r) => r.slug],
  ['baseline', (r) => r.baseline],
  ['exploit test', (r) => r.exploit],
  ['diff vs main', (r) => r.diff],
  ['files ok', (r) => r.files],
  ['verdict', (r) => r.verdict],
];

console.log('');
for (const row of rows) {
  console.log(columns.map(([label, get]) => `${label}=${get(row)}`).join('  '));
}
console.log(`\n${rows.length - failures}/${rows.length} rows PASS`);

/**
 * Drop a worktree's node_modules link before the worktree itself goes away.
 *
 * On Windows the link is a junction, and `git worktree remove --force` walks the
 * directory tree — which follows the junction and deletes the shared install it
 * points at. That is not a hypothetical: it emptied this repo's node_modules once.
 * `rmSync` on the link itself unlinks the reparse point without touching the target.
 */
function unlinkNodeModules(worktree) {
  try {
    rmSync(join(worktree, 'node_modules'), { force: true });
  } catch {
    // A worktree whose link is already gone needs nothing before removal.
  }
}

if (!keepWorktrees) {
  for (const slug of slugsToRun) {
    const path = join(root, '..', `wt-${slug}`);
    if (existsSync(path) && statSync(path).isDirectory()) {
      unlinkNodeModules(path);
      git(['worktree', 'remove', '--force', path]);
    }
  }
  if (existsSync(mainProbe)) {
    unlinkNodeModules(mainProbe);
    git(['worktree', 'remove', '--force', mainProbe]);
  }
  git(['worktree', 'prune']);
} else {
  console.log('worktrees kept (--keep)');
}

if (failures > 0) {
  console.error(`\nverify:branches: ${failures} row(s) not PASS`);
  process.exit(1);
}
console.log('\nverify:branches: all rows PASS');
