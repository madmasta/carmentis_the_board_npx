#!/usr/bin/env node
// Spec self-verification gates for this repository (docs/04 section 4).
//
//   node tools/check-spec.mjs             run every gate
//   node tools/check-spec.mjs --hooks     hook-feature consistency only
//
// Prints one line per violation and exits non-zero when there is any.

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(HERE, '..');
const DOCS = join(ROOT, 'docs');
const VULNS = join(DOCS, 'vulns');
const PHP_REPO = process.env.PHP_REPO ?? join(ROOT, '..', 'carmentis_the_board');

const argv = process.argv.slice(2);
const HOOKS_ONLY = argv.includes('--hooks');

const read = (p) => readFileSync(p, 'utf8').replace(/\r\n/g, '\n');
const failures = [];
const fail = (rule, message) => failures.push(`${rule}  ${message}`);

const catalog = read(join(DOCS, '05-vuln-catalog.md'));
const baseline = read(join(DOCS, '03-security-baseline.md'));
const parity = read(join(DOCS, '02-feature-parity.md'));
const routeInventory = existsSync(join(DOCS, 'parity', 'route-inventory.md'))
  ? read(join(DOCS, 'parity', 'route-inventory.md'))
  : '';

const SECTIONS = [
  'Class and CWE',
  'Intent',
  'Affected surface',
  'Sink',
  'Baseline control removed',
  'Minimal diff',
  'Payload sketch',
  'Differential oracle',
  'Must-not-break invariants',
  'Fidelity to the PHP branch',
  'Carmentis evidence',
  'Definition of done',
];

// ------------------------------------------------- catalog and sheet sets ----

const catalogRows = [...catalog.matchAll(/^\|\s*(\d+)\s*\|\s*`vuln\/([a-z0-9_]+)`\s*\|/gm)].map(
  (m) => ({ n: Number(m[1]), slug: m[2], row: m[0] }),
);

const sheetFiles = existsSync(VULNS)
  ? readdirSync(VULNS)
      .filter((f) => f.endsWith('.md'))
      .map((f) => f.slice(0, -3))
  : [];

const catalogSlugs = catalogRows.map((r) => r.slug);

// R1 one-to-one between catalog and sheets
for (const slug of catalogSlugs) {
  if (!sheetFiles.includes(slug)) fail('R1', `catalog row vuln/${slug} has no docs/vulns/${slug}.md`);
}
for (const slug of sheetFiles) {
  if (!catalogSlugs.includes(slug)) fail('R1', `docs/vulns/${slug}.md is missing from the catalog`);
}
if (new Set(catalogSlugs).size !== catalogSlugs.length) fail('R1', 'catalog has duplicate branch rows');

// R8 counts
if (sheetFiles.length !== 35) fail('R8', `expected 35 sheets, found ${sheetFiles.length}`);
if (catalogRows.length !== 35) fail('R8', `expected 35 catalog rows, found ${catalogRows.length}`);

// R2 parity with the PHP reference target's branch refs
const phpRefsDir = join(PHP_REPO, '.git', 'refs', 'heads', 'vuln');
if (existsSync(phpRefsDir)) {
  const phpSlugs = readdirSync(phpRefsDir)
    .map((f) => f.replace(/-/g, '_'))
    .sort();
  const ours = [...sheetFiles].sort();
  for (const slug of phpSlugs) if (!ours.includes(slug)) fail('R2', `PHP branch vuln/${slug} has no Node sheet`);
  for (const slug of ours) if (!phpSlugs.includes(slug)) fail('R2', `Node sheet ${slug} has no PHP branch`);
} else {
  console.log(`note      R2 skipped: no PHP refs at ${phpRefsDir} (override with PHP_REPO)`);
}

// ------------------------------------------------------------- control ids ----

const controlIds = new Set([...baseline.matchAll(/^\*\*(C-[A-Z]+-\d+)\b/gm)].map((m) => m[1]));
if (controlIds.size < 25) fail('R4', `control register looks truncated: ${controlIds.size} IDs found`);

// ------------------------------------------------------------- each sheet ----

for (const slug of sheetFiles) {
  const path = join(VULNS, `${slug}.md`);
  const text = read(path);

  // front matter consistency
  const branchLine = /- Branch: `vuln\/([a-z0-9_]+)`/.exec(text);
  if (!branchLine) fail('R3', `${slug}: missing "- Branch: \`vuln/<slug>\`" front matter`);
  else if (branchLine[1] !== slug) fail('R3', `${slug}: Branch front matter says vuln/${branchLine[1]}`);

  const testLine = /- Test file: `(test\/vulns\/([a-z0-9_]+)\.test\.mjs)`/.exec(text);
  if (!testLine) fail('R6', `${slug}: missing "- Test file:" front matter`);
  else if (testLine[2] !== slug) fail('R6', `${slug}: Test file says ${testLine[2]}`);

  const rowLine = /- Catalog row: (\d+)/.exec(text);
  if (!rowLine) fail('R1', `${slug}: missing "- Catalog row:" front matter`);
  else {
    const row = catalogRows.find((r) => r.n === Number(rowLine[1]));
    if (!row) fail('R1', `${slug}: catalog row ${rowLine[1]} does not exist`);
    else if (row.slug !== slug) fail('R1', `${slug}: catalog row ${rowLine[1]} is ${row.slug}`);
  }

  // R3 sections present, ordered, non-empty
  const heads = [...text.matchAll(/^## (.+)$/gm)].map((m) => m[1].trim());
  for (const section of SECTIONS) {
    if (!heads.includes(section)) fail('R3', `${slug}: missing section "${section}"`);
  }
  const ordered = SECTIONS.every((s, i) => heads.indexOf(s) === i);
  if (!ordered && heads.length >= SECTIONS.length) {
    fail('R3', `${slug}: sections are out of template order`);
  }
  for (let i = 0; i < heads.length; i++) {
    const start = text.indexOf(`## ${heads[i]}`);
    const end = i + 1 < heads.length ? text.indexOf(`## ${heads[i + 1]}`) : text.length;
    const body = text.slice(start + `## ${heads[i]}`.length, end).trim();
    if (body.length < 40) fail('R3', `${slug}: section "${heads[i]}" is empty or too short (${body.length} chars)`);
  }

  // R4 controls referenced must exist in the register
  const ctlSection = /^## Baseline control removed\n([\s\S]*?)\n## /m.exec(text);
  if (!ctlSection) {
    fail('R4', `${slug}: no Baseline control removed section to parse`);
  } else {
    const ids = [...ctlSection[1].matchAll(/\b(C-[A-Z]+-\d+)\b/g)].map((m) => m[1]);
    if (ids.length === 0) fail('R4', `${slug}: no control ID referenced`);
    for (const id of new Set(ids)) {
      if (!controlIds.has(id)) fail('R4', `${slug}: control ${id} is not in docs/03-security-baseline.md`);
    }
  }

  // R5 the sheet's route must exist in the generated route inventory or the hook table
  const surface = /^## Affected surface\n([\s\S]*?)\n## /m.exec(text);
  if (surface) {
    const minimalDiff = /^## Minimal diff\n([\s\S]*?)\n## /m.exec(text)?.[1] ?? '';
    const architecture = existsSync(join(DOCS, '01-architecture.md')) ? read(join(DOCS, '01-architecture.md')) : '';
    const routes = [...surface[1].matchAll(/`(GET|POST|PUT|DELETE|ANY) (\/[^\s`|]*)`/g)].map((m) => m[2]);
    if (routes.length === 0) fail('R5', `${slug}: Affected surface names no route`);
    for (const route of routes) {
      const pathOnly = route.split('?')[0];
      const inRoutes = routeInventory.includes(`\`${pathOnly}\``);
      const inHooks = parity.includes(pathOnly);
      const addedByBranch = minimalDiff.includes(pathOnly);
      const documentedStatic = architecture.includes(pathOnly);
      if (!inRoutes && !inHooks && !addedByBranch && !documentedStatic) {
        fail('R5', `${slug}: route ${route} is not in the route inventory or docs/02 section 7`);
      }
    }
  } else {
    fail('R5', `${slug}: cannot parse Affected surface`);
  }

  // R6 oracle: names the test file, states the expectation on main
  const oracle = /^## Differential oracle\n([\s\S]*?)\n## /m.exec(text);
  if (!oracle) {
    fail('R6', `${slug}: cannot parse Differential oracle`);
  } else {
    if (!oracle[1].includes(`test/vulns/${slug}.test.mjs`)) {
      fail('R6', `${slug}: oracle does not name test/vulns/${slug}.test.mjs`);
    }
    if (!/On `main`/.test(oracle[1])) {
      fail('R6', `${slug}: oracle does not state what happens on main`);
    }
  }

  // payload block
  const payload = /^## Payload sketch\n([\s\S]*?)\n## /m.exec(text);
  if (!payload || !/```/.test(payload[1])) fail('R7', `${slug}: Payload sketch has no fenced request block`);
}

// ------------------------------------------------------- banned wording ----

const BANNED = [/\bTBD\b/i, /\bTODO\b/i, /\bFIXME\b/i, /\?\?\?/, /\bor similar\b/i, /\betc\./i, /\bas needed\b/i];
const walk = (dir, out = []) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (full.endsWith('templates')) continue; // quotes the anti-patterns on purpose
      walk(full, out);
    } else if (entry.name.endsWith('.md')) {
      out.push(full);
    }
  }
  return out;
};
for (const file of walk(DOCS)) {
  const rel = file.slice(ROOT.length + 1).replace(/\\/g, '/');
  const text = read(file);
  for (const re of BANNED) {
    const m = re.exec(text);
    if (m) fail('R7', `${rel}: banned placeholder wording "${m[0]}"`);
  }
}

// ------------------------------------------------------- hook features ----

const hookRoutes = [
  '/profile/avatar',
  '/avatar/:id',
  '/attachment',
  '/preview',
  '/board/:id/export.xml',
  '/board/:id/import',
  '/directory',
  '/directory/search',
  '/admin/boards/:id/snapshot.json',
  '/admin/boards/:id/restore',
  '/thread/:id/export',
  '/forgot-password',
  '/reset-password',
];
const hookControls = [
  'C-UPLOAD-1',
  'C-SSRF-1',
  'C-XML-1',
  'C-XPATH-1',
  'C-DIR-1',
  'C-DIR-2',
  'C-JSON-1',
  'C-CMD-1',
  'C-JWT-1',
  'C-SESS-1',
  'C-SESS-2',
  'C-SSTI-1',
];
let hookProblems = 0;
for (const route of hookRoutes) {
  if (!parity.includes(route)) {
    fail('HOOK', `docs/02 section 7 does not mention hook route ${route}`);
    hookProblems++;
  }
}
for (const id of hookControls) {
  if (!controlIds.has(id)) {
    fail('HOOK', `hook control ${id} is missing from docs/03`);
    hookProblems++;
  }
  if (!parity.includes(id)) {
    fail('HOOK', `docs/02 section 7 does not cite hook control ${id}`);
    hookProblems++;
  }
}

// ------------------------------------------------------------ reporting ----

const relevantFailures = HOOKS_ONLY ? failures.filter((f) => f.startsWith('HOOK')) : failures;

if (HOOKS_ONLY) {
  if (hookProblems === 0) console.log('hooks      ok: every hook route and hook control is cross-referenced');
} else if (failures.length === 0) {
  console.log(
    `spec gates ok: ${catalogRows.length} catalog rows, ${sheetFiles.length} sheets, ` +
      `${controlIds.size} controls, 0 violations`,
  );
} else {
  for (const f of failures) console.log(f);
  console.log(`\n${failures.length} spec violation(s).`);
}

process.exit(relevantFailures.length === 0 ? 0 : 1);
