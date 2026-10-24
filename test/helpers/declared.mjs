// The branch contract as code (docs/04 section 6).
//
// A `vuln/*` branch declares, in its own sheet under "Baseline control removed",
// exactly which controls its diff takes away. `npm run verify:branch` exports
// THEBOARD_VULN=<slug>, and everything downstream reads that one fact from here:
// which cases are expected to go red, and which sheet to hold to account if they
// do not.
//
// Skipping is case-level. The rule in docs/03 is that a control's proof cases are
// identified by the slug in their name — `c-sql-1 rejects an interpolated where
// fragment` — so declaring `C-SQL-1` removes those cases and leaves every other
// case in the same file running.

import { existsSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..');

/** The slug of the branch under verification, or null on main. */
export function vulnSlug() {
  const fromEnv = (process.env.THEBOARD_VULN ?? '').trim();
  if (fromEnv !== '') return fromEnv;

  // Fall back to the checked-out branch, so a stray `npm test` on a branch
  // behaves like the gate rather than like main.
  try {
    const ref = execSync('git rev-parse --abbrev-ref HEAD', { cwd: repoRoot, encoding: 'utf8' }).trim();
    return ref.startsWith('vuln/') ? ref.slice('vuln/'.length) : null;
  } catch {
    return null;
  }
}

export function sheetPath(slug = vulnSlug()) {
  return slug === null ? null : join(repoRoot, 'docs', 'vulns', `${slug}.md`);
}

/**
 * Control IDs the branch declares removed: every `C-XXX-n` in the first column of
 * a table inside the sheet's "Baseline control removed" section. Side-effect rows
 * live in the same section, so they are picked up too — that is the point.
 */
export function declaredControls(slug = vulnSlug()) {
  const path = sheetPath(slug);
  if (path === null || !existsSync(path)) return [];

  const text = readFileSync(path, 'utf8');
  const from = text.indexOf('## Baseline control removed');
  if (from === -1) return [];
  const rest = text.slice(from + '## Baseline control removed'.length);
  const end = rest.search(/\n## /);
  const section = end === -1 ? rest : rest.slice(0, end);

  const ids = new Set();
  for (const match of section.matchAll(/^\|\s*`(C-[A-Z]+-\d+)`/gm)) ids.add(match[1]);
  return [...ids];
}

const declared = new Set(declaredControls());

/** True when the case's control is declared away by the branch under test. */
export function isDeclared(controlId) {
  return declared.has(controlId.toUpperCase());
}

/** For `it.skipIf(skipIfDeclared('C-SQL-2'))(…)` in the files docs/03 maps to a control. */
export function skipIfDeclared(controlId) {
  return isDeclared(controlId);
}

/** A slug is what a test name carries; a control ID is what a sheet declares. */
export function slugOf(controlId) {
  return controlId.toLowerCase();
}

/**
 * A negative `--testNamePattern` covering the declared slugs, used by the branch
 * harness to drop exactly those cases across every file (docs/04 section 6).
 * Returns null on main, where no case may be skipped.
 */
export function skipPatternFor(controls = declaredControls()) {
  if (controls.length === 0) return null;
  const slugs = controls.map((id) => id.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return `^(?!.*(${slugs.join('|')})(?![0-9a-z-])).*`;
}
