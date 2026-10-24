// C-DEP-1 — dependencies are pinned, few, and clean (docs/03).
//
// The dependency set is a spec document: docs/01 section 7 lists it, and
// `vulnerable_components` is the branch that adds a known-bad one. A set that
// drifts from the document, or an advisory on `main`, fails here.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { root } from '../../src/db/admin.js';

const ARCHITECTURE_DOC = join(root(), 'docs', '01-architecture.md');

function packageJson() {
  return JSON.parse(readFileSync(join(root(), 'package.json'), 'utf8'));
}

/** The names docs/01 section 7 allows, split into runtime and dev. */
function specDependencies() {
  const doc = readFileSync(ARCHITECTURE_DOC, 'utf8');
  const section = doc.split(/^## 7\. Dependencies/m)[1]?.split(/^## 8\./m)[0] ?? '';

  const namesIn = (label) => {
    const block = section.split(new RegExp(`${label}:`))[1]?.split(/\n\n/)[0] ?? '';
    // The sentence “…`@vitest/coverage-v8` is not used” names a package that must
    // be absent, so a name is only allowed when the words after it do not say so.
    const names = [];
    for (const match of block.matchAll(/`([^`]+)`([^`]*)/g)) {
      if (match[1].includes(' ')) continue;
      if (/is not used/.test(match[2].slice(0, 60))) continue;
      names.push(match[1]);
    }
    return names;
  };

  return { runtime: namesIn('Runtime'), dev: namesIn('Dev') };
}

describe('c-dep-1 the dependency set', () => {
  it('c-dep-1 the manifest matches the list in docs/01 section 7 exactly', () => {
    const pkg = packageJson();
    const allowed = specDependencies();

    expect(Object.keys(pkg.dependencies ?? {}).sort()).toEqual([...allowed.runtime].sort());
    expect(Object.keys(pkg.devDependencies ?? {}).sort()).toEqual([...allowed.dev].sort());

    // Banned by name as well as by absence.
    for (const banned of ['express', 'fastify', 'koa', 'body-parser', 'multer', 'cookie-parser', 'libxmljs2', ' sequelize']) {
      expect(`${Object.keys(pkg.dependencies ?? {}).join(',')} ${Object.keys(pkg.devDependencies ?? {}).join(',')}`, banned).not.toContain(banned.trim());
    }
  });

  it('c-dep-1 the lockfile is committed and resolves every dependency', () => {
    const lockPath = join(root(), 'package-lock.json');
    expect(existsSync(lockPath), 'package-lock.json must be committed').toBe(true);

    const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
    expect(typeof lock.lockfileVersion).toBe('number');
    expect(lock.lockfileVersion).toBeGreaterThanOrEqual(2);

    const pkg = packageJson();
    const nodeModules = lock.packages ?? {};
    for (const name of Object.keys(pkg.dependencies ?? {})) {
      const entry = nodeModules[`node_modules/${name}`];
      expect(entry, `${name} is not resolved in the lockfile`).toBeDefined();
      expect(entry.version).toMatch(/^\d+\.\d+\.\d+/);
    }
  });

  it('c-dep-1 npm audit reports no advisory for what is installed', () => {
    // Node refuses to spawn a `.cmd` shim without a shell, so run npm through its
    // own CLI script when that sits next to the running node, and only fall back
    // to a shell when it does not. The arguments are constants either way.
    const npmCli = join(process.execPath, '..', 'node_modules', 'npm', 'bin', 'npm-cli.js');
    const invocation = existsSync(npmCli)
      ? { command: process.execPath, args: [npmCli, 'audit', '--json'], options: {} }
      : { command: process.platform === 'win32' ? 'npm.cmd' : 'npm', args: ['audit', '--json'], options: { shell: true } };

    let report;
    try {
      report = execFileSync(invocation.command, invocation.args, {
        ...invocation.options,
        cwd: root(),
        encoding: 'utf8',
        timeout: 120_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      // `npm audit` exits non-zero when it finds advisories, and that output is
      // the report. A failure without JSON is a harness problem, and saying so
      // beats letting an offline run pass quietly.
      report = typeof error.stdout === 'string' ? error.stdout : '';
      if (report === '') {
        expect.fail(`npm audit could not run: ${String(error.stderr ?? error.message).slice(0, 300)}`);
      }
    }

    const parsed = JSON.parse(report);
    const advisories = parsed?.metadata?.vulnerabilities ?? {};
    const total = Object.entries(advisories).reduce((sum, [key, value]) => (key === 'total' ? sum + value : sum), 0);

    expect(total, JSON.stringify(advisories)).toBe(0);
  });
});
