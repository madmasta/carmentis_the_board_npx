// Port of tests/Unit/EnvTest.php — the .env loader (docs/01 section 3).
//
// The PHP case names and assertions are kept 1:1; the extra loader semantics that
// the PHP class does not expose the same way (int junk, bool spellings, list
// trimming against the shipped defaults) live in env-loader.test.mjs.

import { rmSync, writeFileSync } from "node:fs";
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { get, int, list, resetForTests } from '../../src/config/env.js';
import { clearKeys, restore, setKeys } from '../helpers/env.mjs';

function tempEnvFile(contents) {
  const path = join(tmpdir(), `theboard-env-${Date.now()}-${Math.random().toString(16).slice(2)}.env`);
  writeFileSync(path, contents, 'utf8');
  return path;
}

describe('env loader', () => {
  afterEach(() => {
    resetForTests(null);
    restore();
  });

  it('testParsesKeysValuesAndComments', () => {
    const path = tempEnvFile(
      [
        '# comment line',
        'APP_NAME=My Board',
        '',
        '# quoted values',
        'TITLE="Hello World"',
        "SINGLE='quoted'",
        'EMPTY=',
        'NUMBER=42',
      ].join('\n'),
    );

    // PHP had no shipped default for APP_NAME; the port keeps DEFAULTS out of the
    // way of this assertion by clearing the ambient value first.
    clearKeys(['APP_NAME']);
    resetForTests(path);
    try {
      expect(get('APP_NAME')).toBe('My Board');
      expect(get('SINGLE')).toBe('quoted');
      expect(get('MISSING_KEY_THAT_DOES_NOT_EXIST')).toBeNull();
      expect(get('MISSING_KEY_THAT_DOES_NOT_EXIST', '')).toBe('');
      expect(int('MISSING_KEY_THAT_DOES_NOT_EXIST', 42)).toBe(42);
      expect(int('NUMBER', 0)).toBe(42);
    } finally {
      rmSync(path, { force: true });
    }
  });

  it('testRealEnvironmentVariableWins', () => {
    const path = tempEnvFile('OVERRIDE_ME=file-value\n');

    setKeys({ OVERRIDE_ME: 'env-value' });
    resetForTests(path);
    try {
      expect(get('OVERRIDE_ME')).toBe('env-value');
    } finally {
      restore();
      rmSync(path, { force: true });
    }
  });

  it('testListParsesCommaSeparatedValues', () => {
    const path = tempEnvFile('EMAILS=a@b.com, c@d.com ,, e@f.com\n');

    clearKeys(['EMAILS']);
    resetForTests(path);
    try {
      expect(list('EMAILS')).toEqual(['a@b.com', 'c@d.com', 'e@f.com']);
    } finally {
      rmSync(path, { force: true });
    }
  });
});
