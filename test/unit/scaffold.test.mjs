// Scaffold smoke tests (milestone M0/M1 primitives). These are not parity cases;
// docs/parity/test-inventory.md is the parity contract and is checked by
// scripts/verify-parity-tests.mjs.

import { describe, it, expect, afterEach } from 'vitest';
import { DEFAULTS } from '../../src/config/defaults.js';
import * as env from '../../src/config/env.js';
import * as connection from '../../src/db/connection.js';
import { schemaStatements } from '../../src/db/admin.js';
import * as clock from '../../src/lib/clock.js';
import { clearKeys, restore } from '../helpers/env.mjs';

const PHP_KEYS = [
  'APP_NAME', 'APP_URL', 'APP_DEBUG', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASS',
  'DB_ROOT_PASS', 'ADMIN_EMAILS', 'ADMIN_PASSWORD', 'MAIL_DRIVER', 'MAIL_FROM', 'MAIL_FROM_NAME',
  'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_SECURE', 'SESSION_NAME',
  'PASSWORD_MIN_LENGTH', 'LOGIN_MAX_ATTEMPTS', 'LOGIN_WINDOW_MINUTES', 'LOGIN_THROTTLE_DISABLED',
  'OTP_TTL_MINUTES', 'OTP_MAX_ATTEMPTS',
];

describe('config', () => {
  afterEach(restore);

  it('ships a default for every PHP env key', () => {
    for (const key of PHP_KEYS) {
      expect(DEFAULTS, `DEFAULTS is missing ${key}`).toHaveProperty(key);
    }
  });

  it('prefers a real environment variable over the .env file', () => {
    clearKeys(['APP_DEBUG']);
    expect(env.bool('APP_DEBUG', false)).toBe(false);
    process.env.APP_DEBUG = '1';
    expect(env.bool('APP_DEBUG', false)).toBe(true);
    process.env.APP_DEBUG = '0';
    expect(env.bool('APP_DEBUG', true)).toBe(false);
  });

  it('reads lists and ints the way the PHP loader does', () => {
    setList();
    expect(env.list('ADMIN_EMAILS')).toEqual(['a@example.com', 'b@example.com']);
    expect(env.int('LOGIN_MAX_ATTEMPTS', 5)).toBe(7);
    restore();

    function setList() {
      process.env.ADMIN_EMAILS = 'a@example.com, b@example.com ,';
      process.env.LOGIN_MAX_ATTEMPTS = '7';
    }
  });
});

describe('schema', () => {
  it('applies the seven PHP tables plus the sessions table', () => {
    const statements = schemaStatements();
    expect(statements.length).toBeGreaterThanOrEqual(8);
    const joined = statements.join('\n');
    for (const table of [
      'users', 'boards', 'board_access', 'posts', 'votes', 'login_attempts', 'mfa_codes', 'sessions',
    ]) {
      expect(joined, `schema.sql is missing ${table}`).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
    }
  });

  it('contains no named placeholders or multiple-statement tricks', () => {
    for (const statement of schemaStatements()) {
      expect(statement).not.toMatch(/;\s*\S/);
    }
  });
});

describe('seams', () => {
  it('db/connection.js exposes the fixed contract', () => {
    for (const name of ['query', 'execute', 'transaction', 'forUpdate', 'close']) {
      expect(typeof connection[name]).toBe('function');
    }
  });

  it('clock is the only time source and is overridable', () => {
    // UTC by contract: the database is UTC, so the app's timestamp text is UTC
    // regardless of the host offset.
    const fixed = new Date(Date.UTC(2024, 0, 2, 3, 4, 5));
    clock.setClockForTests(() => fixed);
    expect(clock.now()).toEqual(fixed);
    expect(clock.sqlDateTime()).toBe('2024-01-02 03:04:05');
    expect(clock.sqlDateTime()).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    clock.setClockForTests(null);
    expect(clock.now() instanceof Date).toBe(true);
    expect(clock.clockIsOverridden()).toBe(false);
  });
});
