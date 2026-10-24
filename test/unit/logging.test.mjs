// C-INFO-3 — logs are structured and inert (docs/03).
//
// One record per line, whatever the input tried to do, and no credential, hash,
// OTP or session id in the request log. The throttle bypass record is the one
// record `docs/02` B6 pins verbatim, and it names the account on purpose — it is
// asserted separately so a branch that removes the throttle still sees it change.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { truncateAll } from '../helpers/db.mjs';
import { clearKeys, restore, setKeys } from '../helpers/env.mjs';
import { agent, postForm } from '../helpers/http.mjs';
import { makeUser } from '../helpers/users.mjs';
import { clearForTests, errorStack, log, logPath, sanitize, security } from '../../src/lib/log.js';

const LOG_FILE = 'var/log/app-logging-proof.log';

function lines() {
  try {
    return readFileSync(logPath(), 'utf8').split('\n').filter((line) => line !== '');
  } catch {
    return [];
  }
}

beforeEach(() => {
  setKeys({ APP_LOG: LOG_FILE });
  clearForTests();
});

afterEach(() => {
  restore();
});

describe('c-info-3 log discipline', () => {
  it('c-info-3 a value with newlines stays on one record', () => {
    const line = log('info', 'GET /x', 'title=one\ntwo\r\nthree');

    expect(line.split('\n')).toHaveLength(1);
    expect(line).toContain('one two three');
    expect(lines()).toHaveLength(1);
  });

  it('c-info-3 a hostile value cannot forge a second record', () => {
    log('info', 'request', 'evil\n[2026-01-01T00:00:00.000Z] error forged record');

    const all = lines();
    expect(all).toHaveLength(1);
    expect(all[0]).not.toMatch(/\n/);
    expect(all[0]).toContain('error forged record'); // inert text, not a record
  });

  it('c-info-3 long values are truncated, not dropped', () => {
    const short = sanitize('x'.repeat(50), 20);
    expect(short).toBe(`${'x'.repeat(20)}…`);

    const boundary = sanitize('y'.repeat(400));
    expect(boundary).toHaveLength(400);
    expect(sanitize('z'.repeat(401)).length).toBeLessThanOrEqual(402);
  });

  it('c-info-3 a stack trace is written frame by frame, never to a response', () => {
    errorStack(new Error('first line\nsecond line'));

    const all = lines();
    expect(all.length).toBeGreaterThanOrEqual(2);
    for (const line of all) {
      expect(line).toMatch(/^\[[^\]]+\] stack\s/);
      expect(line).not.toMatch(/\n/);
    }
  });

  it('c-info-3 the request log carries no credential, hash, OTP or session id', async () => {
    await truncateAll();
    clearForTests();
    await makeUser('logging-user', 'logging-user@test.example', 'CorrectHorse12');

    const http = await agent();
    await postForm(http, '/login', { email: 'logging-user@test.example', password: 'wrong-password' }, '/login');
    // The record is written on the server side after the response is flushed, so
    // the client can resolve first; give the loop a turn before reading.
    await new Promise((resolve) => setTimeout(resolve, 50));

    const all = lines();
    expect(all.length).toBeGreaterThan(0);

    const joined = all.join('\n');
    expect(joined).not.toContain('wrong-password');
    expect(joined).not.toContain('CorrectHorse12');
    expect(joined).not.toContain('$2y$');
    expect(joined).not.toMatch(/[0-9a-f]{32}/); // no session id
    expect(joined).not.toContain('logging-user@test.example'); // the request logger names uid, not address
    expect(joined).toMatch(/POST \/login -> 303/);
  });

  it('c-info-3 the security prefix is a single line and is the only guard banner', () => {
    const record = security('login throttle BYPASSED', 'email=a@b ip=1.2.3.4 failures=0/5');

    expect(record).toMatch(/^\[[^\]]+\] security \[SECURITY\] login throttle BYPASSED email=a@b ip=1\.2\.3\.4 failures=0\/5$/);
    expect(lines()).toHaveLength(1);
  });

  it('c-info-3 an unwritable log path is never a 500', () => {
    setKeys({ APP_LOG: '/proc/definitely-not-writable/app.log' });
    expect(() => log('info', 'must not throw')).not.toThrow();
    clearKeys(['APP_LOG']);
  });
});
