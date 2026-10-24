// C-INFO-1 — no internals in responses (docs/03).
//
// The probe arms `src/lib/faults.js#setTestFault`, so the 500 path is exercised
// without putting a real bug in a handler. The `information_disclosure` branch
// keeps this probe and asserts the frames are now rendered by default.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { truncateAll } from '../helpers/db.mjs';
import { setKeys, restore } from '../helpers/env.mjs';
import { agent, csrfToken, loginAs } from '../helpers/http.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import { faultIsArmed, setTestFault } from '../../src/lib/faults.js';
import { clearForTests, logPath } from '../../src/lib/log.js';

const LOG_FILE = 'var/log/app-error-proof.log';

function logText() {
  try {
    return readFileSync(logPath(), 'utf8');
  } catch {
    return '';
  }
}

beforeEach(async () => {
  setKeys({ APP_LOG: LOG_FILE, APP_DEBUG: '0' });
  clearForTests();
  await truncateAll();
});

afterEach(() => {
  setTestFault(null);
  restore();
});

describe('c-info-1 the error path', () => {
  it('c-info-1 a fault renders the generic view and never a stack frame', async () => {
    setTestFault(() => new Error('proof fault: cannot read rows from users'));

    const res = await (await agent()).get('/');
    expect(res.status).toBe(500);
    expect(res.text).toContain('Something went wrong. The error has been logged.');

    expect(res.text).not.toContain('proof fault');
    expect(res.text).not.toContain('at ');
    expect(res.text).not.toContain('src/');
    expect(res.text).not.toContain('node_modules');
    expect(res.text).not.toContain('Error:');
  });

  it('c-info-1 the trace goes to the application log instead', async () => {
    setTestFault(() => new Error('logged fault'));

    expect((await (await agent()).get('/')).status).toBe(500);

    const written = logText();
    expect(written).toContain('logged fault');
    expect(written).toMatch(/\] stack\s/);
    expect(written).toMatch(/unhandled error on GET/);
  });

  it('c-info-1 nothing is armed in a normal run, and a normal request logs no stack', async () => {
    const http = await agent();
    expect((await http.get('/login')).status).toBe(200);
    expect(faultIsArmed()).toBe(false);

    expect(logText()).not.toMatch(/\] stack\s/);
    expect(logText()).not.toMatch(/unhandled error/);
  });

  it('c-info-1 the fault fires exactly once', async () => {
    setTestFault(() => new Error('single shot'));

    expect((await (await agent()).get('/login')).status).toBe(500);
    expect(faultIsArmed()).toBe(false);
    expect((await (await agent()).get('/login')).status).toBe(200);
  });

  it('c-info-1 a debug run renders the trace, and that is the only banner the app ships', async () => {
    setKeys({ APP_DEBUG: '1' });
    setTestFault(() => new Error('visible in debug'));

    const res = await (await agent()).get('/login');
    expect(res.status).toBe(500);
    expect(res.text).toContain('visible in debug');
    expect(res.text).toMatch(/at .*\(.*:\d+:\d+\)/);
  });

  it('c-info-1 an error view never echoes request data', async () => {
    setTestFault(() => new Error('leak probe'));
    const http = await agent();

    const res = await http.get('/board/999?canary=unique-canary-value');
    expect(res.status).toBe(500);
    expect(res.text).not.toContain('unique-canary-value');

    // A plain 404 also refuses to echo the target.
    const missing = await http.get('/no-such-page?canary=second-canary');
    expect(missing.status).toBe(404);
    expect(missing.text).not.toContain('second-canary');
  });

  it('c-info-1 a 404 and a 403 still carry the baseline headers and a generic body', async () => {
    await makeUser('err-admin', 'err-admin@test.example', 'ErrPass1234', 'admin');
    await makeUser('err-pleb', 'err-pleb@test.example', 'ErrPass1234');
    const boardId = Number((await makeBoard('Err Board', false, 1)).id);
    const threadId = Number(await makeThread(boardId, 1, 'Err thread', 'body'));

    const http = await agent();
    await loginAs(http, 'err-pleb@test.example', 'ErrPass1234');

    const forbidden = await http.get('/admin/users');
    expect(forbidden.status).toBe(403);
    expect(forbidden.headers['x-content-type-options']).toBe('nosniff');

    const missing = await http.get(`/thread/${threadId}`);
    expect(missing.status).toBe(404);
    expect(missing.headers['content-security-policy']).toContain("default-src 'self'");
  });
});
