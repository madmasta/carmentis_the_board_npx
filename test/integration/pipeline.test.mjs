// M1 pipeline coverage: headers on a 200 and a 404, the 500 path with and
// without APP_DEBUG, and the fault seam (docs/03 C-HDR-1, C-INFO-1).

import { afterEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { appUnderTest } from '../helpers/http.mjs';
import { CSP_STRING } from '../../src/security/headers-policy.js';
import { setTestFault } from '../../src/lib/faults.js';
import { clearKeys, restore, setKeys } from '../helpers/env.mjs';

const app = await appUnderTest();

afterEach(() => {
  setTestFault(null);
  restore();
});

describe('pipeline', () => {
  it('answers /health with json and the full header set', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body).toEqual({ ok: true });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('same-origin');
    expect(res.headers['content-security-policy']).toBe(CSP_STRING);
  });

  it('serves the two allowlisted static files', async () => {
    const css = await request(app).get('/assets/style.css');
    expect(css.status).toBe(200);
    expect(css.headers['content-type']).toMatch(/text\/css/);
    const js = await request(app).get('/assets/app.js');
    expect(js.status).toBe(200);
    expect(js.headers['content-type']).toMatch(/javascript/);
  });

  it('has no static directory handler', async () => {
    for (const path of ['/assets/', '/assets', '/assets/style.css/', '/.git/config', '/../schema.sql']) {
      const res = await request(app).get(path);
      expect(res.status, path).toBe(404);
    }
  });

  it('renders the pinned 404 copy', async () => {
    const res = await request(app).get('/nope');
    expect(res.status).toBe(404);
    expect(res.text).toContain('The page you requested does not exist.');
    expect(res.headers['content-security-policy']).toBe(CSP_STRING);
  });

  it('hides internals on a 500 unless APP_DEBUG=1', async () => {
    setTestFault(() => new Error('probe-fault'));
    const res = await request(app).get('/');
    expect(res.status).toBe(500);
    expect(res.text).toContain('Something went wrong. The error has been logged.');
    expect(res.text).not.toContain('probe-fault');
    expect(res.text).not.toContain('at ');
  });

  it('c-info-1: shows a stack only when APP_DEBUG=1', async () => {
    setKeys({ APP_DEBUG: '1' });
    setTestFault(() => new Error('probe-fault-visible'));
    const res = await request(app).get('/');
    expect(res.status).toBe(500);
    expect(res.text).toContain('probe-fault-visible');
  });

  it('c-cookie-1 refuses a host that was not configured', async () => {
    const res = await request(app).get('/health').set('Host', 'evil.example');
    expect(res.status).toBe(400);
    expect(res.text).toContain('Unknown host.');
  });

  it('rejects an oversized body before any handler runs', async () => {
    const res = await request(app)
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`a=${'x'.repeat(5 * 1024 * 1024)}`);
    expect([400, 413]).toContain(res.status);
  });
});
