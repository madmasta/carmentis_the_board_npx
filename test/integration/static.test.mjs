// C-INFO-2 — no filesystem exposure (docs/03).
//
// The URL-reachable files are two named assets, plus the two controller routes
// (`/avatar/:id`, `/attachment?file=`) covered in test/integration/hooks.test.mjs.
// Everything else is a 404, and nothing is ever listed.

import { describe, expect, it } from 'vitest';
import { agent } from '../helpers/http.mjs';

/** Paths that must never return file contents. */
const FORBIDDEN = [
  '/schema.sql',
  '/package.json',
  '/package-lock.json',
  '/.env',
  '/.env.example',
  '/.git/config',
  '/.git/HEAD',
  '/var/log/app.log',
  '/var/uploads/anything.png',
  '/uploads/x.png',
  '/public/assets/style.css',
  '/src/server.js',
  '/templates/login.njk',
  '/assets/app.js.map',
  '/assets/style.css.map',
  '/assets',
  '/assets/',
  '/assets/app.js/',
  '/assets/../schema.sql',
  '/%2e%2e/schema.sql',
  '/..%2f..%2fschema.sql',
  '/./schema.sql',
  '/assets/%2e%2e%2f%2e%2e%2fschema.sql',
];

describe('c-info-2 the only reachable files', () => {
  it('c-info-2 the two allowlisted assets are served with fixed content types', async () => {
    const http = await agent();

    const css = await http.get('/assets/style.css');
    expect(css.status).toBe(200);
    expect(css.headers['content-type']).toBe('text/css; charset=utf-8');

    const js = await http.get('/assets/app.js');
    expect(js.status).toBe(200);
    expect(js.headers['content-type']).toBe('text/javascript; charset=utf-8');
    // The CSP that makes this external file the only script source is proved by
    // C-XSS-3 in test/security/controls.test.mjs, not here: this case is about the
    // static allowlist and the types, so it must not fail when a branch relaxes the
    // policy (that is a different control's business).
  });

  it('c-info-2 every other path is a 404 with no file contents', async () => {
    const http = await agent();

    for (const path of FORBIDDEN) {
      const res = await http.get(path);
      expect(res.status, `${path} -> ${res.status}`).toBe(404);
      expect(res.text).not.toContain('CREATE TABLE');
      expect(res.text).not.toContain('DB_PASS');
      expect(res.text).not.toContain('"dependencies"');
      expect(res.text).not.toContain('[core]');
    }
  });

  it('c-info-2 a directory is never listed', async () => {
    const http = await agent();

    for (const dir of ['/public', '/public/assets', '/src', '/test', '/var', '/templates']) {
      const res = await http.get(dir);
      expect(res.status).toBe(404);
      expect(res.text).not.toContain('<ul>');
      expect(res.text).not.toContain('Index of');
    }
  });

  it('c-info-2 the asset allowlist is GET-only', async () => {
    const http = await agent();
    const res = await http.post('/assets/app.js').type('form').send({ x: '1' });

    expect(res.status).toBe(404);
  });

  it('c-info-2 a dotfile probe cannot be answered by a route', async () => {
    const http = await agent();

    for (const path of ['/robots.txt', '/favicon.ico', '/health/../../.env', '/assets/app.js/../../.env']) {
      expect((await http.get(path)).status).toBe(404);
    }
  });
});
