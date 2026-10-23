// HTTP helpers for integration tests (docs/04 section 2, item 5).
//
// `loginAs` walks the real login form with a real CSRF token through a cookie
// jar, so an integration test exercises the same path a browser does — including
// the session regeneration and the cookie flags — instead of forging a session
// row behind the app's back.

import request from 'supertest';
import { createApp } from '../../src/server.js';

let app = null;

/** The app under test (one server per worker; the pool is shared). */
export function appUnderTest() {
  if (app === null) app = createApp();
  return app;
}

export function agent() {
  return request.agent(appUnderTest());
}

/** GET a page and return the csrf_token rendered for this session. */
export async function csrfToken(http, path = '/login') {
  const res = await http.get(path);
  const match = /name="csrf_token" value="([0-9a-f]+)"/.exec(res.text ?? '');
  if (match === null) {
    throw new Error(`no csrf_token found on ${path} (status ${res.status})`);
  }
  return match[1];
}

/** Session id from a response's Set-Cookie header, for tests that read the row. */
export function sessionIdFrom(res) {
  const name = process.env.SESSION_NAME ?? 'theboard_session';
  // The last Set-Cookie is what a browser jar keeps: a login response carries the
  // pre-login id (written when the request started) and the regenerated one.
  let found = null;
  for (const line of res.headers['set-cookie'] ?? []) {
    const match = new RegExp(`^${name}=([0-9a-f]{32})`).exec(String(line));
    if (match !== null) found = match[1];
  }
  return found;
}

/**
 * Log in through POST /login. Returns the response so the caller can assert on
 * the redirect; throws if the credentials did not take effect.
 */
export async function loginAs(http, email, password = 'TestPass123') {
  const token = await csrfToken(http, '/login');
  const res = await http
    .post('/login')
    .type('form')
    .send({ csrf_token: token, email, password });
  if (res.status !== 303) {
    throw new Error(`loginAs(${email}) failed with status ${res.status}`);
  }
  return res;
}

/** POST a form with a fresh CSRF token from `fromPath`. */
export async function postForm(http, path, fields, fromPath = '/login') {
  const token = await csrfToken(http, fromPath);
  return http.post(path).type('form').send({ csrf_token: token, ...fields });
}

export { request };
