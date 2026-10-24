// HTTP helpers for integration tests (docs/04 section 2, item 5).
//
// `loginAs` walks the real login form with a real CSRF token through a cookie
// jar, so an integration test exercises the same path a browser does — including
// the session regeneration and the cookie flags — instead of forging a session
// row behind the app's back.

import { createServer } from 'node:http';
import request from 'supertest';
import { createRequestHandler } from '../../src/http/server.js';
import { routes } from '../../src/routes.js';

let baseUrl = null;

/**
 * The app under test: one ephemeral server per worker, addressed by URL.
 *
 * A persistent server is deliberate. Supertest spins up its own server when it
 * is handed a listener or a Server, and it closes that server after the request
 * — a cookie-jar agent making several requests then hits a server that is no
 * longer listening. The base URL keeps every request in one jar on one server,
 * while the database pool behind it stays shared.
 */
export async function appUnderTest() {
  if (baseUrl === null) {
    const server = createServer(createRequestHandler(routes));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    // Do not hold the worker open; vitest exits when the tests finish.
    server.unref();
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  }
  return baseUrl;
}

export async function agent() {
  return request.agent(await appUnderTest());
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

/** One macrotask, so the jar and the server's post-response writes have landed. */
export async function settled() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Log in through POST /login. Returns the response so the caller can assert on
 * the redirect; throws if the credentials did not take effect.
 *
 * The trailing `settled()` is not decoration: superagent resolves the response
 * and updates its cookie jar on different turns of the loop, so a test that
 * fires its next request immediately can send the pre-login cookie and be told
 * it is anonymous. A browser never does that; a test can.
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
  await settled();
  return res;
}

/** POST a form with a fresh CSRF token from `fromPath`. */
export async function postForm(http, path, fields, fromPath = '/login') {
  const token = await csrfToken(http, fromPath);
  const res = await http.post(path).type('form').send({ csrf_token: token, ...fields });
  await settled();
  return res;
}

export { request };
