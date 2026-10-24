// A request context that is not attached to a socket.
//
// PHP's Auth::attemptLogin() reached $_SESSION globally, so AdminFlowTest could
// call it straight from a test. The port keeps authentication in the request
// context (docs/01 section 5), so a test that exercises the function without an
// HTTP round trip builds this stand-in: a real session object, written to the
// real `sessions` table, plus a response stub that only records headers.

const HEADER_NAME = /^[\w-]+$/;

export function fakeRes() {
  const sent = new Map();
  return {
    headersSent: false,
    statusCode: 200,
    setHeader(name, value) {
      if (!HEADER_NAME.test(name)) throw new Error(`invalid header name: ${name}`);
      const previous = sent.get(String(name).toLowerCase());
      if (String(name).toLowerCase() === 'set-cookie' && previous !== undefined) {
        sent.set('set-cookie', [...(Array.isArray(previous) ? previous : [previous]), value]);
      } else {
        sent.set(String(name).toLowerCase(), value);
      }
    },
    getHeader(name) {
      return sent.get(String(name).toLowerCase());
    },
    end() {
      this.headersSent = true;
    },
  };
}

export function fakeReq(overrides = {}) {
  return {
    method: 'POST',
    path: '/',
    https: false,
    socket: { remoteAddress: '127.0.0.1' },
    headers: { host: process.env.APP_URL ? new URL(process.env.APP_URL).host : 'localhost' },
    fields: Object.create(null),
    query: Object.create(null),
    cookies: Object.create(null),
    ...overrides,
  };
}

/** A session in the same shape src/session/store.js produces. */
export function fakeSession(id = '0'.repeat(32)) {
  return {
    id,
    userId: null,
    isNew: true,
    data: {
      auth_user_id: null,
      mfa_pending_user_id: null,
      csrf_token: null,
      flash: [],
      intended_path: null,
      mfa_last_sent: 0,
      auth_created_at: null,
    },
  };
}

export function fakeCtx(overrides = {}) {
  const session = overrides.session ?? fakeSession();
  return {
    req: overrides.req ?? fakeReq(),
    res: overrides.res ?? fakeRes(),
    session,
    user: overrides.user ?? null,
  };
}
