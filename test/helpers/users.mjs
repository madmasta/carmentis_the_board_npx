// Fixture users for integration tests — the Node equivalent of
// IntegrationTestCase::makeUser (docs/04 section 2). Rows are inserted directly,
// bypassing the validators, exactly as the PHP helper does.

import { randomBytes } from 'node:crypto';
import { query, insert } from './db.mjs';
import { hash } from '../../src/security/passwords.js';

export const DEFAULT_PASSWORD = 'CorrectHorse1';

// A bcrypt hash is expensive to produce and identical for a fixed password, so
// one hash per distinct password is reused across fixtures. The app still verifies
// the plaintext against it.
const hashCache = new Map();

async function hashOf(password) {
  if (!hashCache.has(password)) hashCache.set(password, await hash(password));
  return hashCache.get(password);
}

export async function makeUser(
  username = 'alice',
  email = null,
  password = DEFAULT_PASSWORD,
  role = 'user',
) {
  const address = (email ?? `${String(username).toLowerCase()}@test.example`).toLowerCase();
  await insert('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', [
    username,
    address,
    await hashOf(password),
    role,
  ]);
  const rows = await query('SELECT * FROM users WHERE email = ?', [address]);
  if (rows.length === 0) throw new Error(`user not created: ${address}`);
  return rows[0];
}

export async function makeBoard(name = 'General', defaultAccess = false, createdBy = null) {
  const { insertId } = await insert('INSERT INTO boards (name, description, default_access, created_by) VALUES (?, ?, ?, ?)', [
    name,
    'A board',
    defaultAccess ? 1 : 0,
    createdBy,
  ]);
  const rows = await query('SELECT * FROM boards WHERE id = ?', [insertId]);
  return rows[0];
}

/** A fake controller context for calls that would otherwise need a request. */
export function fakeContext(sessionData = {}) {
  const headers = new Map();
  return {
    req: { https: false, socket: { remoteAddress: '127.0.0.1' }, fields: {}, query: {} },
    res: {
      headers,
      headersSent: false,
      statusCode: 200,
      setHeader(name, value) {
        headers.set(String(name).toLowerCase(), value);
      },
    },
    session: {
      id: randomBytes(16).toString('hex'),
      userId: null,
      data: {
        auth_user_id: null,
        mfa_pending_user_id: null,
        csrf_token: null,
        flash: [],
        intended_path: null,
        mfa_last_sent: 0,
        auth_created_at: null,
        ...sessionData,
      },
      isNew: true,
    },
    user: null,
  };
}
