// M1 unit coverage for CSRF tokens (not a parity case). The control proof lives
// in test/security/controls.test.mjs#c-csrf-1.

import { describe, it, expect } from 'vitest';
import { CSRF_ERROR, CSRF_FIELD, issue, rotate, verify } from '../../src/security/csrf.js';

function session(data = {}) {
  return { id: 'x', userId: null, data: { csrf_token: null, ...data } };
}

describe('csrf', () => {
  it('issues a 32-byte hex token and keeps it stable per session', () => {
    const s = session();
    const first = issue(s);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(issue(s)).toBe(first);
  });

  it('rotates to a different token', () => {
    const s = session();
    const before = issue(s);
    const after = rotate(s);
    expect(after).not.toBe(before);
    expect(verify(s, before)).toBe(false);
    expect(verify(s, after)).toBe(true);
  });

  it('rejects missing, empty and mismatched submissions', () => {
    const s = session();
    issue(s);
    expect(verify(s, null)).toBe(false);
    expect(verify(s, '')).toBe(false);
    expect(verify(s, 'short')).toBe(false);
    expect(verify(s, 'x'.repeat(64))).toBe(false);
  });

  it('never verifies against a session with no token', () => {
    expect(verify(session(), 'anything')).toBe(false);
  });

  it('exposes the field name and the exact failure copy', () => {
    expect(CSRF_FIELD).toBe('csrf_token');
    expect(CSRF_ERROR).toBe('Invalid or missing CSRF token. Go back and try again.');
  });
});
