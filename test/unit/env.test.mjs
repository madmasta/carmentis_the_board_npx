// M1 unit coverage for the config loader (not a parity case).

import { describe, it, expect, afterEach } from 'vitest';
import { bool, get, int, list } from '../../src/config/env.js';
import { DEFAULTS } from '../../src/config/defaults.js';
import { clearKeys, restore, setKeys } from '../helpers/env.mjs';

describe('env loader', () => {
  afterEach(restore);

  it('reads a string key, falling back to the shipped default', () => {
    clearKeys(['SESSION_NAME']);
    expect(get('SESSION_NAME')).toBe(DEFAULTS.SESSION_NAME);
    setKeys({ SESSION_NAME: 'custom_session' });
    expect(get('SESSION_NAME')).toBe('custom_session');
  });

  it('treats an empty environment value as unset, like PHP getenv()', () => {
    setKeys({ APP_NAME: '' });
    expect(get('APP_NAME', 'fallback')).toBe(DEFAULTS.APP_NAME);
  });

  it('parses ints with a fallback for junk', () => {
    setKeys({ LOGIN_MAX_ATTEMPTS: '9' });
    expect(int('LOGIN_MAX_ATTEMPTS', 5)).toBe(9);
    setKeys({ LOGIN_MAX_ATTEMPTS: 'nope' });
    expect(int('LOGIN_MAX_ATTEMPTS', 5)).toBe(5);
  });

  it('parses booleans the PHP way', () => {
    for (const truthy of ['1', 'true', 'TRUE', 'yes', 'on']) {
      setKeys({ APP_DEBUG: truthy });
      expect(bool('APP_DEBUG', false)).toBe(true);
    }
    for (const falsy of ['0', 'false', 'no', 'off', '']) {
      setKeys({ APP_DEBUG: falsy });
      expect(bool('APP_DEBUG', true)).toBe(false);
    }
  });

  it('splits comma lists, trims and drops empties', () => {
    setKeys({ ADMIN_EMAILS: 'a@x.example, b@y.example,,' });
    expect(list('ADMIN_EMAILS')).toEqual(['a@x.example', 'b@y.example']);
    setKeys({ ADMIN_EMAILS: '   ' });
    expect(list('ADMIN_EMAILS')).toEqual([]);
  });
});
