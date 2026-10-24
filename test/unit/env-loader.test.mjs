// Infrastructure coverage for the config loader (M1, not a PHP parity case).
//
// PHP reads ints with a cast and booleans with one in_array() call in Env, and
// the app never had shipped defaults for numeric keys. The Node port adds
// config/defaults.js and defensive parsing, so the extra semantics get their own
// file instead of being smuggled into the ported cases.

import { describe, expect, it } from 'vitest';
import { bool, get, int, list } from '../../src/config/env.js';
import { DEFAULTS } from '../../src/config/defaults.js';
import { clearKeys, setKeys } from '../helpers/env.mjs';

describe('config loader', () => {
  it('testStringKeyFallsBackToShippedDefault', () => {
    clearKeys(['SESSION_NAME']);
    expect(get('SESSION_NAME')).toBe(DEFAULTS.SESSION_NAME);
    setKeys({ SESSION_NAME: 'custom_session' });
    expect(get('SESSION_NAME')).toBe('custom_session');
  });

  it('testEmptyEnvironmentValueIsUnset', () => {
    // PHP: getenv() returns '' for an empty assignment and Env treats it as unset.
    setKeys({ APP_NAME: '' });
    expect(get('APP_NAME', 'fallback')).toBe(DEFAULTS.APP_NAME);
  });

  it('testIntParsesWithFallbackForJunk', () => {
    setKeys({ LOGIN_MAX_ATTEMPTS: '9' });
    expect(int('LOGIN_MAX_ATTEMPTS', 5)).toBe(9);
    setKeys({ LOGIN_MAX_ATTEMPTS: 'nope' });
    expect(int('LOGIN_MAX_ATTEMPTS', 5)).toBe(5);
  });

  it('testBoolAcceptsThePhpTruthySpellings', () => {
    for (const truthy of ['1', 'true', 'TRUE', 'yes', 'on']) {
      setKeys({ APP_DEBUG: truthy });
      expect(bool('APP_DEBUG', false)).toBe(true);
    }
    for (const falsy of ['0', 'false', 'no', 'off', '']) {
      setKeys({ APP_DEBUG: falsy });
      expect(bool('APP_DEBUG', true)).toBe(false);
    }
  });

  it('testListSplitsTrimsAndDropsEmpties', () => {
    setKeys({ ADMIN_EMAILS: 'a@x.example, b@y.example,,' });
    expect(list('ADMIN_EMAILS')).toEqual(['a@x.example', 'b@y.example']);
    setKeys({ ADMIN_EMAILS: '   ' });
    expect(list('ADMIN_EMAILS')).toEqual([]);
  });
});
