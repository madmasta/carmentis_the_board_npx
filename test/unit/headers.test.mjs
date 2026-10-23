// M1 unit coverage for the header set (docs/03 C-HDR-1..3 proof cases).

import { describe, it, expect } from 'vitest';
import {
  UnsafeHeaderValue,
  applySecurityHeaders,
  assertSafeHeader,
  safeRedirectLocation,
  setHeader,
} from '../../src/http/headers.js';
import { CSP_STRING, STATIC_HEADERS } from '../../src/security/headers-policy.js';

function fakeRes() {
  const headers = new Map();
  return {
    headers,
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
  };
}

describe('security headers', () => {
  it('applies the full baseline set', () => {
    const res = fakeRes();
    applySecurityHeaders(res, { https: false });
    for (const [name] of STATIC_HEADERS) {
      expect(res.headers.has(name.toLowerCase()), `missing ${name}`).toBe(true);
    }
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('referrer-policy')).toBe('same-origin');
    expect(res.headers.get('x-permitted-cross-domain-policies')).toBe('none');
    expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    expect(res.headers.get('content-security-policy')).toBe(CSP_STRING);
    expect(res.headers.has('strict-transport-security')).toBe(false);
  });

  it('adds HSTS only over https', () => {
    const res = fakeRes();
    applySecurityHeaders(res, { https: true });
    expect(res.headers.get('strict-transport-security')).toBe('max-age=31536000; includeSubDomains');
  });

  it('rejects CR and LF in a header value', () => {
    expect(() => assertSafeHeader('X-Test', 'ok\r\nX-Injected: 1')).toThrow(UnsafeHeaderValue);
    expect(() => assertSafeHeader('X-Test', 'line\nbreak')).toThrow(UnsafeHeaderValue);
    expect(() => assertSafeHeader('X-Test', 'nul\u0000')).toThrow(UnsafeHeaderValue);
  });

  it('rejects a header name that could split the response', () => {
    expect(() => assertSafeHeader('X-Test\r\nX-Evil', 'v')).toThrow(UnsafeHeaderValue);
    expect(() => assertSafeHeader('', 'v')).toThrow(UnsafeHeaderValue);
  });

  it('cors-closed: no CORS header can ever be emitted', () => {
    const res = fakeRes();
    expect(() => setHeader(res, 'Access-Control-Allow-Origin', '*')).toThrow(UnsafeHeaderValue);
    expect(() => setHeader(res, 'Access-Control-Allow-Credentials', 'true')).toThrow(UnsafeHeaderValue);
    expect(res.headers.size).toBe(0);
    applySecurityHeaders(res, { https: false });
    for (const name of res.headers.keys()) {
      expect(name.startsWith('access-control-')).toBe(false);
    }
  });
});

describe('redirect targets', () => {
  it('accepts an internal path', () => {
    expect(safeRedirectLocation('/login')).toBe('/login');
    expect(safeRedirectLocation('/thread/7?page=2')).toBe('/thread/7?page=2');
  });

  it('rejects protocol-relative, absolute and CRLF targets', () => {
    expect(() => safeRedirectLocation('//evil.example')).toThrow(UnsafeHeaderValue);
    expect(() => safeRedirectLocation('http://evil.example')).toThrow(UnsafeHeaderValue);
    expect(() => safeRedirectLocation('/a\r\nLocation: /b')).toThrow(UnsafeHeaderValue);
    expect(() => safeRedirectLocation('')).toThrow(UnsafeHeaderValue);
  });
});
