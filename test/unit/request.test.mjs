// C-ASSIGN-1 and C-COOKIE-1 at the request boundary (docs/03).
//
// These are the two halves the spec pins: prototype-poisoning keys are rejected
// before anything can be assigned from them, unknown fields never reach a
// handler, and no request-supplied host is ever believed.

import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { RequestError, fieldNames, hostIsAllowed, isDangerousKey, parse, pickFields } from '../../src/http/request.js';

function requestOf({ method = 'POST', url = '/x', headers = {}, body = '' }) {
  const req = Readable.from(body === '' ? [] : [Buffer.from(body, 'utf8')]);
  req.method = method;
  req.url = url;
  req.headers = { host: 'localhost:8088', ...headers };
  req.socket = { remoteAddress: '203.0.113.7', encrypted: false };
  return req;
}

function urlencoded(fields) {
  return new URLSearchParams(fields).toString();
}

describe('c-assign-1 bodies become typed DTOs', () => {
  it('c-assign-1 the dangerous key set is rejected, not silently dropped', () => {
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      expect(isDangerousKey(key)).toBe(true);
    }
    expect(isDangerousKey('username')).toBe(false);
  });

  it('c-assign-1 a body carrying a prototype key is a 400 before any assignment', async () => {
    for (const body of ['title=hi&__proto__=1', 'title=hi&constructor=1', 'prototype=x']) {
      const req = requestOf({ body, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
      await expect(parse(req)).rejects.toBeInstanceOf(RequestError);
    }
  });

  it('c-assign-1 a query string carrying a prototype key is a 400 too', async () => {
    await expect(parse(requestOf({ method: 'GET', url: '/x?__proto__=1' }))).rejects.toBeInstanceOf(RequestError);
  });

  it('c-assign-1 bracket notation pollutes nothing: fields are a null-prototype map', async () => {
    const parsed = await parse(requestOf({ body: 'title=hi&__proto__[polluted]=1&constructor[x]=1', headers: { 'content-type': 'application/x-www-form-urlencoded' } }));

    expect(Object.getPrototypeOf(parsed.fields)).toBeNull();
    expect(parsed.fields['@__proto__[polluted]'.slice(1)]).toBe('1');
    expect({}.polluted).toBeUndefined();
    expect({}.x).toBeUndefined();
  });

  it('c-assign-1 a field allowlist picks named fields and drops the rest', async () => {
    const req = requestOf({
      body: urlencoded({ title: '  A title  ', body: 'text', role: 'admin', is_banned: '1', csrf_token: 'x' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    const parsed = await parse(req);

    const picked = pickFields(parsed, ['title', 'body']);
    expect(picked).toEqual({ title: 'A title', body: 'text' });
    // A handler asks for the names it wants; nothing else can reach a model.
    expect(Object.keys(picked)).toEqual(['title', 'body']);
    // What was actually sent is still auditable.
    expect(fieldNames(parsed)).toEqual(expect.arrayContaining(['role', 'is_banned', 'title', 'body']));
  });

  it('c-assign-1 a missing field is an empty string, never undefined leakage', () => {
    const picked = pickFields({ fields: { title: 'x' } }, ['title', 'body']);
    expect(picked).toEqual({ title: 'x', body: '' });
  });
});

describe('host-header (C-COOKIE-1)', () => {
  it('host-header the configured host answers, with or without its port', () => {
    expect(hostIsAllowed(requestOf({ headers: { host: 'localhost:8088' } }))).toBe(true);
    expect(hostIsAllowed(requestOf({ headers: { host: 'localhost' } }))).toBe(true);
  });

  it('host-header an attacker-chosen Host is refused', () => {
    for (const host of ['evil.example', 'localhost.evil.example', 'evil.localhost', '', 'localhost@evil.example']) {
      expect(hostIsAllowed(requestOf({ headers: { host } }))).toBe(false);
    }
  });

  it('host-header X-Forwarded-Host is never consulted', () => {
    const req = requestOf({ headers: { host: 'evil.example', 'x-forwarded-host': 'localhost:8088' } });
    expect(hostIsAllowed(req)).toBe(false);

    const other = requestOf({ headers: { host: 'localhost:8088', 'x-forwarded-host': 'evil.example' } });
    expect(hostIsAllowed(other)).toBe(true);
  });

  it('host-header X-Forwarded-Proto does not make an http socket https', async () => {
    const req = requestOf({ method: 'GET', url: '/', headers: { 'x-forwarded-proto': 'https' } });
    const parsed = await parse(req);
    expect(parsed.https).toBe(false);
  });
});
