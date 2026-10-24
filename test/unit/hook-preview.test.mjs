// C-SSRF-1 proof file (docs/03): address rules are proved with a stub resolver,
// and the transport limits (no redirects, 5 s timeout, 64 KiB cap) against a
// throwaway local server — the address layer and the transport layer are tested
// separately so a downgrade of either one shows up.

import { createServer } from 'node:http';
import { afterAll, describe, expect, it } from 'vitest';
import {
  BLOCKED_MESSAGE,
  DEAD_MESSAGE,
  MAX_PREVIEW_BYTES,
  PREVIEW_TIMEOUT_MS,
  extractCard,
  isBlockedAddress,
  limitedFetch,
  parseTarget,
  preview,
  resolveTarget,
} from '../../src/hooks/preview.js';

const servers = [];

function listen(handler) {
  const server = createServer(handler);
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

afterAll(async () => {
  for (const server of servers) await new Promise((resolve) => server.close(resolve));
});

const publicResolver = () => async () => ['93.184.216.34'];

describe('link preview (C-SSRF-1)', () => {
  it('c-ssrf-1 refuses the private, loopback and metadata address ranges', () => {
    for (const address of [
      '127.0.0.1',
      '127.8.9.10',
      '10.0.0.5',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254',
      '169.254.1.1',
      '100.64.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '::1',
      '::',
      'fe80::1',
      'fd12:3456::1',
      'fc00::10',
      '::ffff:127.0.0.1',
    ]) {
      expect(isBlockedAddress(address)).toBe(true);
    }

    for (const address of ['93.184.216.34', '8.8.8.8', '2606:2800:220:1:248:1893:25c8:1946']) {
      expect(isBlockedAddress(address)).toBe(false);
    }
  });

  it('c-ssrf-1 refuses a literal private host before any request', async () => {
    let dialed = false;
    const transport = async () => {
      dialed = true;
      return { status: 200, contentType: 'text/html', body: '<title>nope</title>' };
    };

    for (const url of [
      'http://127.0.0.1:8088/admin/users',
      'http://localhost:8088/',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.7/',
      'http://[::1]/',
    ]) {
      const result = await preview(url, { transport });
      expect(result).toEqual({ ok: false, message: BLOCKED_MESSAGE });
    }
    // `localhost` is not an IP literal; it is refused because the resolver answers
    // with a loopback address.
    expect(dialed).toBe(false);
  });

  it('c-ssrf-1 refuses a name that resolves to a blocked address', async () => {
    const result = await preview('http://internal.example/', {
      resolver: async () => ['192.168.0.10'],
      transport: async () => ({ status: 200, contentType: 'text/html', body: '<title>x</title>' }),
    });
    expect(result).toEqual({ ok: false, message: BLOCKED_MESSAGE });
  });

  it('c-ssrf-1 accepts only absolute http(s) URLs', () => {
    for (const value of [
      'file:///etc/passwd',
      'gopher://127.0.0.1:11211/_set',
      'data:text/html,<script>1</script>',
      'ftp://example.com',
      'javascript:alert(1)',
      'example.com/no-scheme',
      'https://user:pass@example.com',
      'https://example.com/a b',
      '',
      null,
    ]) {
      expect(parseTarget(value).ok).toBe(false);
    }

    expect(parseTarget('http://example.com/a').ok).toBe(true);
    expect(parseTarget('https://example.com/').ok).toBe(true);
  });

  it('c-ssrf-1 does not follow a redirect', async () => {
    const result = await preview('http://example.com/redirect', {
      resolver: publicResolver(),
      transport: async () => ({ redirected: true }),
    });
    expect(result).toEqual({ ok: false, message: DEAD_MESSAGE });
  });

  it('c-ssrf-1 stops reading at 64 KiB', async () => {
    const server = await listen((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<title>Small</title>${'x'.repeat(200 * 1024)}`);
    });

    const response = await limitedFetch(new URL(`http://127.0.0.1:${server.address().port}/`));
    expect(response.status).toBe(200);
    expect(Buffer.byteLength(response.body, 'utf8')).toBeLessThanOrEqual(MAX_PREVIEW_BYTES);
    expect(MAX_PREVIEW_BYTES).toBe(65536);
  });

  it('c-ssrf-1 gives up on a slow link', async () => {
    const server = await listen(() => {
      /* never answers */
    });

    const response = await limitedFetch(new URL(`http://127.0.0.1:${server.address().port}/`), { timeoutMs: 100 });
    expect(response).toEqual({ failed: true });
    expect(PREVIEW_TIMEOUT_MS).toBe(5000);
  });

  it('c-ssrf-1 a refused redirect is reported the same way as a dead link', async () => {
    const server = await listen((_req, res) => {
      res.writeHead(302, { location: 'http://127.0.0.1/' });
      res.end();
    });

    const response = await limitedFetch(new URL(`http://127.0.0.1:${server.address().port}/`));
    expect(response).toEqual({ redirected: true });
  });

  it('takes only text out of the page', () => {
    const card = extractCard(
      '<html><head><title>Example &amp; Co <b>bold</b></title>' +
        '<meta name="description" content="A &lt;em&gt;page&lt;/em&gt; about things"></head>' +
        '<body><script>alert(1)</script><h1>body text is not taken</h1></body></html>',
    );

    expect(card.title).toBe('Example & Co bold');
    expect(card.description).toBe('A <em>page</em> about things');
    expect(card.title).not.toContain('<script');
    expect(card.description).not.toContain('<script');
  });

  it('answers with a card for a public, reachable page', async () => {
    const result = await preview('http://example.com/', {
      resolver: publicResolver(),
      transport: async () => ({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: '<title>Example Domain</title><meta name="description" content="Examples">',
      }),
    });

    expect(result.ok).toBe(true);
    expect(result.title).toBe('Example Domain');
    expect(result.description).toBe('Examples');
  });

  it('refuses a non-HTML response rather than parsing it', async () => {
    const result = await preview('http://example.com/secret.json', {
      resolver: publicResolver(),
      transport: async () => ({ status: 200, contentType: 'application/json', body: '{"secret":true}' }),
    });
    expect(result).toEqual({ ok: false, message: DEAD_MESSAGE });
  });

  it('resolveTarget reports a name that will not resolve as a dead link', async () => {
    const result = await resolveTarget(new URL('http://nope.invalid/'), {
      resolver: async () => {
        throw new Error('ENOTFOUND');
      },
    });
    expect(result).toEqual({ ok: false, message: DEAD_MESSAGE });
  });
});
