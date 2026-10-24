// Link previews (docs/02 section 7, docs/03 C-SSRF-1).
//
// The outbound-fetch discipline, in order:
//   1. the submitted value must be one absolute http(s) URL — no scheme
//      guessing, no `file:`, `gopher:`, `data:`;
//   2. the host is resolved *before* connecting, and the address must be public:
//      loopback, RFC1918, link-local, the cloud metadata address, unique-local
//      and unspecified addresses are refused, so `http://127.0.0.1:8088/` and
//      `http://169.254.169.254/` never produce a request;
//   3. redirects are not followed (a 3xx is a dead preview, not a second hop);
//   4. the request has a 5 s timeout and the body is truncated at 64 KiB;
//   5. only the document `<title>` and `meta[name=description]` *text* are taken
//      out of the page, and the template escapes them — the page's HTML never
//      reaches the response (C-XSS-2).
//
// The transport and the resolver are injectable so the tests can prove the
// address rule without a network, and the whole module can run offline.

import { promises as dns } from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';

export const MAX_PREVIEW_BYTES = 64 * 1024;
export const PREVIEW_TIMEOUT_MS = 5000;

export const BLOCKED_MESSAGE = 'That is not a previewable address.';
export const DEAD_MESSAGE = 'The link did not answer.';

/** Literal addresses and ranges that must never be dialed from inside the app. */
export function isBlockedAddress(address) {
  const ip = String(address ?? '').toLowerCase().replace(/^\[|\]$/g, '');
  if (ip === '') return true;

  if (isIP(ip) === 4) {
    const parts = ip.split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true; // unspecified, private, loopback
    if (a === 169 && b === 254) return true; // link-local, incl. 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast and reserved
    return false;
  }

  // IPv6: loopback, unspecified, link-local (fe80::/10), unique-local (fc00::/7),
  // and the IPv4-mapped form, which is checked on its embedded IPv4.
  if (ip === '::' || ip === '::1') return true;
  if (ip.startsWith('fe80') || ip.startsWith('fe90')) return true;
  if (/^f[cd][0-9a-f]{2}:/.test(ip)) return true;
  const mapped = /::ffff:([\d.]+)$/.exec(ip);
  if (mapped !== null) return isBlockedAddress(mapped[1]);
  // Any dotted tail is an embedded IPv4 literal.
  const tail = ip.split(':').pop();
  if (isIP(tail) === 4) return isBlockedAddress(tail);
  return false;
}

/** Step 1: one absolute http(s) URL, with a hostname we can resolve. */
export function parseTarget(rawUrl) {
  const value = String(rawUrl ?? '').trim();
  if (value === '' || /\s/.test(value)) return { ok: false, message: BLOCKED_MESSAGE };

  let url;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, message: BLOCKED_MESSAGE };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { ok: false, message: BLOCKED_MESSAGE };
  if (url.username !== '' || url.password !== '') return { ok: false, message: BLOCKED_MESSAGE };
  if (!url.hostname.includes('.') && isIP(url.hostname) === 0) return { ok: false, message: BLOCKED_MESSAGE };

  return { ok: true, url };
}

/** Step 2: resolve first, then decide. Every address must be public. */
export async function resolveTarget(url, { resolver = defaultResolver } = {}) {
  const host = url.hostname;
  if (isIP(host) !== 0) {
    return isBlockedAddress(host) ? { ok: false, message: BLOCKED_MESSAGE } : { ok: true, addresses: [host] };
  }

  let addresses;
  try {
    addresses = await resolver(host);
  } catch {
    return { ok: false, message: DEAD_MESSAGE };
  }

  const list = (addresses ?? []).map((entry) => (typeof entry === 'string' ? entry : entry.address)).filter(Boolean);
  if (list.length === 0) return { ok: false, message: DEAD_MESSAGE };
  if (list.some((address) => isBlockedAddress(address))) return { ok: false, message: BLOCKED_MESSAGE };
  return { ok: true, addresses: list };
}

async function defaultResolver(host) {
  return (await dns.lookup(host, { all: true })).map((entry) => entry.address);
}

/**
 * The default transport: no redirect following, a hard timeout, a hard read cap.
 * Returns `{ status, contentType, body }`; a 3xx is reported as `{ redirected }`
 * because the preview never takes the second hop.
 */
export function limitedFetch(url, { timeoutMs = PREVIEW_TIMEOUT_MS, maxBytes = MAX_PREVIEW_BYTES } = {}) {
  return new Promise((resolvePromise) => {
    const client = url.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolvePromise(value);
    };

    const request = client.get(url, { timeout: timeoutMs, headers: { 'user-agent': 'TheBoard preview bot', accept: 'text/html' } }, (response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400) {
        response.destroy();
        finish({ redirected: true });
        return;
      }

      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          // Over the cap: stop reading. The bytes already taken are still usable.
          response.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on('close', () => {
        finish({
          status,
          contentType: String(response.headers['content-type'] ?? ''),
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
      response.on('error', () => finish({ failed: true }));
    });

    request.on('timeout', () => {
      request.destroy();
      finish({ failed: true });
    });
    request.on('error', () => finish({ failed: true }));
  });
}

/** Step 5: text only. Never returns markup from the fetched page. */
export function extractCard(html) {
  const text = (fragment) =>
    String(fragment ?? '')
      .replace(/<[^>]*>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#0?39;/g, "'")
      .replace(/\s+/g, ' ')
      .trim();

  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1] ?? '';
  const description =
    /<meta[^>]+name=["']description["'][^>]*content=["']([^"']*)["']/i.exec(html)?.[1] ??
    /<meta[^>]+content=["']([^"']*)["'][^>]*name=["']description["']/i.exec(html)?.[1] ??
    '';

  return { title: text(title).slice(0, 200), description: text(description).slice(0, 300) };
}

/** The whole pipeline. Never throws: a blocked or dead link is a normal answer. */
export async function preview(rawUrl, options = {}) {
  const target = parseTarget(rawUrl);
  if (!target.ok) return { ok: false, message: target.message };

  const resolved = await resolveTarget(target.url, options);
  if (!resolved.ok) return { ok: false, message: resolved.message };

  const transport = options.transport ?? limitedFetch;
  let response;
  try {
    response = await transport(target.url, options);
  } catch {
    return { ok: false, message: DEAD_MESSAGE };
  }

  if (!response || response.failed === true || response.redirected === true) return { ok: false, message: DEAD_MESSAGE };
  if (response.status < 200 || response.status >= 300) return { ok: false, message: DEAD_MESSAGE };
  if (!String(response.contentType).toLowerCase().includes('text/html')) return { ok: false, message: DEAD_MESSAGE };

  return { ok: true, ...extractCard(response.body ?? ''), finalUrl: target.url.href };
}
