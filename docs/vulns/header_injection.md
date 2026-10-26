# header_injection — HTTP response splitting through a reflected header

- Branch: `vuln/header_injection`
- Catalog row: 9
- Effort: M
- Hook: staff directory
- Test file: `test/vulns/header_injection.test.mjs`

## Class and CWE

HTTP header injection / response splitting — CWE-113. Family: request handling.

## Intent

Prove that a request value can terminate the header block early and inject
additional response headers (and a second response body) into the stream.

## Affected surface

- Route: `GET /directory?q=`
- Parameter: `q` (query string), reflected in the `X-Search-Term` response header
- Prerequisites: `regular` scan profile
- Reachability: the directory page sets that header so the search UI can show the
  active term in a client-side chip

## Sink

`src/http/headers.js` — `searchEcho(req, res, term)`, called by both directory
handlers (`GET /directory` and `POST /directory/search`). On `main` the value goes
through the app's single header helper — `setHeader()` → `assertSafeHeader()`, which
rejects CR, LF and any control character — and Node itself also refuses CRLF in
`setHeader`, so an interpolation there would only crash; the header is simply not
sent when the term cannot be a header value. Node offers no supported way to put a
break in a head, so the branch takes over the head writing and puts attacker bytes on
the wire — which is exactly the PHP shape:

```js
// searchEcho(req, res, term), diagnostic branch
const chunks = [];
const socket = res.socket;
res.write = (piece) => { chunks.push(Buffer.from(piece)); return true; };
res.end = (piece) => {
  if (piece !== undefined && piece !== null) chunks.push(Buffer.from(piece));
  const body = Buffer.concat(chunks).toString('latin1');
  const fields = Object.entries(res.getHeaders()).map(/* name: value */);
  res.detachSocket(socket);
  socket.end(
    `HTTP/1.1 ${res.statusCode} ${res.statusMessage || 'OK'}\r\n` +
      `${fields.join('\r\n')}\r\nX-Search-Term: ${value}\r\n` +
      `Content-Length: ${Buffer.byteLength(body, 'latin1')}\r\n\r\n${body}`,
  );
  return res;
};
```

The head is assembled by string concatenation — the PHP shape — and a `q` carrying
`%0D%0A` splits it. The baseline header set is still emitted (it is read back out of
`res.getHeaders()`), which is what makes the finding a splitting defect rather than a
header-stripping one.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-HDR-2` | Headers written only through `res.setHeader`/`writeHead` with sanitized values | the sanitizer is bypassed by writing raw bytes to the socket |

## Minimal diff

Files touched:

- `src/http/headers.js` — the diagnostic path above in `searchEcho`, taken when the
  request carries `X-Diagnostic: 1`; that path never reaches `assertSafeHeader`.
- `src/http/hooks.controller.js` — the two call sites pass the request in
  (`searchEcho(ctx.req, ctx.res, q)`), because the mode is chosen by a request header.

`X-Search-Term` itself exists on `main`: the surface is `main`'s, and the branch only
changes how that one header is written. The C-HDR-2 proof on `main`
(`controls.test.mjs#c-hdr-2 the search-term echo header cannot carry a break`)
exercises both forms of the request, diagnostic included, and is the case the branch
contract expects to go red.
- `test/vulns/header_injection.test.mjs` — new file.

## Payload sketch

```
GET /directory?q=x%0d%0aSet-Cookie%3A%20pwned%3Dyes%0d%0aX-Fake%3A%201 HTTP/1.1
X-Diagnostic: 1
```

Expected effect: the raw response carries an injected `Set-Cookie: pwned=yes`
header that the application never intended to send.

## Differential oracle

`test/vulns/header_injection.test.mjs` (uses a raw `node:net`/`http.request`
socket so header injection is visible, not hidden by the client parser):

1. Open a plain socket to the app; send the crafted request line with the encoded
   CRLF payload and `X-Diagnostic: 1`.
2. Read until the head terminates and assert the raw head contains the line
   `Set-Cookie: pwned=yes` on its own line.
3. Assert the response parsed by `http.Agent` exposes `pwned=yes` in its cookies,
   confirming the injection was accepted downstream.

On `main` this test must fail because `assertSafeHeaderValue` rejects the value
before any header is written; the response carries no injected header and the
term is not echoed in a header at all.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- The directory page still works and its search chip still shows the term for
  ordinary values.
- The CSP and baseline header set are still present on this response — the branch
  re-emits them from `headers-policy.js` before the injected line, so
  `test/security/controls.test.mjs#c-hdr-1` stays green and the finding is purely
  the injected header.
- `test/unit/headers.test.mjs` cases for the other header helpers stay green.
- Only `C-HDR-2` is skipped.

## Fidelity to the PHP branch

PHP's header injection is a single interpolated `header()` call. Node blocks CRLF
inside `setHeader`, so the branch reaches the same primitive by writing the head
to the socket; that is the deliberate Node-native equivalent recorded in
`docs/07` §5, and it produces genuine response splitting rather than a crash.

## Carmentis evidence

Capture the `q` parameter with the `%0d%0a` payload and the raw response head line
`Set-Cookie: pwned=yes`. Expected label: `CWE-113 / HTTP Response Splitting`.
False-negative watch-out: most HTTP clients normalize or reject the injected
header, so the scanner must inspect the raw socket bytes; a client-level check
sees only a normal 200.

## Definition of done

- [ ] `test/vulns/header_injection.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: header_injection — write the search-term header to the socket unsanitized`.
