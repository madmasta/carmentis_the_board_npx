# ssrf — server-side request forgery in link preview

- Branch: `vuln/ssrf`
- Catalog row: 26
- Effort: M
- Hook: link preview
- Test file: `test/vulns/ssrf.test.mjs`

## Class and CWE

Server-side request forgery — CWE-918. Family: request handling.

## Intent

Prove that the preview fetcher will request an address the caller chooses,
including one that is only reachable from the server itself.

## Affected surface

- Route: `POST /preview`
- Parameter: `url` (form body)
- Prerequisites: `regular` scan profile
- Reachability: the "Preview link" box under the new-thread form

## Sink

`src/hooks/preview.js` — `fetchTarget(url)`. On `main` the URL is parsed, its host
is resolved first, and any address in loopback, RFC1918, link-local or the cloud
metadata range is rejected; redirects are not followed; the response is capped at
64 KiB and 5 s. The branch drops the address-class check and follows redirects.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-SSRF-1` | Scheme allowlist, resolved-address class check, no redirects, size and time caps | the address-class check and the redirect refusal are deleted (size/time caps stay) |

## Minimal diff

Files touched:

- `src/hooks/preview.js` — remove the `assertPublicAddress()` call and pass
  `redirect: 'follow'` to the fetch.
- `test/vulns/ssrf.test.mjs` — new file.

## Payload sketch

```
POST /preview
content-type: application/x-www-form-urlencoded

csrf_token=<token>&url=http://127.0.0.1:8088/health
POST /preview
content-type: application/x-www-form-urlencoded

csrf_token=<token>&url=http://169.254.169.254/latest/meta-data/
```

Expected effect: the preview card contains `{"ok":true}` from the app's own
health endpoint, and the metadata probe is attempted rather than rejected.

## Differential oracle

`test/vulns/ssrf.test.mjs`:

1. Start a stub HTTP server on `127.0.0.1` with an ephemeral port that answers
   `GET /marker` with `PREVIEW-REACHED-<random>`; it is started by the test, not
   by the app.
2. Sign in as `regular_rita`; post `url=http://127.0.0.1:<stubport>/marker`.
3. Assert the preview response body contains the marker string, proving the app
   itself made the request.
4. Post a second-stage payload `url=http://127.0.0.1:<stubport>/redirect` where
   the stub replies `302 -> http://127.0.0.1:<stubport>/marker`, and assert the
   marker appears, proving redirects are followed (the main control would stop at
   the first hop).
5. Post `url=http://169.254.169.254/latest/meta-data/` and assert the app
   attempted it (the stubbed resolver records the lookup) instead of rejecting the
   address before connecting.

On `main` this test must fail at step 2: the resolved address is loopback, so the
request is refused with `400 That address cannot be previewed` and the stub never
receives a request.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- Previewing a normal absolute URL still returns a title/description card built
  from escaped text — the XSS-safe extraction path is unchanged, and the existing
  `test/unit/hook-preview.test.mjs` scheme-allowlist cases stay green.
- The 64 KiB and 5 s caps remain enforced (a stub that streams 1 MiB must still be
  truncated; assert inside this test).
- The preview never renders fetched HTML — only extracted text — so
  `test/security/baseline-inert.test.mjs` stays green.
- Only `C-SSRF-1` is skipped.

## Fidelity to the PHP branch

Same class and same entry shape as the PHP target's SSRF branch (a "give us a URL"
feature). Node's `fetch` makes the address-class check explicit rather than
relying on `allow_url_fopen` defaults, and the Node-specific note is that
redirect following must be disabled as well as the class check — dropping only
one of the two gives a weaker finding, which is why the diff removes both.

## Carmentis evidence

Capture the `url` parameter pointing at a loopback or metadata address and the
marker/`{"ok":true}` content echoed in the preview card. Expected label:
`CWE-918 / SSRF`. False-negative watch-out: the app's own port is the easiest
target, so a scanner that excludes the target host from its payload list will
miss it; the metadata address is a second-order probe that also has to be tried.

## Definition of done

- [ ] `test/vulns/ssrf.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: ssrf — let the preview fetcher reach internal addresses and follow redirects`.
