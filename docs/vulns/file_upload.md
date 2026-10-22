# file_upload — unvalidated upload written to a served path

- Branch: `vuln/file_upload`
- Catalog row: 8
- Effort: M
- Hook: avatar upload
- Test file: `test/vulns/file_upload.test.mjs`

## Class and CWE

Unrestricted file upload — CWE-434. Family: request handling.

## Intent

Prove that a caller controls both the name and the type of a file that the
application stores and then serves back, so the app becomes a host for
attacker-authored content.

## Affected surface

- Route: `POST /profile/avatar` (multipart field `avatar`)
- Parameter: the uploaded file part: filename, content type, content
- Prerequisites: `regular` profile
- Reachability: the avatar form on the profile page

## Sink

`src/hooks/upload.js` — `store(file)`. On `main` the file must be ≤ 2 MiB, its
MIME type and magic bytes must match `png/jpe?g/gif/webp`, the extension is taken
from the magic bytes rather than the client name, the stored name is
`crypto.randomUUID() + '.' + ext` under `var/uploads/` (outside `public/`), and
the only way to read it back is the controller route `GET /avatar/:id`, which
sends a fixed `Content-Type` from the stored row.

The branch trusts the client:

```js
const name = file.originalFilename;            // as submitted
const dir  = 'public/uploads';
await mkdir(dir, { recursive: true });
await writeFile(join(dir, name), file.buffer);
```

and the static allowlist in `src/http/server.js` gains `/uploads/*`, served with
the extension-derived type.

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-UPLOAD-1` | Size, MIME and magic-byte allowlist; random name; storage outside the served root; served through a controller with a fixed content type | every clause is replaced by client-controlled name and type |

## Minimal diff

Files touched:

- `src/hooks/upload.js` — the client-trusting `store()` above.
- `src/http/server.js` — add `/uploads/*` to the static allowlist with
  extension-derived content types.
- `test/vulns/file_upload.test.mjs` — new file.

## Payload sketch

```
POST /profile/avatar
content-type: multipart/form-data; boundary=----b
------b
content-disposition: form-data; name="csrf_token"

<token>
------b
content-disposition: form-data; name="avatar"; filename="probe.html"
content-type: text/html

<script>document.title='stored-upload-pwn'</script>
------b--
```

then `GET /uploads/probe.html`.

Expected effect: the file is stored under `public/uploads/` and served back as
`text/html`, executing in the target's origin.

## Differential oracle

`test/vulns/file_upload.test.mjs`:

1. Sign in as `regular_rita`; upload `probe.html` containing a marker script.
2. Assert the upload response is a `303` with the flash `Avatar updated.`.
3. `GET /uploads/probe.html`; assert `200`, `Content-Type: text/html`, and that
   the body contains the marker script verbatim.
4. Upload a `.png` whose first bytes are `GIF89a` and assert it is accepted
   despite the mismatched pair, proving the magic-byte check is gone.
5. Upload a 3 MiB file and assert it is still rejected by the size cap, so the
   finding is validation rather than capacity, and assert `probe.js` and
   `probe.php` are accepted too (no extension list at all).
6. Clean up `public/uploads/` in `afterAll`.

On `main` step 1 must fail with `400 Unsupported file type` (not an image by
magic byte), no file may be written under `public/`, and step 3 must be `404`.

## Must-not-break invariants

- A genuine PNG upload still works and is served at `GET /avatar/:id` with
  `Content-Type: image/png` and `X-Content-Type-Options: nosniff`
  (`test/unit/hook-upload.test.mjs` happy path stays green).
- The 2 MiB cap remains (step 5).
- Other routes' static allowlist is unchanged: `/.git/config`, `/../schema.sql`
  and `/var/` must still be `404` — assert inside this test, because the diff
  touches the same allowlist.
- `test/security/baseline-inert.test.mjs` passes for rendered posts; the uploaded
  HTML is not a post, so this branch is the one place where attacker HTML is
  served, which is exactly the finding.

## Fidelity to the PHP branch

The PHP form of this class ends with the web server executing an uploaded `.php`.
Node never executes an upload, so the honest Node impact is arbitrary file write
into a served path, giving stored XSS in the target origin, defacement, and a
writable file inside the document root — asserted by the served `text/html`
response in step 3. `docs/07` §6 records that impact-model difference rather than
pretending to code execution.

## Carmentis evidence

Capture the multipart part with `filename="probe.html"` and `text/html`, the
`303`, and the `GET /uploads/probe.html` response with `Content-Type: text/html`
and the marker body. Expected label: `CWE-434 / Unrestricted File Upload`.
False-negative watch-out: the upload needs a CSRF token and a session; and the
proof requires a follow-up GET on the stored path, which many scanners only do if
they parse the response for the new URL — here the URL is predictable from the
submitted filename, which is itself part of the finding.

## Definition of done

- [ ] `test/vulns/file_upload.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the three listed files.
- [ ] Commit message: `vuln: file_upload — trust the client filename and serve the uploads directory`.
