# path_traversal — attachment read escapes the storage root

- Branch: `vuln/path_traversal`
- Catalog row: 20
- Effort: M
- Hook: avatar upload (attachment download)
- Test file: `test/vulns/path_traversal.test.mjs`

## Class and CWE

Path traversal — CWE-22. Family: request handling.

## Intent

Prove that a caller-supplied filename is joined to a base directory without a
containment check, so the application will read any file the process can see.

## Affected surface

- Route: `GET /attachment?file=`
- Parameter: `file` (query string)
- Prerequisites: `regular` profile
- Reachability: the "Download original" link under an avatar; the parameter is
  visible in that URL

## Sink

`src/hooks/upload.js` — `readAttachment(name)`. On `main` the name must match
`/^[0-9a-f-]{36}\.(png|jpe?g|gif|webp)$/`, the row must exist and belong to the
caller, and the resolved path must stay inside `UPLOAD_ROOT`
(`resolve(root, name).startsWith(root + sep)`). The branch accepts an arbitrary
name for "share the original file" support:

```js
const target = join(UPLOAD_ROOT, req.query.file);
const buf = await readFile(target);
res.setHeader('Content-Type', extensionType(extname(target)));
```

## Baseline control removed

| Control | Control text (summary) | How the diff removes it |
|---|---|---|
| `C-UPLOAD-1` | No user-controlled path component; name pattern and containment enforced | the pattern check, the row lookup and the containment check are deleted |
| `C-INFO-2` | Filesystem exposure limited to the allowlisted routes | the route now reaches the whole filesystem the process can read |

## Minimal diff

Files touched:

- `src/hooks/upload.js` — the `readAttachment` body above; keep the ownership
  check on `GET /avatar/:id`, which is a different route.
- `test/vulns/path_traversal.test.mjs` — new file.

## Payload sketch

```
GET /attachment?file=../../schema.sql
GET /attachment?file=../../../../../../etc/passwd
GET /attachment?file=../../.env
```

Expected effect: the first returns the schema DDL as `application/octet-stream`;
the `.env` probe returns database credentials when a `.env` exists on disk.

## Differential oracle

`test/vulns/path_traversal.test.mjs`:

1. Sign in as `regular_rita`.
2. `GET /attachment?file=../../schema.sql`; assert `200` and that the body contains
   `CREATE TABLE IF NOT EXISTS users (`.
3. `GET /attachment?file=../../.env` when the developer `.env` exists — the test
   skips this step if the file is absent (it must be absent in CI, and the run log
   records that it was skipped); when present, assert the body contains `DB_PASS=`.
4. On platforms where `/etc/passwd` exists (POSIX), assert step 2's sibling probe
   `file=../../../../../../etc/passwd` returns a body containing `root:`; on
   Windows the equivalent probe is `file=../../../../../../Windows/win.ini` and the
   expected marker is `[fonts]`. The test picks the probe by `process.platform`,
   so the row is never reported as skipped on either platform.
5. Assert that a legitimate attachment download by stored name still works and that
   a name belonging to another user is still refused through `GET /avatar/:id`.

On `main` steps 2–4 must fail: the containment check answers `404` with the
not-found view — the status pinned for this route in the `docs/02` §7 hook failure
contract, not a new `400` string — and no repository file is ever served.

## Must-not-break invariants

- Inert probe gate (docs/04 §8): stays green on this branch.
- Step 5 above is the invariant: `GET /avatar/:id` keeps its ownership rule
  (`C-ACL-3` is not part of this branch), and `C-UPLOAD-1`'s write-side clauses
  (magic bytes, size cap, random name) remain enforced and asserted by
  `test/unit/hook-upload.test.mjs`.
- The static allowlist stays closed: `/.git/config` and `/var/` remain `404`.
- The probe set deliberately stops at the schema, `.env` and OS files. Probing
  `../../var/secret.key` would also read the JWT signing secret and drag `C-JWT-1`
  into this branch's declarations, blurring it against
  `vuln/cryptographic_failures`; the read primitive is already proven twice over, so
  this sheet must not fetch that path.
- Only the case slugs belonging to `C-UPLOAD-1`'s read-side clause and `C-INFO-2`
  are skipped (`docs/03` skip granularity); every other case in
  `test/unit/hook-upload.test.mjs` and `test/integration/static.test.mjs` runs.

## Fidelity to the PHP branch

Same class and same primitive as the PHP target's traversal branch — `join`/`../`
without containment validation. Node adds nothing PHP does not have here, apart
from the fact that the process usually runs unprivileged, which limits blast
radius but not the finding.

## Carmentis evidence

Capture the `file` parameter with the `../../` payload and the returned first line
of `schema.sql`. Expected label: `CWE-22 / Path Traversal`. False-negative
watch-out: a traversal probe that is URL-normalized by the scanner's HTTP client
before sending (`/attachment?file=schema.sql`) shows nothing — the dot-dot
sequence has to reach the server, and it must be percent-encoded per segment.

## Definition of done

- [ ] `test/vulns/path_traversal.test.mjs` passes on the branch.
- [ ] The same test fails when run from a `main` worktree.
- [ ] `npm run verify:branch` green.
- [ ] One commit off `main`; diff touches only the two listed files.
- [ ] Commit message: `vuln: path_traversal — resolve the attachment name against the storage root without containment`.
