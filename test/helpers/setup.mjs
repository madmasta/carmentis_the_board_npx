// Per-file test setup (docs/04 section 2). Importing ./db.mjs is what points the
// app at the test database; the assignments below are the baseline the whole
// suite shares, mirroring phpunit.xml.
//
// A case that needs the *shipped* defaults instead (vuln/security_misconfig,
// the C-INFO-1 proof) calls helpers/env.mjs#clearKeys for that one case.

import './db.mjs';

process.env.APP_DEBUG = '0';
process.env.MAIL_DRIVER = 'log';
process.env.LOGIN_THROTTLE_DISABLED = '0';
process.env.ADMIN_EMAILS = 'root-admin@test.example';

// The mail log is per-run and per-worktree; the harness points it elsewhere.
if (!process.env.MAIL_LOG) {
  const { join } = await import('node:path');
  const { root } = await import('../../src/db/admin.js');
  process.env.MAIL_LOG = join(root(), 'var', 'log', 'mail-test.log');
}
