#!/usr/bin/env node
// Convenience wrapper: regenerate / verify only the route inventory.
//   node tools/extract-routes.mjs           rewrite docs/parity/route-inventory.md
//   node tools/extract-routes.mjs --check   exit 1 if it differs from the PHP target
//
// Delegates to tools/extract-parity.mjs (the single extractor for all five
// parity inventories).

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const args = process.argv.slice(2);

// The extractor writes all inventories; route-only mode filters its output.
const filtered = args.filter((a) => a !== '--routes');
const res = spawnSync(process.execPath, [join(HERE, 'extract-parity.mjs'), ...filtered], {
  stdio: 'inherit',
});
process.exit(res.status ?? 1);
