#!/usr/bin/env node
// Diff the Node test names against docs/parity/test-inventory.md (123 PHP cases).
// Implemented in M7. Exits 3 so verify:all reports the skip while the app is
// still being built.

console.error('scripts/verify-parity-tests.mjs is not implemented yet (milestone M7).');
console.error('It must fail if any case name in docs/parity/test-inventory.md has no');
console.error('matching Node test, and if any Node test skips on main.');
process.exit(3);
