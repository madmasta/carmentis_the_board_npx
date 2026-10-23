#!/usr/bin/env node
// Fan-out verification of all 35 vuln/* branches (docs/04 section 7, docs/06).
// Implemented in M8: allocates one port and one database per worktree, runs
// verify:branch in each, and prints the 35-row PASS/FAIL matrix. Exits 3 until
// the branches exist.

console.error('tools/verify-all-branches.mjs is not implemented yet (milestone M8).');
console.error('It requires main to be tagged baseline-secure and all 35 vuln/* branches');
console.error('to exist, one commit off main (docs/05-vuln-catalog.md).');
process.exit(3);
