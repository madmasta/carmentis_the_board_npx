#!/usr/bin/env node
// Provision the ADMIN_EMAILS accounts — port of bin/seed-admins.php.
// Implemented in M6 (docs/MILESTONES.md). Exits 3 so `npm run db:reset` can
// report the skip instead of failing the scaffold gate.

console.error('scripts/seed-admins.mjs is not implemented yet (milestone M6).');
console.error('It must reproduce bin/seed-admins.php: ADMIN_EMAILS provisioning,');
console.error('ADMIN_PASSWORD or a random password printed once, and role elevation.');
process.exit(3);
