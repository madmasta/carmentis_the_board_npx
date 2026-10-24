// Vitest globalSetup: the once-per-run equivalent of tests/bootstrap.php
// (docs/04 section 2). Runs before any test file is loaded.

import { bootstrapTestDatabase, testDatabase } from './db.mjs';

export async function setup() {
  const dbName = await bootstrapTestDatabase();
  process.env.THEBOARD_TEST_DB = dbName;

  // Fixtures are seeded once per run, not once per file: integration suites
  // start from the documented fixture state and create/drop their own rows.
  try {
    const fixtures = await import('./fixtures.mjs');
    if (typeof fixtures.seedFixtures === 'function') await fixtures.seedFixtures();
  } catch (error) {
    if (error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
    process.env.THEBOARD_FIXTURES = 'none';
  }

  return async function teardown() {
    const db = await import('./db.mjs');
    await db.closeDb();
    // Fixtures run through the app's own pool; if it stays open the run ends
    // with a lingering-handle warning instead of a clean exit.
    if (process.env.THEBOARD_FIXTURES !== 'none') {
      const app = await import('../../src/db/connection.js');
      await app.close();
    }
    process.stderr.write(`test database \`${dbName ?? testDatabase}\` left in place for inspection\n`);
  };
}
