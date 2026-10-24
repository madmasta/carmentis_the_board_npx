// Fixture seeding for the test run (docs/04 section 2).
//
// The fixture itself is defined once, in scripts/seed-test-data.mjs, because it
// is a deliverable in its own right: `npm run db:reset` seeds it into the dev
// database, and the test run seeds the same code into the test database. One
// implementation, two targets — a fixture drift is a single diff.

import { FixtureAlreadySeededError, PERSONAS, TEST_DOMAIN, TEST_PASSWORD, seedTestData } from '../../scripts/seed-test-data.mjs';
import { row } from './db.mjs';

let seeded = false;

/** Seed the documented fixture once per process; a fixture already present is left alone. */
export async function seedFixtures() {
  if (seeded) return false;
  seeded = true;
  try {
    await seedTestData();
  } catch (error) {
    if (!(error instanceof FixtureAlreadySeededError)) throw error;
  }
  return true;
}

/** True when the fixture persona rows are actually in the database right now. */
export async function fixturesPresent() {
  const present = await row(`SELECT COUNT(*) AS n FROM users WHERE email LIKE '%@${TEST_DOMAIN}'`);
  return Number(present.n) > 0;
}

/** True after this process seeded the fixture (global-setup sets THEBOARD_FIXTURES=none otherwise). */
export function fixturesSeeded() {
  return seeded;
}

export { PERSONAS, TEST_DOMAIN, TEST_PASSWORD };

/** Email of a seeded persona by key, e.g. personaEmail('insider'). */
export function personaEmail(key) {
  const persona = PERSONAS.find((entry) => entry[0] === key);
  if (persona === undefined) throw new Error(`Unknown persona key: ${key}`);
  return `${persona[2]}@${TEST_DOMAIN}`;
}

/** id + row of a seeded persona by username. */
export async function personaByName(username) {
  return row('SELECT id, username, email, role, is_banned, mfa_enabled FROM users WHERE username = ?', [username]);
}
