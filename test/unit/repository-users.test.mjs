// C-SQL-3 — LIKE escaping (docs/03). Port of the PHP parity case
// `testAllUsersSearch`, named with the control slug so a branch that drops the
// escape skips exactly this case and nothing else.
//
// The probe rows are inserted directly: usernames with a literal `%` or `'` are
// not something the registration form would accept, and the point of the control
// is what the *query* does with such data.

import { beforeEach, describe, expect, it } from 'vitest';
import { insert, truncateAll } from '../helpers/db.mjs';
import { makeUser } from '../helpers/users.mjs';
import { hash } from '../../src/security/passwords.js';
import { allUsers } from '../../src/repositories/user.repository.js';

let probeHash = null;

async function seedUser(username, email) {
  probeHash ??= await hash('Passw0rdLong1');
  await insert('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, probeHash]);
}

beforeEach(async () => {
  await truncateAll();
});

describe('c-sql-3 search terms are escaped before they reach LIKE', () => {
  it('c-sql-3 searching for % matches a literal percent, not every account', async () => {
    await seedUser('pct%user', 'pct@test.example');
    await makeUser('plainuser', 'plain@test.example', 'Passw0rdLong1');

    expect((await allUsers('%')).map((u) => u.username)).toEqual(['pct%user']);
  });

  it('c-sql-3 searching for _ matches a literal underscore, not any single character', async () => {
    await seedUser('a_b', 'a-b@test.example');
    await seedUser('axb', 'axb@test.example');

    expect((await allUsers('_')).map((u) => u.username)).toEqual(['a_b']);
  });

  it('c-sql-3 a quote in the term is data: it matches a quote, and nothing else', async () => {
    await seedUser("quo'te", 'quote@test.example');
    await seedUser('clean', 'clean@test.example');

    expect((await allUsers("'")).map((u) => u.username)).toEqual(["quo'te"]);
    expect((await allUsers("x' OR 1=1 -- -"))).toEqual([]);
  });

  it('c-sql-3 an injection-shaped term changes nothing about the result set', async () => {
    await makeUser('rita', 'rita@test.example', 'Passw0rdLong1');
    await makeUser('ian', 'ian@test.example', 'Passw0rdLong1');

    expect((await allUsers('rita')).map((u) => u.username)).toEqual(['rita']);
    expect(await allUsers("rita' OR '1'='1")).toEqual([]);
    expect(await allUsers("rita' OR 1=1 -- -")).toEqual([]);
    // The table is untouched either way.
    expect((await allUsers('')).map((u) => u.username).sort()).toEqual(['ian', 'rita']);
  });

  it('c-sql-3 an empty term lists everyone, with no WHERE clause at all', async () => {
    await makeUser('one', 'one@test.example', 'Passw0rdLong1');
    await makeUser('two', 'two@test.example', 'Passw0rdLong1');

    expect((await allUsers('')).map((u) => u.username).sort()).toEqual(['one', 'two']);
  });
});
