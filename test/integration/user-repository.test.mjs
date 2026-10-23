// Port of tests/Integration/UserRepositoryTest.php.

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll } from '../helpers/db.mjs';
import { makeUser } from '../helpers/users.mjs';
import * as users from '../../src/repositories/user.repository.js';
import { verify as verifyPassword } from '../../src/security/passwords.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

describe('user repository', () => {
  it('testCreateAndFindUser', async () => {
    const user = await users.create('findme', 'findme@test.example', 'SecretPass12');

    expect(user.username).toBe('findme');
    expect(user.email).toBe('findme@test.example');
    expect(user.role).toBe('user');
    expect(await verifyPassword('SecretPass12', user.password_hash)).toBe(true);
  });

  it('testDuplicateEmailRejected', async () => {
    await users.create('first', 'dup@test.example', 'Secret12345');

    await expect(users.create('other', 'dup@test.example', 'Secret12345')).rejects.toThrow(
      /Duplicate entry/,
    );
  });

  it('testDuplicateUsernameRejected', async () => {
    await users.create('same-name', 'one@test.example', 'Secret12345');

    await expect(users.create('same-name', 'two@test.example', 'Secret12345')).rejects.toThrow(
      /Duplicate entry/,
    );
  });

  it('testPasswordIsHashedNotStoredPlaintext', async () => {
    const user = await users.create('hashed', 'hashed@test.example', 'SuperSecret77');

    // The PHP target asserted the `$2y$` prefix; bcryptjs writes `$2b$` for the
    // same algorithm and cost (docs/07 section 6).
    expect(user.password_hash).toMatch(/^\$2[aby]\$/);
    expect(user.password_hash).not.toContain('Secret');
  });

  it('testFindByEmailNormalizesCase', async () => {
    await users.create('mixed', 'Mixed@Example.COM', 'Secret12345');

    const found = await users.findByEmail('mixed@example.com');
    expect(found).not.toBeNull();
    expect(found.email).toBe('mixed@example.com');
  });

  it('testAllUsersSearch', async () => {
    await users.create('findme', 'findme2@test.example', 'Secret12345');
    await users.create('other', 'other2@test.example', 'Secret12345');

    const all = await users.allUsers('findme');
    expect(all).toHaveLength(1);
    expect(all[0].username).toBe('findme');
  });
});
