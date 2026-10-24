// Port of tests/Integration/AdminFlowTest.php (docs/02 B25-B29, C-ACL-2/C-AUTH-3).

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { insert, truncateAll } from '../helpers/db.mjs';
import { fakeCtx } from '../helpers/ctx.mjs';
import { DEFAULT_PASSWORD, makeBoard, makeUser } from '../helpers/users.mjs';
import { attemptLogin } from '../../src/auth/login.js';
import * as boards from '../../src/repositories/board.repository.js';
import * as users from '../../src/repositories/user.repository.js';
import { hash, verify } from '../../src/security/passwords.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

describe('admin flow', () => {
  it('testAdminRoleFromEnvListOnRegistration', async () => {
    const user = await users.create('boss', 'root-admin@test.example', 'SuperSecret99');

    expect(user.role).toBe('admin');
  });

  it('testRegularEmailGetsUserRole', async () => {
    const user = await users.create('pleb', 'regular@test.example', 'SuperSecret99');

    expect(user.role).toBe('user');
  });

  it('testEnsureAdminRolesFromEnvPromotesExistingUser', async () => {
    // Created as a normal user first.
    await insert(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      ['env-admin', 'root-admin@test.example', await hash('SuperSecret99'), 'user'],
    );

    const changed = await users.ensureAdminRolesFromEnv();

    expect(changed).toBe(1);
    expect((await users.findByEmail('root-admin@test.example')).role).toBe('admin');
  });

  it('testBanPreventsLoginAndUnbanRestores', async () => {
    const user = await makeUser('banme', 'banme@test.example', 'Password123');
    await users.setBanned(Number(user.id), true, 'test ban');

    // PHP called Auth::attemptLogin() against the global $_SESSION; the port
    // needs a request context, so the test supplies the stand-in (helpers/ctx).
    expect((await attemptLogin(fakeCtx(), 'banme@test.example', 'Password123', '127.1.1.1')).status).toBe('banned');

    await users.setBanned(Number(user.id), false, null);
    expect((await attemptLogin(fakeCtx(), 'banme@test.example', 'Password123', '127.1.1.1')).status).toBe('ok');
  });

  it('testAdminCannotBeBanned', async () => {
    const admin = await makeUser('the-admin', 'the-admin@test.example', 'Password12345', 'admin');

    await users.setBanned(Number(admin.id), true, 'attempt');

    expect(Number((await users.findById(Number(admin.id))).is_banned)).toBe(0);
  });

  it('testBoardLifecycle', async () => {
    const admin = await makeUser('board-admin', null, DEFAULT_PASSWORD, 'admin');

    const id = await boards.create('Lifecycle', 'desc', false, Number(admin.id));
    const created = await boards.find(id);
    expect(created).not.toBeNull();

    await boards.update(Number(created.id), 'Renamed', 'new desc', true);
    const renamed = await boards.find(Number(created.id));
    expect(renamed.name).toBe('Renamed');
    expect(Number(renamed.default_access)).toBe(1);

    await boards.softDelete(Number(created.id), Number(admin.id));
    expect(await boards.find(Number(created.id))).toBeNull();
  });

  it('testAccessListReflectsGrants', async () => {
    const admin = await makeUser('access-admin', null, DEFAULT_PASSWORD, 'admin');
    const boardId = await boards.create('ACL', '', false, Number(admin.id));
    const u1 = await makeUser('acl1');
    const u2 = await makeUser('acl2');

    await boards.grantAccess(boardId, Number(u1.id), Number(admin.id));
    await boards.grantAccess(boardId, Number(u2.id), Number(admin.id));

    const list = await boards.accessList(boardId);
    expect(list).toHaveLength(2);
    expect(list.map((a) => a.username).sort()).toEqual(['acl1', 'acl2']);
  });

  it('testMfaTogglePersists', async () => {
    const user = await makeUser('mfaflag');

    await users.setMfaEnabled(Number(user.id), true);
    expect(Number((await users.findById(Number(user.id))).mfa_enabled)).toBe(1);

    await users.setMfaEnabled(Number(user.id), false);
    expect(Number((await users.findById(Number(user.id))).mfa_enabled)).toBe(0);
  });

  it('testPasswordUpdateAndVerify', async () => {
    const user = await makeUser('pwchange', 'pwchange@test.example', 'OldPassword1');

    await users.updatePassword(Number(user.id), 'NewPassword99');

    const fresh = await users.findById(Number(user.id));
    expect(await verify('NewPassword99', fresh.password_hash)).toBe(true);
    expect(await verify('OldPassword1', fresh.password_hash)).toBe(false);
  });
});
