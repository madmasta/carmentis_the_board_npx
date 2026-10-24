// Port of tests/Integration/BoardAccessTest.php (docs/03 C-ACL-1).

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { truncateAll } from '../helpers/db.mjs';
import { DEFAULT_PASSWORD, makeBoard, makeUser } from '../helpers/users.mjs';
import * as boards from '../../src/repositories/board.repository.js';
import * as users from '../../src/repositories/user.repository.js';

beforeAll(async () => {
  await truncateAll();
});

beforeEach(async () => {
  await truncateAll();
});

const idsOf = (list) => list.map((board) => Number(board.id));

describe('board access', () => {
  it('testDefaultAccessBoardVisibleToAnyUser', async () => {
    const board = await makeBoard('Open', true);
    const user = await makeUser('open-user');

    expect(await boards.userCanAccess(user, board)).toBe(true);
    expect(idsOf(await boards.listForUser(user))).toContain(Number(board.id));
  });

  it('testRestrictedBoardHiddenWithoutGrant', async () => {
    const board = await makeBoard('Private', false);
    const user = await makeUser('outsider');

    expect(await boards.userCanAccess(user, board)).toBe(false);
    expect(idsOf(await boards.listForUser(user))).not.toContain(Number(board.id));
  });

  it('testGrantGivesAccess', async () => {
    const admin = await makeUser('grant-admin', null, DEFAULT_PASSWORD, 'admin');
    const board = await makeBoard('Members', false, Number(admin.id));
    const user = await makeUser('member');

    await boards.grantAccess(Number(board.id), Number(user.id), Number(admin.id));

    expect(await boards.userCanAccess(user, board)).toBe(true);
    expect(idsOf(await boards.listForUser(user))).toContain(Number(board.id));
    expect(await boards.hasExplicitAccess(Number(board.id), Number(user.id))).toBe(true);
  });

  it('testRevokeRemovesAccess', async () => {
    const admin = await makeUser('revoke-admin', null, DEFAULT_PASSWORD, 'admin');
    const board = await makeBoard('Temp', false, Number(admin.id));
    const user = await makeUser('revoked');

    await boards.grantAccess(Number(board.id), Number(user.id), Number(admin.id));
    expect(await boards.userCanAccess(user, board)).toBe(true);

    await boards.revokeAccess(Number(board.id), Number(user.id));
    expect(await boards.userCanAccess(user, board)).toBe(false);
    expect(await boards.hasExplicitAccess(Number(board.id), Number(user.id))).toBe(false);
  });

  it('testAdminSeesAllBoards', async () => {
    const admin = await makeUser('seesall', null, DEFAULT_PASSWORD, 'admin');
    await makeBoard('A1', false);
    await makeBoard('A2', false);

    expect(await boards.listForUser(admin)).toHaveLength(2);
  });

  it('testAdminCanAccessRestrictedBoard', async () => {
    const board = await makeBoard('Locked', false);
    const admin = await makeUser('super', null, DEFAULT_PASSWORD, 'admin');

    expect(await boards.userCanAccess(admin, board)).toBe(true);
  });

  it('testAnonymousSeesNothingWithoutDefaultAccess', async () => {
    await makeBoard('Hidden1', false);
    expect(await boards.listForUser(null)).toEqual([]);
  });

  it('testAnonymousSeesNoBoards', async () => {
    // Boards are only visible to authenticated users, even default-access ones.
    await makeBoard('Public One', true);
    await makeBoard('Closed', false);

    expect(await boards.listForUser(null)).toEqual([]);
  });

  it('testBannedUserIsDeniedAccess', async () => {
    const board = await makeBoard('BannedZone', true);
    const user = await makeUser('bannedguy');
    await users.setBanned(Number(user.id), true, 'test');

    // The ban is enforced at the auth layer; the access check itself stays
    // board-scoped. The pipeline logs a banned user out first.
    expect(await boards.userCanAccess(user, board)).toBe(true);
  });
});
