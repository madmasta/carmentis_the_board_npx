// Board data access and the single ACL choke point — port of
// src/BoardRepository.php (docs/03 C-ACL-1, C-ACL-2).
//
// C-SQL-1: one literal per statement, `?` placeholders only, no fragments.
// C-ACL-1: `userCanAccess` is the only access decision for board content; every
// board-facing controller calls it after loading the row, and a denial is a 404.

import { query, execute } from '../db/connection.js';
import { now, sqlDateTime } from '../lib/clock.js';

const SELECT_BOARD = 'SELECT b.*, u.username AS creator_name FROM boards b LEFT JOIN users u ON u.id = b.created_by WHERE b.id = ? AND b.deleted_at IS NULL';
const SELECT_BOARDS_ALL = 'SELECT b.*, u.username AS creator_name, (SELECT COUNT(*) FROM posts p WHERE p.board_id = b.id AND p.parent_id IS NULL AND p.deleted_at IS NULL) AS thread_count FROM boards b LEFT JOIN users u ON u.id = b.created_by WHERE b.deleted_at IS NULL ORDER BY b.name ASC';
const SELECT_BOARDS_FOR_USER = 'SELECT b.*, (SELECT COUNT(*) FROM posts p WHERE p.board_id = b.id AND p.parent_id IS NULL AND p.deleted_at IS NULL) AS thread_count FROM boards b WHERE b.deleted_at IS NULL AND (b.default_access = 1 OR b.id IN (SELECT board_id FROM board_access WHERE user_id = ?)) ORDER BY b.name';
const SELECT_EXPLICIT_ACCESS = 'SELECT COUNT(*) AS n FROM board_access WHERE board_id = ? AND user_id = ?';
const SELECT_ACCESS_LIST = 'SELECT u.id, u.username, u.email, u.role, u.is_banned, ba.granted_at FROM board_access ba JOIN users u ON u.id = ba.user_id WHERE ba.board_id = ? ORDER BY u.username';

export async function find(id) {
  const rows = await query(SELECT_BOARD, [id]);
  return rows[0] ?? null;
}

export async function create(name, description, defaultAccess, createdBy) {
  const result = await execute('INSERT INTO boards (name, description, default_access, created_by) VALUES (?, ?, ?, ?)', [
    String(name).trim(),
    String(description).trim(),
    defaultAccess ? 1 : 0,
    createdBy,
  ]);
  return Number(result.insertId);
}

export async function update(id, name, description, defaultAccess) {
  await execute('UPDATE boards SET name = ?, description = ?, default_access = ? WHERE id = ?', [
    String(name).trim(),
    String(description).trim(),
    defaultAccess ? 1 : 0,
    id,
  ]);
}

export async function softDelete(id, deletedBy) {
  await execute('UPDATE boards SET deleted_at = ?, deleted_by = ? WHERE id = ? AND deleted_at IS NULL', [
    sqlDateTime(now()),
    deletedBy,
    id,
  ]);
}

export async function listAll() {
  return query(SELECT_BOARDS_ALL);
}

/**
 * Boards visible to a user: default-access boards, explicitly granted boards,
 * and everything for an admin. Anonymous visitors see nothing — login is the
 * gate for the whole board area (docs/02 B16).
 */
export async function listForUser(user) {
  if (user === null || user === undefined) return [];
  if (user.role === 'admin') return listAll();
  return query(SELECT_BOARDS_FOR_USER, [Number(user.id)]);
}

/** The ACL choke point (C-ACL-1). A denial is a 404 in every caller. */
export async function userCanAccess(user, board) {
  if (board.deleted_at !== null) return false;
  if (user === null || user === undefined) return false;
  if (user.role === 'admin') return true;
  if (Number(board.default_access) === 1) return true;
  return hasExplicitAccess(Number(board.id), Number(user.id));
}

export async function hasExplicitAccess(boardId, userId) {
  const rows = await query(SELECT_EXPLICIT_ACCESS, [boardId, userId]);
  return Number(rows[0]?.n ?? 0) > 0;
}

export async function grantAccess(boardId, userId, grantedBy) {
  await execute('INSERT IGNORE INTO board_access (board_id, user_id, granted_by) VALUES (?, ?, ?)', [
    boardId,
    userId,
    grantedBy,
  ]);
}

export async function revokeAccess(boardId, userId) {
  await execute('DELETE FROM board_access WHERE board_id = ? AND user_id = ?', [boardId, userId]);
}

/** Users with explicit access to a board (admin board detail page). */
export async function accessList(boardId) {
  return query(SELECT_ACCESS_LIST, [boardId]);
}
