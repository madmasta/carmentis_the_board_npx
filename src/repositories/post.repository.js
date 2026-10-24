// Post/thread/reply data access — port of src/PostRepository.php.
//
// The discussion model is flat: a reply always points at the thread, never at
// another reply. Soft deletes are `deleted_at`, and every read filters on it.
//
// One deliberate signature change from PHP: `createThread`/`createReply` took an
// `&$errors` out-parameter. JS has no by-reference strings, so they return
// `{ postId, errors }` with `postId: null` on a validation failure — same
// information, one channel.
//
// C-SQL-1: statements are single literals with `?` placeholders. `LIMIT`/`OFFSET`
// are bound as placeholders too, and clamped to integers here so a page number
// from the query string can never reach SQL as text.

import { query, execute } from '../db/connection.js';
import { now, sqlDateTime } from '../lib/clock.js';
import * as validator from '../security/validator.js';

export const THREADS_PER_PAGE = 20;
export const REPLIES_PREVIEW = 3;

const SELECT_POST = 'SELECT p.*, u.username AS author_name, u.is_banned AS author_banned FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ? AND p.deleted_at IS NULL';
const SELECT_THREADS = 'SELECT p.id, p.board_id, p.parent_id, p.author_id, p.title, p.body, p.created_at, p.edited_at, u.username AS author_name, COALESCE((SELECT SUM(v.value) FROM votes v WHERE v.post_id = p.id), 0) AS score, (SELECT COUNT(*) FROM posts r WHERE r.parent_id = p.id AND r.deleted_at IS NULL) AS reply_count FROM posts p JOIN users u ON u.id = p.author_id WHERE p.board_id = ? AND p.parent_id IS NULL AND p.deleted_at IS NULL ORDER BY p.created_at DESC, p.id DESC LIMIT ? OFFSET ?';
const COUNT_THREADS = 'SELECT COUNT(*) AS n FROM posts WHERE board_id = ? AND parent_id IS NULL AND deleted_at IS NULL';
const SELECT_THREAD = 'SELECT p.*, u.username AS author_name, COALESCE((SELECT SUM(v.value) FROM votes v WHERE v.post_id = p.id), 0) AS score FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ? AND p.parent_id IS NULL AND p.deleted_at IS NULL';
const SELECT_REPLIES = 'SELECT p.*, u.username AS author_name, COALESCE((SELECT SUM(v.value) FROM votes v WHERE v.post_id = p.id), 0) AS score FROM posts p JOIN users u ON u.id = p.author_id WHERE p.parent_id = ? AND p.deleted_at IS NULL ORDER BY p.created_at ASC';
const SELECT_POST_WITH_AUTHOR = 'SELECT p.*, u.username AS author_name, b.name AS board_name FROM posts p JOIN users u ON u.id = p.author_id JOIN boards b ON b.id = p.board_id WHERE p.id = ? AND p.deleted_at IS NULL';
const SELECT_RECENT_POSTS = 'SELECT p.*, u.username AS author_name, b.name AS board_name FROM posts p JOIN users u ON u.id = p.author_id JOIN boards b ON b.id = p.board_id WHERE p.deleted_at IS NULL ORDER BY p.created_at DESC LIMIT ?';
const SELECT_RECENT_POSTS_INCLUDING_DELETED = 'SELECT p.*, u.username AS author_name, b.name AS board_name FROM posts p JOIN users u ON u.id = p.author_id JOIN boards b ON b.id = p.board_id ORDER BY p.created_at DESC LIMIT ?';
const SELECT_POSTS_BY_AUTHOR = 'SELECT p.*, b.name AS board_name, COALESCE((SELECT SUM(v.value) FROM votes v WHERE v.post_id = p.id), 0) AS score FROM posts p JOIN boards b ON b.id = p.board_id WHERE p.author_id = ? AND p.deleted_at IS NULL ORDER BY p.created_at DESC LIMIT ?';

function positiveInt(value, fallback, cap = 1000) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(Math.trunc(n), cap);
}

export async function find(id) {
  const rows = await query(SELECT_POST, [id]);
  return rows[0] ?? null;
}

/** Create a top-level thread. */
export async function createThread(boardId, authorId, title, body) {
  const errors = [...validator.postTitle(title), ...validator.messageBody(body)];
  if (errors.length > 0) return { postId: null, errors };

  const result = await execute('INSERT INTO posts (board_id, parent_id, author_id, title, body) VALUES (?, NULL, ?, ?, ?)', [
    boardId,
    authorId,
    String(title).trim(),
    body,
  ]);
  return { postId: Number(result.insertId), errors: [] };
}

export async function createReply(threadId, authorId, body) {
  const errors = validator.messageBody(body);
  if (errors.length > 0) return { postId: null, errors };

  const thread = await find(threadId);
  if (thread === null || thread.parent_id !== null) {
    return { postId: null, errors: ['Thread not found.'] };
  }

  // Replies are always attached to the thread (flat discussion model).
  const result = await execute('INSERT INTO posts (board_id, parent_id, author_id, title, body) VALUES (?, ?, ?, NULL, ?)', [
    Number(thread.board_id),
    Number(thread.id),
    authorId,
    String(body).trim(),
  ]);
  return { postId: Number(result.insertId), errors: [] };
}

export async function listThreads(boardId, page = 1, perPage = THREADS_PER_PAGE) {
  const limit = positiveInt(perPage, THREADS_PER_PAGE, 100);
  const safePage = positiveInt(page, 1, 10_000);
  const offset = (safePage - 1) * limit;
  return query(SELECT_THREADS, [boardId, limit, offset]);
}

export async function countThreads(boardId) {
  const rows = await query(COUNT_THREADS, [boardId]);
  return Number(rows[0]?.n ?? 0);
}

export async function getThread(threadId) {
  const rows = await query(SELECT_THREAD, [threadId]);
  return rows[0] ?? null;
}

export async function listReplies(threadId) {
  return query(SELECT_REPLIES, [threadId]);
}

export async function getPostWithAuthor(postId) {
  const rows = await query(SELECT_POST_WITH_AUTHOR, [postId]);
  return rows[0] ?? null;
}

/** Author edits their own post; an admin edits anything (C-ACL-3). */
export async function editPost(postId, editorId, editorIsAdmin, newBody) {
  if (validator.messageBody(newBody).length > 0) return false;

  const result = await execute(
    'UPDATE posts SET body = ?, edited_at = ? WHERE id = ? AND deleted_at IS NULL AND (? = 1 OR author_id = ?)',
    [String(newBody).trim(), sqlDateTime(now()), postId, editorIsAdmin ? 1 : 0, editorId],
  );
  return result.affectedRows > 0;
}

/** Soft delete — admins moderate any message (docs/02 B21). */
export async function deletePost(postId, deletedBy) {
  const result = await execute('UPDATE posts SET deleted_at = ?, deleted_by = ? WHERE id = ? AND deleted_at IS NULL', [
    sqlDateTime(now()),
    deletedBy,
    postId,
  ]);
  return result.affectedRows > 0;
}

/** Recent posts across all boards, for the moderation feed. */
export async function recentPosts(limit = 50, includeDeleted = false) {
  const capped = positiveInt(limit, 50, 500);
  return query(includeDeleted ? SELECT_RECENT_POSTS_INCLUDING_DELETED : SELECT_RECENT_POSTS, [capped]);
}

export async function listByAuthor(authorId, limit = 50) {
  return query(SELECT_POSTS_BY_AUTHOR, [authorId, positiveInt(limit, 50, 500)]);
}
