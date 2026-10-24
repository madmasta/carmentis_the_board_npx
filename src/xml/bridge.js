// The XML a board exports, and the importer that reads it back
// (docs/02 section 7, docs/03 C-XML-1, C-XSS-1).
//
// The envelope is this app's own, with a schema attribute; the importer refuses
// anything else before it looks inside. Text is written escaped and read back as
// text: an exported `<script>` stays a message, and an imported one is put
// through the same validator and renderer as a form post would be.

import { MAX_XML_BYTES, XmlError, child, children, parse } from './reader.js';
import { query } from '../db/connection.js';
import { sqlDateTime } from '../lib/clock.js';

export const EXPORT_SCHEMA = 'theboard-board-export/1';
export const MAX_IMPORT_BYTES = MAX_XML_BYTES;
export const IMPORT_REJECTED = 'That file could not be imported.';

const escape = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

/** Build the export document for a board (threads with their replies). */
export async function exportBoard(boardId) {
  const boards = await query('SELECT id, name, description FROM boards WHERE id = ? AND deleted_at IS NULL', [boardId]);
  if (boards.length === 0) return null;
  const board = boards[0];

  const threads = await query(
    `SELECT id, title, body, author_id, created_at
       FROM posts
      WHERE board_id = ? AND parent_id IS NULL AND deleted_at IS NULL
      ORDER BY id ASC`,
    [boardId],
  );

  const blocks = [];
  for (const thread of threads) {
    const replies = await query(
      `SELECT id, body, author_id, created_at
         FROM posts
        WHERE parent_id = ? AND deleted_at IS NULL
        ORDER BY id ASC`,
      [thread.id],
    );

    blocks.push(
      `  <thread id="${thread.id}" title="${escape(thread.title)}">\n` +
        `    <post author_id="${thread.author_id}" created_at="${escape(thread.created_at)}">${escape(thread.body)}</post>\n` +
        replies
          .map(
            (reply) =>
              `    <reply id="${reply.id}" author_id="${reply.author_id}" created_at="${escape(reply.created_at)}">${escape(reply.body)}</reply>`,
          )
          .join('\n') +
        '\n  </thread>',
    );
  }

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<board-export schema="${EXPORT_SCHEMA}" board_id="${Number(board.id)}" exported_at="${sqlDateTime(new Date())}">`,
    blocks.join('\n'),
    '</board-export>',
    '',
  ].join('\n');
}

/**
 * Read an exported board back. Returns `{ ok: true, threads }` where each thread
 * is `{ title, body, replies: [body] }` — plain text that the caller still sends
 * through the post validator and the renderer — or `{ ok: false, message }`.
 */
export function importBoard(input, boardId) {
  let doc;
  try {
    doc = parse(input, { maxBytes: MAX_IMPORT_BYTES });
  } catch (error) {
    return { ok: false, message: IMPORT_REJECTED, reason: error instanceof XmlError ? error.message : 'unreadable' };
  }

  const root = doc.children[0];
  if (root === undefined || root.tag !== 'board-export') return { ok: false, message: IMPORT_REJECTED, reason: 'not the app envelope' };
  if (root.attrs.schema !== EXPORT_SCHEMA) return { ok: false, message: IMPORT_REJECTED, reason: 'unknown schema' };
  if (Number(root.attrs.board_id) !== Number(boardId)) return { ok: false, message: IMPORT_REJECTED, reason: 'another board' };

  const threads = children(root, 'thread').map((thread) => {
    const first = child(thread, 'post');
    return {
      title: String(thread.attrs.title ?? '').trim(),
      body: String(first?.text ?? '').trim(),
      replies: children(thread, 'reply').map((reply) => String(reply.text ?? '').trim()),
    };
  });

  return { ok: true, threads };
}
