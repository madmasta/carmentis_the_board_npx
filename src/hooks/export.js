// Thread export (docs/02 section 7, docs/03 C-CMD-1).
//
// The formatter runs in this process. There is no shell, no `exec`, no command
// string, and no external binary at all — the format name selects one of two
// functions from a fixed map. `format` never reaches a path, a command or a
// template compiler; if a future feature ever needs an external program, the only
// permitted shape is a program name from an allowlist plus an argument array.

import { plain } from '../security/markup.js';

export const EXPORT_FORMATS = new Map([
  ['md', { contentType: 'text/markdown; charset=utf-8', render: renderMarkdown }],
  ['txt', { contentType: 'text/plain; charset=utf-8', render: renderText }],
]);

export const UNKNOWN_FORMAT = 'Unknown export format.';

/**
 * A message body or title, as text. BBCode markers are removed by `plain`, and
 * any HTML tag in the stored text is dropped here: the export is a text file, so
 * angle brackets from a message are not passed through to a renderer that a user
 * might open it with.
 */
function toText(value) {
  return plain(String(value ?? '').replace(/<[^>]*>/g, ' '));
}

function header(thread) {
  return {
    title: toText(thread.title) || '(untitled)',
    board: toText(thread.board_name ?? ''),
    author: toText(thread.author_name ?? 'unknown'),
    created: String(thread.created_at ?? ''),
  };
}

function renderMarkdown(thread, replies) {
  const meta = header(thread);
  const lines = [`# ${meta.title}`, '', `Board: ${meta.board} · Started by ${meta.author} on ${meta.created}`, ''];
  lines.push(toText(thread.body), '');

  replies.forEach((reply, index) => {
    lines.push(`---`, '', `## Reply ${index + 1} — ${toText(reply.author_name) || 'unknown'} (${reply.created_at ?? ''})`, '');
    lines.push(toText(reply.body), '');
  });

  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;
}

function renderText(thread, replies) {
  const meta = header(thread);
  const rule = '='.repeat(72);
  const parts = [
    rule,
    meta.title,
    rule,
    `Board: ${meta.board}`,
    `Started by ${meta.author} on ${meta.created}`,
    '',
    toText(thread.body),
    '',
  ];

  replies.forEach((reply, index) => {
    parts.push(
      '-'.repeat(72),
      `Reply ${index + 1}: ${toText(reply.author_name) || 'unknown'} on ${reply.created_at ?? ''}`,
      '',
      toText(reply.body),
      '',
    );
  });

  return `${parts.join('\n')}\n`;
}

/**
 * Build the export. `format` is looked up in EXPORT_FORMATS; anything else is a
 * 400-level answer from the controller, and the value is never used as a
 * filename, path or argument.
 */
export function exportThread(thread, replies = [], format = 'txt') {
  const chosen = EXPORT_FORMATS.get(String(format));
  if (chosen === undefined) return { ok: false, message: UNKNOWN_FORMAT };

  return {
    ok: true,
    contentType: chosen.contentType,
    filename: `thread-${Number(thread.id)}.${String(format) === 'md' ? 'md' : 'txt'}`,
    body: chosen.render(thread, replies),
  };
}
