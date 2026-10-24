// C-CMD-1 proof file (docs/03): the export is in-process, the format name is a
// map key, and this module contains no shell surface at all.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { root } from '../../src/db/admin.js';
import { EXPORT_FORMATS, UNKNOWN_FORMAT, exportThread } from '../../src/hooks/export.js';

const THREAD = {
  id: 12,
  title: 'Release notes <b>2.0</b>',
  body: 'Ships [b]faster[/b] parsing and <script>alert(1)</script>',
  board_name: 'General',
  author_name: 'alice',
  created_at: '2024-05-05 10:00:00',
};

const REPLIES = [
  { id: 13, body: 'Nice [i]work[/i]', author_name: "bob's", created_at: '2024-05-05 11:00:00' },
  { id: 14, body: 'Second reply', author_name: 'carol', created_at: '2024-05-05 12:00:00' },
];

describe('thread export (C-CMD-1)', () => {
  it('the format allowlist is exactly md and txt', () => {
    expect([...EXPORT_FORMATS.keys()]).toEqual(['md', 'txt']);
  });

  it('renders markdown in process', () => {
    const result = exportThread(THREAD, REPLIES, 'md');

    expect(result.ok).toBe(true);
    expect(result.contentType).toBe('text/markdown; charset=utf-8');
    expect(result.body).toContain('# Release notes 2.0');
    // Markup becomes text; nothing from the post is emitted as markup.
    expect(result.body).toContain('faster parsing');
    expect(result.body).not.toContain('<script>');
    expect(result.body).not.toContain('<b>');
    expect(result.body).toContain('## Reply 1 — bob');
    expect(result.body).toContain('## Reply 2 — carol');
  });

  it('renders plain text', () => {
    const result = exportThread(THREAD, REPLIES, 'txt');

    expect(result.ok).toBe(true);
    expect(result.contentType).toBe('text/plain; charset=utf-8');
    expect(result.body).toContain('Release notes 2.0');
    expect(result.body).not.toContain('<script>');
    expect(result.body).toContain('Reply 1: bob');
    expect(result.body).toContain('-'.repeat(72));
  });

  it('c-cmd-1 an unknown format is refused, not interpolated anywhere', () => {
    for (const format of ['', 'html', 'md; rm -rf /', '$(id)', '..\\..\\windows', '`id`']) {
      const result = exportThread(THREAD, REPLIES, format);
      expect(result).toEqual({ ok: false, message: UNKNOWN_FORMAT });
    }
  });

  it('c-cmd-1 the export module never names a shell or a child process', () => {
    const source = readFileSync(join(root(), 'src', 'hooks', 'export.js'), 'utf8');

    for (const banned of ['child_process', 'execSync', 'exec(', 'spawn(', 'spawnSync', 'shell:', 'execFile', 'eval(', 'new Function']) {
      expect(source).not.toContain(banned);
    }
    // No import other than the markup renderer.
    expect(source.match(/^import .*$/gm)).toHaveLength(1);
  });

  it('the filename is built from the post id, never the request', () => {
    expect(exportThread(THREAD, [], 'md').filename).toBe('thread-12.md');
    expect(exportThread(THREAD, [], 'txt').filename).toBe('thread-12.txt');
  });
});
