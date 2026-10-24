// C-SQL-2 — driver hardening (docs/03, "SQL / data layer").
//
// The option has to be *written down*: mysql2 already defaults
// `multipleStatements` to false, so an absent option proves nothing about intent
// and the `sqli` branch has to flip it to true on purpose.

import { afterAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root } from '../../src/db/admin.js';
import { close, query } from '../../src/db/connection.js';

const SOURCE = readFileSync(join(root(), 'src', 'db', 'connection.js'), 'utf8');

afterAll(async () => {
  await close();
});

describe('c-sql-2 driver hardening', () => {
  it('c-sql-2 the pool config states multipleStatements: false explicitly', () => {
    expect(SOURCE).toMatch(/multipleStatements:\s*false/);
    expect(SOURCE).toMatch(/connectTimeout:\s*\d+/);
  });

  it('c-sql-2 named placeholders are off, so a placeholder typo cannot smuggle text', () => {
    expect(SOURCE).toMatch(/namedPlaceholders:\s*false/);
  });

  it('c-sql-2 statements go through query(), the client-side binding path', () => {
    // execute() prepares server-side and would mask stacked statements behind a
    // prepare error instead of showing the class.
    expect(SOURCE).toContain('getPool().query(sql, params)');
    expect(SOURCE).not.toContain('getPool().execute(');
  });

  it('c-sql-2 a two-statement string is refused by the driver', async () => {
    await expect(query('SELECT 1; SELECT 2')).rejects.toThrow();
  });

  it('c-sql-2 a stacked payload bound as a parameter is one harmless string', async () => {
    const rows = await query('SELECT COUNT(*) AS n FROM users WHERE email = ?', ["x'@y'; DROP TABLE users; -- -"]);
    expect(Number(rows[0].n)).toBe(0);
    const stillThere = await query('SELECT COUNT(*) AS n FROM users');
    expect(Number(stillThere[0].n)).toBeGreaterThanOrEqual(0);
  });
});
