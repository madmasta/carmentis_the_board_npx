// Database provisioning helpers: create/drop a database and apply schema.sql.
// Used by scripts/reset.mjs and test/helpers/db.mjs, so the dev database and the
// test database are always built the same way (docs/04 section 2).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createAdminConnection } from './connection.js';
import { get } from '../config/env.js';

const ROOT = process.env.THEBOARD_ROOT ?? process.cwd();

export function root() {
  return ROOT;
}

export function schemaPath() {
  return join(ROOT, 'schema.sql');
}

/** Strip `--` comment lines and split on semicolons, like the PHP bootstrap. */
export function schemaStatements(text = readFileSync(schemaPath(), 'utf8')) {
  const stripped = text
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n');
  return stripped
    .split(';')
    .map((statement) => statement.trim())
    .filter((statement) => statement !== '');
}

function safe(name) {
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`unsafe database name: ${name}`);
  return name;
}

/** Connect as root with no database selected. */
export async function adminConnection() {
  return createAdminConnection();
}

export async function dropDatabase(conn, name) {
  await conn.query(`DROP DATABASE IF EXISTS \`${safe(name)}\``);
}

export async function createDatabase(conn, name, { grantTo = get('DB_USER', 'theboard') } = {}) {
  await conn.query(
    `CREATE DATABASE \`${safe(name)}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
  );
  // The container only pre-grants the database named in MARIADB_DATABASE, so a
  // freshly created dev or test database would be invisible to the app user.
  if (/^[A-Za-z0-9_]+$/.test(grantTo)) {
    await conn.query(`GRANT ALL PRIVILEGES ON \`${safe(name)}\`.* TO '${grantTo}'@'%'`);
    await conn.query('FLUSH PRIVILEGES');
  }
}

/**
 * Apply schema.sql to a database. FOREIGN_KEY_CHECKS is off while the DDL runs
 * and restored afterwards, matching the PHP test bootstrap's intent without
 * relying on statement order.
 */
export async function applySchema(conn, database, statements = schemaStatements()) {
  await conn.query(`USE \`${safe(database)}\``);
  await conn.query("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'");
  await conn.query('SET FOREIGN_KEY_CHECKS = 0');
  try {
    for (const statement of statements) await conn.query(statement);
  } finally {
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
  }
}

/** Row counts for every table in the current database, in a stable order. */
export async function tableCounts(conn, database) {
  await conn.query(`USE \`${safe(database)}\``);
  const [rows] = await conn.query(
    'SELECT TABLE_NAME AS name FROM information_schema.TABLES ' +
      'WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME',
    [database],
  );
  const counts = {};
  for (const row of rows) {
    const [[{ n }]] = await conn.query(
      `SELECT COUNT(*) AS n FROM \`${safe(database)}\`.\`${row.name.replaceAll('`', '')}\``,
    );
    counts[row.name] = Number(n);
  }
  return counts;
}

export const TABLES = [
  'users',
  'boards',
  'board_access',
  'posts',
  'votes',
  'login_attempts',
  'mfa_codes',
  'sessions',
];
