// Test database access — the Node equivalent of tests/bootstrap.php (docs/04
// section 2). Importing this module is what points the app at the test database:
// it loads .env, then forces DB_NAME to `<DB_NAME>_test`, because a real
// environment variable outranks the file in src/config/env.js (same precedence
// the PHP bootstrap relies on when phpunit.xml sets DB_NAME).
//
// The helpers deliberately bypass the repository layer and apply no field
// filtering: an exploit test must be able to read columns the application never
// renders (users.password_hash) as the oracle for a data-leak assertion.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import mysql from 'mysql2/promise';
import { load, get } from '../../src/config/env.js';
import {
  adminConnection,
  applySchema,
  createDatabase,
  dropDatabase,
  root,
  schemaStatements,
} from '../../src/db/admin.js';

const envFile = join(root(), '.env');
if (!existsSync(envFile)) {
  throw new Error(
    `test/helpers/db.mjs: no .env in ${root()} — copy .env.example to .env before running the suite`,
  );
}
load(envFile);

// Deriving from a value this same module exports would double the suffix when
// vitest re-evaluates the module graph with process.env already pinned, so a
// trailing `_test` is stripped before it is appended again.
const devDbName = get('DB_NAME', 'theboard_node').replace(/_test$/, '');
export const testDatabase = `${devDbName}_test`;
process.env.DB_NAME = testDatabase;

let conn = null;

async function connect() {
  if (conn === null) {
    conn = await mysql.createConnection({
      host: get('DB_HOST', '127.0.0.1'),
      port: Number(get('DB_PORT', '3307')),
      user: get('DB_USER', 'theboard'),
      password: get('DB_PASS', ''),
      database: testDatabase,
      charset: 'utf8mb4',
      multipleStatements: false,
      decimalNumbers: true,
      dateStrings: true,
      connectTimeout: 10_000,
    });
    await conn.query("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'");
  }
  return conn;
}

/** Drop + recreate the test database and apply schema.sql (once per run). */
export async function bootstrapTestDatabase() {
  const admin = await adminConnection();
  await dropDatabase(admin, testDatabase);
  await createDatabase(admin, testDatabase);
  await applySchema(admin, testDatabase, schemaStatements());
  await admin.end();
  if (conn !== null) {
    await conn.end();
    conn = null;
  }
  return testDatabase;
}

/** Raw statement with placeholders; returns the row array. */
export async function query(sql, params = []) {
  const [rows] = await (await connect()).query(sql, params);
  return rows;
}

export async function rows(sql, params = []) {
  return query(sql, params);
}

/** First row or null. */
export async function row(sql, params = []) {
  const found = await query(sql, params);
  return found[0] ?? null;
}

/** Count helper for `SELECT COUNT(*) AS n ...` probes. */
export async function count(sql, params = []) {
  const found = await query(sql, params);
  const first = found[0] ?? {};
  const value = Object.values(first)[0] ?? 0;
  return Number(value);
}

export async function insert(sql, params = []) {
  const [result] = await (await connect()).query(sql, params);
  return { insertId: result.insertId ?? 0, affectedRows: result.affectedRows ?? 0 };
}

/** Delete every row in the app tables, keeping schema and fixtures optional. */
export async function truncateAll() {
  await query('SET FOREIGN_KEY_CHECKS = 0');
  for (const table of [
    'votes',
    'posts',
    'board_access',
    'boards',
    'login_attempts',
    'mfa_codes',
    'sessions',
    'jwt_claims',
    'users',
  ]) {
    await query(`TRUNCATE TABLE \`${table}\``);
  }
  await query('SET FOREIGN_KEY_CHECKS = 1');
}

export async function closeDb() {
  if (conn !== null) {
    await conn.end();
    conn = null;
  }
}
