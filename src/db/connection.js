// Database access — port of src/Database.php (docs/01 section 3).
//
// Two hard rules, both pinned by control proofs in docs/03:
//   * C-SQL-1: every statement goes through query()/execute() with `?`
//     placeholders. No caller may build SQL text from user input.
//   * C-SQL-2: the pool is created with `multipleStatements: false` written
//     explicitly. mysql2's own default is already false, so an option that is
//     merely absent would prove nothing — and `vuln/sqli` flips this literal to
//     true, which is why it has to be here.
//
// Also per docs/07 section 10: `decimalNumbers` so numeric columns arrive as
// numbers (PDO parity) and `dateStrings` so DATETIME columns arrive as strings,
// exactly as PDO hands them to PHP. Both keep the ported tests honest.

import mysql from 'mysql2/promise';
import { get, int } from '../config/env.js';

let pool = null;

function poolConfig() {
  return {
    host: get('DB_HOST', '127.0.0.1'),
    port: int('DB_PORT', 3307),
    user: get('DB_USER', 'theboard'),
    password: get('DB_PASS', ''),
    database: get('DB_NAME', 'theboard_node'),
    charset: 'utf8mb4',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 10_000,
    multipleStatements: false,
    decimalNumbers: true,
    dateStrings: true,
    namedPlaceholders: false,
  };
}

/** The pool used by every repository and hook. */
export function getPool() {
  if (pool === null) pool = mysql.createPool(poolConfig());
  return pool;
}

/** A separate root connection for database creation (scripts and tests only). */
export async function createAdminConnection() {
  return mysql.createConnection({
    host: get('DB_HOST', '127.0.0.1'),
    port: int('DB_PORT', 3307),
    user: 'root',
    password: get('DB_ROOT_PASS', ''),
    charset: 'utf8mb4',
    connectTimeout: 10_000,
    multipleStatements: false,
    dateStrings: true,
  });
}

/**
 * Run a statement with placeholders and return rows.
 * Uses conn.query (client-side binding) — see docs/01 section 5: this is what
 * makes stacked statements observable at all when C-SQL-2 is downgraded,
 * instead of masking the class behind a server-side prepare error.
 */
export async function query(sql, params = []) {
  const [rows] = await getPool().query(sql, params);
  return rows;
}

/** Run a statement that changes rows; returns insertId/affectedRows. */
export async function execute(sql, params = []) {
  const [result] = await getPool().query(sql, params);
  return { insertId: result.insertId ?? 0, affectedRows: result.affectedRows ?? 0 };
}

/**
 * BEGIN / COMMIT / ROLLBACK around fn(conn). Pass the connection to the work so
 * it cannot accidentally use a pooled connection outside the transaction.
 */
export async function transaction(fn) {
  const conn = await getPool().getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn(conn);
    await conn.commit();
    return result;
  } catch (error) {
    try {
      await conn.rollback();
    } catch {
      /* rollback of an already-aborted transaction is not an error worth hiding */
    }
    throw error;
  } finally {
    conn.release();
  }
}

/** SELECT ... FOR UPDATE inside a transaction connection (C-RACE-1). */
export async function forUpdate(conn, sql, params = []) {
  const [rows] = await conn.query(`${sql} FOR UPDATE`, params);
  return rows[0] ?? null;
}

/** Drain and close the pool (tests, graceful shutdown). */
export async function close() {
  if (pool !== null) {
    const dying = pool;
    pool = null;
    await dying.end();
  }
}

/** Escape an identifier that comes from a fixed allowlist, never from input. */
export function ident(name) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`refusing to use identifier: ${name}`);
  }
  return `\`${name}\``;
}
