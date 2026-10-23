#!/usr/bin/env node
// Reset the application to a clean state — port of bin/reset.php.
//
// Usage (same flags as the PHP script):
//   npm run db:reset                    # asks for confirmation first
//   npm run db:reset -- --force         # no prompt (scripted use)
//   npm run db:reset -- --keep-mail-log # leave var/log/mail.log alone
//   npm run db:reset -- --no-test-data  # bare install: admins only, no test data
//   npm run db:reset -- --test-db       # also rebuild <DB_NAME>_test

import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { load, get, list } from '../src/config/env.js';
import {
  adminConnection,
  applySchema,
  createDatabase,
  dropDatabase,
  root,
  schemaStatements,
  tableCounts,
} from '../src/db/admin.js';
import { close } from '../src/db/connection.js';

// Seed scripts that a later milestone has not implemented yet exit with this
// code; the reset then reports the skip instead of failing the scaffold gate.
const NOT_IMPLEMENTED = 3;

const args = process.argv.slice(2);
const force = args.includes('--force') || args.includes('--yes');
const keepMailLog = args.includes('--keep-mail-log');
const testData = !args.includes('--no-test-data');
const alsoTestDb = args.includes('--test-db');

const envFile = join(root(), '.env');
if (!existsSync(envFile)) {
  console.error(`No .env in ${root()} — copy .env.example to .env first.`);
  process.exit(1);
}
load(envFile);

const host = get('DB_HOST', '127.0.0.1');
const port = get('DB_PORT', '3307');
const dbName = get('DB_NAME', 'theboard_node');
const dbUser = get('DB_USER', '');
const dbPass = get('DB_PASS', '');
const statements = schemaStatements();

if (!force) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question(
    `This DESTROYS every row in \`${dbName}\` on ${host}:${port} (users, boards, posts, votes).\nType 'reset' to continue: `,
  )).toLowerCase().trim();
  await rl.close();
  if (answer !== 'reset') {
    console.log('Aborted, nothing was changed.');
    process.exit(1);
  }
}

let conn;
try {
  conn = await adminConnection();
  await dropDatabase(conn, dbName);
  await createDatabase(conn, dbName);
  console.log(`Dropped and recreated database \`${dbName}\`.`);
} catch (error) {
  // No usable root credentials: fall back to dropping the application user's own
  // tables, exactly like the PHP script does.
  console.log(`Root reset unavailable (${error.message}).\nFalling back to dropping tables as '${dbUser}'.`);
  const mysql = (await import('mysql2/promise')).default;
  conn = await mysql.createConnection({
    host,
    port: Number(port),
    user: dbUser,
    password: dbPass,
    database: dbName,
    charset: 'utf8mb4',
    multipleStatements: false,
  });
  const [rows] = await conn.query('SHOW TABLES');
  const tables = rows.flatMap((row) => Object.values(row));
  await conn.query('SET FOREIGN_KEY_CHECKS = 0');
  for (const table of tables) await conn.query(`DROP TABLE IF EXISTS \`${table.replaceAll('`', '')}\``);
  await conn.query('SET FOREIGN_KEY_CHECKS = 1');
  console.log(`Dropped ${tables.length} table(s) in \`${dbName}\`.`);
}

if (!keepMailLog) {
  const mailLog = process.env.MAIL_LOG ?? join(root(), 'var', 'log', 'mail.log');
  if (existsSync(mailLog)) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(mailLog, '');
    console.log('Cleared var/log/mail.log.');
  }
}

console.log('Applying schema and seeding admins...');
await applySchema(conn, dbName, statements);

function runScript(name) {
  const result = spawnSync(process.execPath, [join(root(), 'scripts', name)], {
    stdio: 'inherit',
    env: process.env,
  });
  if (result.status === NOT_IMPLEMENTED) {
    console.log(`${name}: skipped (milestone not implemented yet).`);
    return 0;
  }
  return result.status ?? 1;
}

let status = runScript('seed-admins.mjs');
if (status !== 0) {
  console.error(`Seeding failed (exit ${status}).`);
  await conn.end();
  await close();
  process.exit(status);
}

if (testData) {
  status = runScript('seed-test-data.mjs');
  if (status !== 0) {
    console.error(`Test data seeding failed (exit ${status}).`);
    await conn.end();
    await close();
    process.exit(status);
  }
}

if (alsoTestDb) {
  const testDb = `${dbName}_test`;
  await dropDatabase(conn, testDb);
  await createDatabase(conn, testDb);
  await applySchema(conn, testDb, statements);
  console.log(`Rebuilt test database \`${testDb}\`.`);
}

const counts = await tableCounts(conn, dbName);
await conn.end();
await close();

console.log(`\nReset complete. Admins from .env: ${list('ADMIN_EMAILS').join(', ') || '(none)'}`);
if (!testData) console.log('Test data was skipped (--no-test-data).');
console.log('Row counts:');
for (const [table, n] of Object.entries(counts)) console.log(`  ${table.padEnd(16)} ${n}`);
