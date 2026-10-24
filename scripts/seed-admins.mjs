#!/usr/bin/env node
// Provision the admin accounts named in ADMIN_EMAILS — port of bin/seed-admins.php.
//
//   node scripts/seed-admins.mjs                    # provision missing admins
//   node scripts/seed-admins.mjs --reset-passwords  # also reset existing admin passwords
//
// Behaviour pinned by the PHP original (docs/02 section 6):
//   * existing users with those emails are promoted to admin
//   * missing accounts are created with ADMIN_PASSWORD, or with a random
//     password printed exactly once
//   * the username is 'admin' + first 6 hex chars of md5(email), made unique by
//     appending a random 3-digit suffix
//   * ADMIN_PASSWORD that fails the password policy is still used, but warns

import { existsSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { get, list, load } from '../src/config/env.js';
import { adminConnection, applySchema, root, schemaStatements } from '../src/db/admin.js';
import { close } from '../src/db/connection.js';
import * as users from '../src/repositories/user.repository.js';
import * as validator from '../src/security/validator.js';

const args = process.argv.slice(2);

if (existsSync(`${root()}/.env`)) load(`${root()}/.env`);

// The PHP script applies schema.sql itself so it can run against an empty
// database; reset.mjs has already done so, and re-running is harmless (CREATE
// TABLE IF NOT EXISTS).
try {
  const conn = await adminConnection();
  await applySchema(conn, get('DB_NAME', 'theboard_node'), schemaStatements());
  // An admin connection is standalone, not pooled: leaving it open keeps the
  // process alive after the work is done.
  await conn.end();
} catch (error) {
  // The application user may lack CREATE DATABASE rights; the tables already
  // exist in that path, so carry on and let the repository calls decide.
  console.log(`schema step skipped: ${error.message}`);
}

await users.ensureAdminRolesFromEnv();

const resetPasswords = args.includes('--reset-passwords');
let password = String(get('ADMIN_PASSWORD', '') ?? '');

if (password !== '' && validator.password(password).length > 0) {
  console.error(
    `WARNING: ADMIN_PASSWORD in .env does not meet the password policy (min ${validator.passwordMinLength()} chars, letter + number). Resetting anyway.`,
  );
}

for (const email of list('ADMIN_EMAILS')) {
  const existing = await users.findByEmail(email);

  if (existing === null) {
    if (password === '') {
      password = randomBytes(9).toString('hex');
      console.log(`Generated password for ${email}: ${password}`);
    }
    const base = `admin${createHash('md5').update(email).digest('hex').slice(0, 6)}`;
    let username = base;
    for (let i = 0; (await users.findByUsername(username)) !== null; i += 1) {
      username = `${base}${100 + Math.floor(Math.random() * 900)}`;
      void i;
    }
    await users.create(username, email, password);
    console.log(`Created admin account for ${email}`);
    continue;
  }

  if (resetPasswords) {
    const newPassword = password !== '' ? password : randomBytes(9).toString('hex');
    await users.updatePassword(Number(existing.id), newPassword);
    console.log(password === '' ? `Generated password for ${email}: ${newPassword}` : `Password reset from .env for ${email}`);
  } else {
    console.log(`Admin ${email} exists (id ${existing.id}).`);
  }
}

// Second pass: accounts created just now pick up the admin role from ADMIN_EMAILS.
await users.ensureAdminRolesFromEnv();
console.log('Admin provisioning complete.');

await close();
