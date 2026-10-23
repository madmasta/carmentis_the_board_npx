// Password hashing — port of PHP's password_hash()/password_verify()
// (docs/07 section 6).
//
// PHP's PASSWORD_DEFAULT is bcrypt at cost 10, so the port uses bcrypt at cost
// 10 as well. One unavoidable difference: PHP writes `$2y$` identifiers and
// bcryptjs writes `$2b$`. Both are the same algorithm and bcryptjs verifies
// `$2y` hashes, so a hash string copied from the PHP target still checks out —
// which is what the fixture port and the `cryptographic_failures` sheet rely on.

import bcrypt from 'bcryptjs';

/** PASSWORD_DEFAULT cost in PHP 8.3. */
export const BCRYPT_COST = 10;

/**
 * The dummy hash PHP verifies against when the account does not exist, so an
 * unknown email takes the same time as a real check. Copied verbatim from
 * `src/Auth.php` — the `cryptographic_failures` and timing probes assume the
 * cost is the same as a normal hash.
 */
export const TIMING_EQUALIZER_HASH = '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';

export async function hash(plain) {
  return bcrypt.hash(String(plain), BCRYPT_COST);
}

/** False for a malformed or empty hash rather than an exception. */
export async function verify(plain, hashed) {
  if (typeof hashed !== 'string' || hashed === '') return false;
  try {
    return await bcrypt.compare(String(plain ?? ''), hashed);
  } catch {
    return false;
  }
}

/** Burn one hash-comparison's worth of time for a non-existent account. */
export async function fakeVerify(plain) {
  return verify(plain, TIMING_EQUALIZER_HASH);
}
