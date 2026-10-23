// The only time source in the app (docs/01 section 5, docs/07 section 10).
//
// PHP uses NOW() server-side; the Node port sends timestamps produced here so a
// test can move the clock instead of sleeping or mutating rows behind the app's
// back. Moving the clock is also how the ported OTP-expiry and throttle-window
// cases work, which is what proves the TTL logic is real.

let clockFn = null;

export function now() {
  return clockFn ? clockFn() : new Date();
}

export function nowMs() {
  return now().getTime();
}

/**
 * Timestamp string for DATETIME/TIMESTAMP columns, in the format MariaDB wants.
 *
 * UTC components, because the database is UTC: the PHP target ran inside a UTC
 * container, so `NOW()`, `CURRENT_TIMESTAMP` and PHP's `date()` all agreed on UTC
 * there. The Node app runs on the host, so its clock has to be normalised to UTC
 * explicitly or the two disagree by the host offset — which is exactly how the
 * throttle window and the OTP TTL silently go wrong. `docker-compose.yml` pins
 * `--default-time-zone=+00:00` so a host-side MariaDB cannot drift either, and
 * `dateStrings: true` returns the same UTC text.
 */
export function sqlDateTime(date = now()) {
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

/** ISO-8601 with milliseconds, as used by the mail log record (behaviour B35). */
export function isoTimestamp(date = now()) {
  return date.toISOString();
}

/** Add milliseconds to the current clock without waiting. */
export function plusMs(milliseconds, from = now()) {
  return new Date(from.getTime() + milliseconds);
}

/** Real delay, used only where a sheet specifies a widened race window. */
export function sleepMs(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * Install a test clock (`() => new Date(...)`) or pass null to restore the real
 * one. Never called from src/ outside tests.
 */
export function setClockForTests(fnOrNull = null) {
  clockFn = typeof fnOrNull === 'function' ? fnOrNull : null;
}

export function clockIsOverridden() {
  return clockFn !== null;
}
