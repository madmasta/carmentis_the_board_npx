// Login throttle plus its development kill switch — port of
// src/LoginThrottle.php (docs/02 B6, docs/03 C-AUTH-3).
//
// The kill switch is deliberately hard to leave on by accident: it is honoured
// only when APP_DEBUG=1, a refused flag is logged, every bypassed check writes a
// line to the app log, every page renders a full-width banner, and the CLI
// scripts print a warning block.
//
// One deliberate API difference from PHP: `exceeded()` receives the failure count
// instead of querying the repository, so this module has no DB dependency and
// the throttle stays testable in isolation. The caller (auth/login.js) does the
// lookup.

import { bool, int } from '../config/env.js';
import { security as logSecurity } from '../lib/log.js';

export const ENV_FLAG = 'LOGIN_THROTTLE_DISABLED';

export const STATUS_ENFORCED = 'enforced';
export const STATUS_DISABLED = 'disabled';
export const STATUS_REFUSED = 'refused';

let announced = false;

export function status() {
  if (!bool(ENV_FLAG, false)) return STATUS_ENFORCED;
  // The escape hatch only exists in a debug build.
  return bool('APP_DEBUG', false) ? STATUS_DISABLED : STATUS_REFUSED;
}

export function isDisabled() {
  return status() === STATUS_DISABLED;
}

export function windowSeconds() {
  return int('LOGIN_WINDOW_MINUTES', 15) * 60;
}

export function maxAttempts() {
  return int('LOGIN_MAX_ATTEMPTS', 5);
}

/**
 * Has this email/IP pair burned through its allowance? Always false while the
 * kill switch is active, with the bypass logged every time.
 */
export function exceeded({ email, ip, recentFailures }) {
  const max = maxAttempts();
  if (isDisabled()) {
    logSecurity(
      `login throttle BYPASSED (${ENV_FLAG}=1): email=${email} ip=${ip} failures=${recentFailures}/${max}`,
    );
    return false;
  }
  return Number(recentFailures) >= max;
}

/** One-line banner for the site header, or null when there is nothing to say. */
export function bannerText() {
  switch (status()) {
    case STATUS_DISABLED:
      return (
        'LOGIN THROTTLING IS DISABLED — brute-force protection is OFF. ' +
        'Unlimited password guesses are allowed against every account. ' +
        `Development only: remove ${ENV_FLAG}=1 from .env before this instance faces anyone else.`
      );
    case STATUS_REFUSED:
      return (
        `${ENV_FLAG}=1 is set but was IGNORED because APP_DEBUG=0. ` +
        'Login throttling is still enforced. Set APP_DEBUG=1 if you really meant to disable it.'
      );
    default:
      return null;
  }
}

/** The banner title rendered in the page header (templates/partials/header). */
export function bannerTitle() {
  switch (status()) {
    case STATUS_DISABLED:
      return 'BRUTE-FORCE PROTECTION IS OFF';
    case STATUS_REFUSED:
      return 'INSECURE SETTING IGNORED';
    default:
      return null;
  }
}

function wrap(text, width) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const word of words) {
    if (line === '') {
      line = word;
    } else if (`${line} ${word}`.length <= width) {
      line = `${line} ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line !== '') lines.push(line);
  return lines;
}

/** Multi-line warning block for terminal output and the app log. */
export function warningBlock() {
  const text = bannerText();
  if (text === null) return null;

  const headline = isDisabled() ? 'BRUTE-FORCE PROTECTION IS DISABLED' : `${ENV_FLAG} WAS IGNORED`;
  const lines = ['', headline, '', ...wrap(text, 68)];

  let out = `\n${'!'.repeat(74)}\n`;
  for (const line of lines) {
    const pad = Math.max(0, 68 - line.length);
    out += `!! ${line}${' '.repeat(pad)} !!\n`;
  }
  out += `${'!'.repeat(74)}\n`;
  return out;
}

/** Emit the warning block once per process (CLI → stderr, server → log). */
export function announce({ cli = false } = {}) {
  if (announced) return null;
  const block = warningBlock();
  if (block === null) return null;
  announced = true;

  if (cli) {
    process.stderr.write(block);
    return block;
  }
  logSecurity(bannerText());
  return block;
}

/** Test seam: let a case announce again. */
export function resetAnnouncementForTests() {
  announced = false;
}
