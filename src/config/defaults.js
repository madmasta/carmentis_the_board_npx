// The shipped fallback values — the single source of truth for "what the app
// runs with when nobody configured anything" (docs/01 section 2, control
// C-INFO-1 / C-AUTH-3 read these).
//
// Changing a value here changes the shipped default for every process: the
// server, the scripts and the test bootstrap. `vuln/security_misconfig` is the
// branch that makes this file the vulnerability.

export const DEFAULTS = {
  APP_NAME: 'The Board',
  APP_URL: 'http://localhost:8088',
  APP_DEBUG: '0',

  DB_HOST: '127.0.0.1',
  DB_PORT: '3307',
  DB_NAME: 'theboard_node',
  DB_USER: 'theboard',
  DB_PASS: 'theboard',
  DB_ROOT_PASS: '',

  ADMIN_EMAILS: '',
  ADMIN_PASSWORD: '',

  MAIL_DRIVER: 'log',
  MAIL_FROM: 'no-reply@theboard.local',
  MAIL_FROM_NAME: 'The Board',
  SMTP_HOST: '',
  SMTP_PORT: '587',
  SMTP_USER: '',
  SMTP_PASS: '',
  SMTP_SECURE: 'tls',

  SESSION_NAME: 'theboard_session',
  PASSWORD_MIN_LENGTH: '10',
  LOGIN_MAX_ATTEMPTS: '5',
  LOGIN_WINDOW_MINUTES: '15',
  LOGIN_THROTTLE_DISABLED: '0',
  OTP_TTL_MINUTES: '10',
  OTP_MAX_ATTEMPTS: '5',

  // Node-only keys (docs/07 section 8)
  PORT: '8088',
  HOST: '127.0.0.1',
  HOST_ALLOWLIST: '',
  MAIL_LOG: '',
  THEBOARD_VULN: '',
};
