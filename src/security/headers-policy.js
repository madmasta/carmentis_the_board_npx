// The header policy — single source of truth (docs/03 C-HDR-1, C-XSS-3, C-HDR-3).
//
// Ported verbatim from the PHP front controller's header block. `vuln/xss_config`
// is the branch that relaxes CSP_STRING; `vuln/cors_misconfig` is the branch that
// adds the Access-Control headers this file deliberately never emits.

export const CSP_STRING =
  "default-src 'self'; img-src * data:; style-src 'self'; script-src 'self'; " +
  "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";

/** Headers applied to every response, including error responses. */
export const STATIC_HEADERS = [
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'DENY'],
  ['Referrer-Policy', 'same-origin'],
  ['X-Permitted-Cross-Domain-Policies', 'none'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['Content-Security-Policy', CSP_STRING],
];

/** Only when the request arrived over https. */
export const HSTS_HEADER = ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'];

/** C-HDR-3: nothing here may ever appear. */
export const FORBIDDEN_HEADER_PREFIX = 'access-control-';
