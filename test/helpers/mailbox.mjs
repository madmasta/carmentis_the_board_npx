// Mail log reader for tests (docs/02 section 6: "the OTP step goes through
// test/helpers/mailbox.mjs#lastCode(to)").
//
// The mail log is the delivery channel in tests — MAIL_DRIVER=log — so the code a
// user would have received is read from the same file the application wrote,
// never from the mfa_codes row.

import { readMailLog, clearMailLog, mailLogPath } from '../../src/mail/mailer.js';

export { mailLogPath, clearMailLog as clear };

/** Every record in the log, oldest first. */
export function messages() {
  const raw = readMailLog();
  if (raw === null || raw === '') return [];

  const out = [];
  for (const block of raw.split('\n----\n')) {
    const text = block.trim();
    if (text === '') continue;
    // The TO value sits on the same line as the timestamp:
    //   [2026-…Z] TO: someone@example.com
    const header = /\bTO: (\S+)/.exec(text);
    const subject = /^SUBJECT: (.*)$/m.exec(text);
    const bodyStart = text.indexOf('-'.repeat(40));
    out.push({
      to: header ? header[1].trim() : '',
      subject: subject ? subject[1].trim() : '',
      body: bodyStart === -1 ? text : text.slice(bodyStart + 40).trim(),
    });
  }
  return out;
}

/** The last message addressed to `to`, or null. */
export function lastMessage(to) {
  const found = messages().filter((message) => message.to === String(to).toLowerCase());
  return found.length === 0 ? null : found[found.length - 1];
}

/** The 6-digit code inside the last message to `to`. */
export function lastCode(to) {
  const message = lastMessage(to);
  if (message === null) return null;
  const strong = /<strong>\s*(\d{6})\s*<\/strong>/.exec(message.body);
  if (strong !== null) return strong[1];
  const bare = /(?:code is|code:)\D{0,40}(\d{6})/i.exec(message.body);
  return bare === null ? null : bare[1];
}
