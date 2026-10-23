// Mail delivery — port of src/Mailer.php (docs/02 B35, docs/03 C-MAIL-1).
//
// Drivers:
//   log  — appends the PHP record format verbatim to var/log/mail.log (default,
//          and what every test reads; no test may open a network connection)
//   smtp — a minimal client over node:net / node:tls with AUTH LOGIN and STARTTLS
//
// C-MAIL-1: the recipient and subject are stripped of CR, LF and NUL before a
// message is composed, and `From` comes from configuration only. That strip is
// the control; `vuln/email_header_injection` removes it.

import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { join } from 'node:path';

import { get, int } from '../config/env.js';
import { isoTimestamp, now } from '../lib/clock.js';
import { root } from '../db/admin.js';

export const HEADER_STRIP = /[\r\n\0]/g;

/** C-MAIL-1: no header value may carry a line break. */
export function headerValue(value) {
  return String(value ?? '').replace(HEADER_STRIP, '');
}

export function mailLogPath() {
  const configured = get('MAIL_LOG', null);
  if (configured) return configured;
  return join(root(), 'var', 'log', 'mail.log');
}

export class Mailer {
  async send(to, subject, htmlBody) {
    const driver = String(get('MAIL_DRIVER', 'log')).toLowerCase();
    const recipient = headerValue(to);
    const safeSubject = headerValue(subject);

    if (recipient === '') return false;

    if (driver === 'smtp') {
      return sendSmtp(recipient, safeSubject, String(htmlBody ?? ''));
    }
    return sendLog(recipient, safeSubject, String(htmlBody ?? ''));
  }
}

/** The PHP record format, byte for byte apart from the timestamp format. */
function sendLog(to, subject, html) {
  const entry =
    `[${isoTimestamp(now())}] TO: ${to}\nSUBJECT: ${subject}\n${'-'.repeat(40)}\n${html}\n----\n`;
  try {
    mkdirSync(join(mailLogPath(), '..'), { recursive: true });
    appendFileSync(mailLogPath(), entry, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/** Read the whole mail log — the oracle exploit tests grep for codes. */
export function readMailLog() {
  try {
    return readFileSync(mailLogPath(), 'utf8');
  } catch {
    return null;
  }
}

/** Remove every record written so far (test isolation). */
export function clearMailLog() {
  try {
    mkdirSync(join(mailLogPath(), '..'), { recursive: true });
    appendFileSync(mailLogPath(), '', 'utf8');
    return true;
  } catch {
    return false;
  }
}

function encodeHeader(value) {
  return `=?UTF-8?B?${Buffer.from(String(value), 'utf8').toString('base64')}?=`;
}

function sendSmtp(to, subject, html) {
  const host = String(get('SMTP_HOST', ''));
  if (host === '') return Promise.resolve(false);

  const port = int('SMTP_PORT', 587);
  const secure = String(get('SMTP_SECURE', 'tls')).toLowerCase(); // tls | ssl | none
  const user = String(get('SMTP_USER', ''));
  const pass = String(get('SMTP_PASS', ''));
  const from = String(get('MAIL_FROM', 'no-reply@localhost'));
  const fromName = String(get('MAIL_FROM_NAME', 'The Board'));
  const ehloHost = (() => {
    try {
      return new URL(String(get('APP_URL', 'http://localhost'))).hostname || 'localhost';
    } catch {
      return 'localhost';
    }
  })();

  const socket = secure === 'ssl' ? tlsConnect({ host, port, servername: host }) : createConnection({ host, port });
  socket.setTimeout(15_000);

  return new Promise((resolve) => {
    let buffer = '';
    let pending = null;

    const onData = (chunk) => {
      buffer += chunk.toString('latin1');
      const lines = buffer.split('\r\n');
      buffer = lines.pop() ?? '';
      let response = '';
      for (const line of lines) {
        response += `${line}\r\n`;
        if (line[3] !== '-') break; // a multi-line reply keeps the dash in [3]
      }
      if (pending !== null && response !== '') {
        const waiter = pending;
        pending = null;
        waiter(response);
      }
    };

    socket.on('data', onData);
    socket.on('timeout', () => {
      socket.destroy();
    });
    socket.on('error', () => {
      if (pending !== null) {
        const waiter = pending;
        pending = null;
        waiter('');
      }
    });

    const read = () =>
      new Promise((done) => {
        pending = done;
      });

    const command = async (text, expect) => {
      if (text !== '') socket.write(`${text}\r\n`);
      const response = await read();
      if (!response.startsWith(expect)) {
        throw new Error(`SMTP expected ${expect}, got: ${response.trim()}`);
      }
      return response;
    };

    const work = async () => {
      await command('', '220');
      await command(`EHLO ${ehloHost}`, '250');

      if (secure === 'tls') {
        await command('STARTTLS', '220');
        await upgrade(socket, host);
        socket.prependListener('data', onData);
        await command(`EHLO ${ehloHost}`, '250');
      }

      if (user !== '') {
        await command('AUTH LOGIN', '334');
        await command(Buffer.from(user, 'utf8').toString('base64'), '334');
        await command(Buffer.from(pass, 'utf8').toString('base64'), '235');
      }

      await command(`MAIL FROM:<${from}>`, '250');
      await command(`RCPT TO:<${to}>`, '250');
      await command('DATA', '354');

      const headers =
        `From: ${encodeHeader(fromName)} <${from}>\r\n` +
        `To: <${to}>\r\n` +
        `Subject: ${encodeHeader(subject)}\r\n` +
        `Date: ${new Date().toUTCString()}\r\n` +
        'MIME-Version: 1.0\r\n' +
        'Content-Type: text/html; charset=UTF-8\r\n';
      const body = String(html).replace(/^\./gm, '..');
      await command(`${headers}\r\n${body}\r\n.`, '250');
      await command('QUIT', '221');
      return true;
    };

    work()
      .then(() => {
        socket.end();
        resolve(true);
      })
      .catch(() => {
        socket.destroy();
        resolve(false);
      });
  });
}

function upgrade(socket, host) {
  return new Promise((resolve, reject) => {
    const secure = tlsConnect(
      { socket, servername: host, rejectUnauthorized: false },
      () => resolve(undefined),
    );
    secure.once('error', reject);
  });
}

export default Mailer;
