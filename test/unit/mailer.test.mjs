// Port of tests/Unit/MailerTest.php, plus the C-MAIL-1 control proof.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { Mailer, clearMailLog, headerValue, mailLogPath } from '../../src/mail/mailer.js';

beforeEach(() => {
  process.env.MAIL_DRIVER = 'log';
  clearMailLog();
});

afterEach(() => {
  clearMailLog();
});

describe('mailer', () => {
  it('testLogDriverWritesMessageToFile', async () => {
    const mailer = new Mailer();
    expect(await mailer.send('dest@example.com', 'Your code', '<p>Code 123456</p>')).toBe(true);

    const contents = readFileSync(mailLogPath(), 'utf8');
    expect(contents).toContain('TO: dest@example.com');
    expect(contents).toContain('SUBJECT: Your code');
    expect(contents).toContain('123456');
    // The PHP record format: a 40-dash rule and the closing separator.
    expect(contents).toContain('-'.repeat(40));
    expect(contents).toContain('\n----\n');
  });

  it('c-mail-1: recipient and subject cannot carry a header break', async () => {
    const mailer = new Mailer();
    const injected = 'victim@example.com\r\nBcc: attacker@example.com';
    expect(await mailer.send(injected, 'Hi\r\nX-Evil: 1', '<p>body</p>')).toBe(true);

    const contents = readFileSync(mailLogPath(), 'utf8');
    // The record has one recipient line and no injected header line.
    expect(contents).toContain('TO: victim@example.comBcc: attacker@example.com');
    expect(contents).not.toMatch(/^Bcc:/m);
    expect(contents).not.toMatch(/^X-Evil:/m);
    expect(headerValue('a\r\nb')).toBe('ab');
    expect(headerValue('a\0b')).toBe('ab');
  });
});
