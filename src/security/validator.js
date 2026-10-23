// Input validation — port of src/Validator.php. Every message string here is
// asserted verbatim by the ported unit cases and by integration tests, so the
// wording is part of the parity surface (docs/02 section 5).
//
// The password rules carry the weak-password control (docs/03 C-PW-1): the
// letter and digit requirements are conditional on the configured minimum being
// at least 8, exactly as PHP wrote them, which is what lets `vuln/weak_password_policy`
// lower PASSWORD_MIN_LENGTH and lose them.

import { int } from '../config/env.js';

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 30;
export const TITLE_MAX = 200;
export const BODY_MAX = 10000;
export const EMAIL_MAX = 254;
export const PASSWORD_MAX = 200;

const USERNAME_PATTERN = /^[A-Za-z0-9_-]+$/;

// PHP's FILTER_VALIDATE_EMAIL accepts a dot-separated domain and rejects a
// single-label one (`missing@tld` is an error there), so the domain must contain
// at least one dot.
const EMAIL_PATTERN =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

/** mb_strlen equivalent: code points, not UTF-16 units. */
function length(value) {
  return Array.from(String(value ?? '')).length;
}

export function username(value) {
  const errors = [];
  const len = length(value);
  if (len < USERNAME_MIN || len > USERNAME_MAX) {
    errors.push(`Username must be between ${USERNAME_MIN} and ${USERNAME_MAX} characters.`);
  }
  if (!USERNAME_PATTERN.test(String(value ?? ''))) {
    errors.push('Username may only contain letters, numbers, dashes and underscores.');
  }
  return errors;
}

export function email(value) {
  const errors = [];
  const value2 = String(value ?? '');
  if (length(value2) > EMAIL_MAX) errors.push('Email address is too long.');
  if (!EMAIL_PATTERN.test(value2)) errors.push('Please provide a valid email address.');
  return errors;
}

export function password(value, usernameValue = null, emailValue = null) {
  const errors = [];
  const plain = String(value ?? '');
  const min = int('PASSWORD_MIN_LENGTH', 10);

  if (length(plain) < min) errors.push(`Password must be at least ${min} characters long.`);
  if (length(plain) > PASSWORD_MAX) errors.push('Password is too long.');
  if (min >= 8 && !/[A-Za-z]/.test(plain)) errors.push('Password must contain at least one letter.');
  if (min >= 8 && !/\d/.test(plain)) errors.push('Password must contain at least one number.');
  if (usernameValue !== null && usernameValue !== '' && plain.toLowerCase() === usernameValue.toLowerCase()) {
    errors.push('Password must not match your username.');
  }
  if (emailValue !== null && emailValue !== '' && plain.toLowerCase() === emailValue.toLowerCase()) {
    errors.push('Password must not match your email address.');
  }

  return errors;
}

export function boardName(value) {
  const len = length(String(value ?? '').trim());
  return len < 1 || len > 100 ? ['Board name must be between 1 and 100 characters.'] : [];
}

export function postTitle(value) {
  if (value === null || value === undefined) return [];
  const title = String(value).trim();
  if (title === '') return ['Title is required.'];
  if (length(title) > TITLE_MAX) return [`Title must be at most ${TITLE_MAX} characters.`];
  return [];
}

export function messageBody(value) {
  const body = String(value ?? '');
  const errors = [];
  if (body.trim() === '') errors.push('Message body must not be empty.');
  if (length(body) > BODY_MAX) errors.push(`Message body must be at most ${BODY_MAX} characters.`);
  return errors;
}

export function passwordMinLength() {
  return int('PASSWORD_MIN_LENGTH', 10);
}
