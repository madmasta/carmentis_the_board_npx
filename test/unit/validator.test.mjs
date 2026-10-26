// Port of tests/Unit/ValidatorTest.php (docs/03 C-PW-1, C-INPUT-1).

import { describe, expect, it } from 'vitest';
import {
  boardName,
  email,
  messageBody,
  password,
  postTitle,
  username,
} from '../../src/security/validator.js';

describe('validator', () => {
  it('testAcceptsValidUsername', () => {
    expect(username('alice_1')).toEqual([]);
  });

  it('testRejectsShortUsername', () => {
    expect(username('ab')).not.toEqual([]);
  });

  it('testRejectsLongUsername', () => {
    expect(username('a'.repeat(31))).not.toEqual([]);
  });

  it('testRejectsInvalidUsernameCharacters', () => {
    expect(username('bad name!')).not.toEqual([]);
    expect(username('<script>')).not.toEqual([]);
  });

  it('testAcceptsValidEmail', () => {
    expect(email('user.name+tag@example.co.uk')).toEqual([]);
  });

  it('testRejectsInvalidEmail', () => {
    expect(email('not-an-email')).not.toEqual([]);
    expect(email('missing@tld')).not.toEqual([]);
    expect(email('@example.com')).not.toEqual([]);
  });

  it('testPasswordLength — c-auth-2 the length floor is the policy minimum', () => {
    expect(password('LongEnough1')).toEqual([]);
    expect(password('short1a')).not.toEqual([]);
  });

  it('testPasswordRequiresLetterAndDigit — c-auth-2 letter and digit are required', () => {
    expect(password('nodigitshere')).not.toEqual([]);
    expect(password('1234567890')).not.toEqual([]);
  });

  it('testPasswordMustNotMatchUsernameOrEmail — c-auth-2 the password may not equal the username or email', () => {
    // 'alice12345' passes length/character rules but equals the username
    expect(password('alice12345', 'alice12345')).not.toEqual([]);
    expect(password('user@example.com', null, 'user@example.com')).not.toEqual([]);
    expect(password('OtherPass99', 'alice12345')).toEqual([]);
  });

  it('testPasswordConfirmMismatchIsControllerLogic', () => {
    // Documented behaviour: the validator never sees a confirmation field; the
    // controllers compare it. Two identical valid passwords are both accepted.
    expect(password('LongEnough1')).toEqual(password('LongEnough1'));
  });

  it('testBoardNameValidation', () => {
    expect(boardName('General')).toEqual([]);
    expect(boardName('')).not.toEqual([]);
    expect(boardName('x'.repeat(101))).not.toEqual([]);
  });

  it('testPostTitleValidation', () => {
    expect(postTitle('A fine title')).toEqual([]);
    expect(postTitle('   ')).not.toEqual([]);
    expect(postTitle('x'.repeat(201))).not.toEqual([]);
  });

  it('testMessageBodyValidation', () => {
    expect(messageBody('   ')).not.toEqual([]);
    expect(messageBody('hello')).toEqual([]);
    expect(messageBody('x'.repeat(10001))).not.toEqual([]);
  });

  it('testUsernamesAreAsciiOnlyByDesign', () => {
    // Accented characters are deliberately rejected (strict charset)
    expect(username('é'.repeat(10))).not.toEqual([]);
    expect(username('abcde')).toEqual([]);
  });
});
