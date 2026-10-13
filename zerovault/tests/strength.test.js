import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateStrength, generatePassword } from '../src/crypto/index.js';

test('common and short passwords score very weak', () => {
  assert.equal(estimateStrength('password123').score, 0);
  assert.equal(estimateStrength('').score, 0);
});

test('long mixed passphrases score high', () => {
  assert.ok(estimateStrength('Tr0ub4dor&3-purple-Kettle-9!').score >= 3);
});

test('repetition is penalised', () => {
  assert.ok(estimateStrength('aaaaaaaaaaaaaaaa').bits < estimateStrength('aZ3$kQ9!mL2#vB7x').bits);
});

test('generated passwords have the right length, charset and variety', () => {
  const a = generatePassword(24);
  const b = generatePassword(24);
  assert.equal(a.length, 24);
  assert.notEqual(a, b);
  assert.match(a, /^[A-Za-z0-9!@#$%^&*\-_=+?]+$/);
  assert.throws(() => generatePassword(3), RangeError);
});
