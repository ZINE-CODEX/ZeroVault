/**
 * strength.js  -  a small, honest password strength estimate
 * ------------------------------------------------------------------
 * Encryption is only as strong as the password. This gives quick
 * feedback while typing. It is a HEURISTIC, not a guarantee:
 *
 *   bits ~= length * log2(size of the character pool used)
 *
 * then reduced for common weaknesses (known passwords, repeated
 * characters, keyboard/number runs). For reference, 60 bits already
 * takes a very long time to brute-force against PBKDF2-600k; 80+ is
 * comfortable. A random 4-5 word passphrase easily reaches that.
 */

// A tiny sample of the most-used passwords; real attackers use millions.
const COMMON = [
  'password', 'passw0rd', '123456', '12345678', 'qwerty', 'letmein', 'welcome',
  'admin', 'iloveyou', 'monkey', 'dragon', 'football', 'abc123', 'login',
  'princess', 'sunshine', 'master', 'shadow', 'trustno1',
];

/**
 * @param {string} password
 * @returns {{bits:number, score:0|1|2|3|4, label:string, hints:string[]}}
 */
export function estimateStrength(password) {
  const hints = [];
  if (!password) return { bits: 0, score: 0, label: 'Empty', hints: ['Enter a password.'] };

  // Size of the character pool the password draws from.
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  let bits = password.length * Math.log2(pool || 1);

  // Penalty: contains a very common password.
  const lower = password.toLowerCase();
  if (COMMON.some((word) => lower.includes(word))) {
    bits = Math.min(bits, 20);
    hints.push('Contains a very common password.');
  }

  // Penalty: few distinct characters ("aaaaaaaaaaaa").
  const unique = new Set(password).size;
  if (unique < password.length / 2) {
    bits *= unique / password.length + 0.5;
    hints.push('Too many repeated characters.');
  }

  // Penalty: simple runs like "abcd" or "1234".
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)/i.test(password)) {
    bits -= 12;
    hints.push('Avoid sequences like 1234 or qwerty.');
  }

  if (password.length < 12) hints.push('Use at least 12 characters.');
  bits = Math.max(0, Math.round(bits));

  const score = bits < 30 ? 0 : bits < 50 ? 1 : bits < 70 ? 2 : bits < 90 ? 3 : 4;
  const label = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'][score];
  return { bits, score, label, hints };
}
