import { describe, it, expect } from 'vitest';
import {
  normalize,
  required,
  maxLength,
  minLength,
  isEmail,
  isURL,
  isNumber,
  matches,
  validate,
} from './validation';

describe('normalize', () => {
  it('trims whitespace', () => {
    expect(normalize('  hello  ')).toBe('hello');
  });

  it('strips null bytes', () => {
    expect(normalize('he\x00llo')).toBe('hello');
  });

  it('returns empty string for non-string input', () => {
    expect(normalize(123)).toBe('');
    expect(normalize(null)).toBe('');
    expect(normalize(undefined)).toBe('');
    expect(normalize({})).toBe('');
  });

  it('returns empty string for already-empty value', () => {
    expect(normalize('')).toBe('');
  });

  it('normalizes Unicode to NFC', () => {
    // e-acute as combining sequence (NFD) -> composed form (NFC)
    expect(normalize('é')).toBe('é');
  });
});

describe('required', () => {
  const validator = required();

  it('returns error for empty string', () => {
    expect(validator('')).toBe('This field is required');
  });

  it('returns error for whitespace-only', () => {
    expect(validator('   ')).toBe('This field is required');
  });

  it('returns error for string with null bytes only', () => {
    expect(validator('\x00')).toBe('This field is required');
  });

  it('returns null for non-empty string', () => {
    expect(validator('hello')).toBeNull();
  });

  it('supports custom message', () => {
    const custom = required('Name is required');
    expect(custom('')).toBe('Name is required');
  });
});

describe('maxLength', () => {
  it('returns error when value exceeds max', () => {
    const validator = maxLength(5);
    expect(validator('123456')).toBe('Must be at most 5 characters');
  });

  it('returns null when value is within limit', () => {
    const validator = maxLength(5);
    expect(validator('12345')).toBeNull();
  });

  it('returns null when value is under limit', () => {
    const validator = maxLength(5);
    expect(validator('12')).toBeNull();
  });

  it('supports custom message', () => {
    const validator = maxLength(3, 'Too long!');
    expect(validator('1234')).toBe('Too long!');
  });
});

describe('minLength', () => {
  it('returns error when value is too short', () => {
    const validator = minLength(5);
    expect(validator('ab')).toBe('Must be at least 5 characters');
  });

  it('returns null when value meets minimum', () => {
    const validator = minLength(5);
    expect(validator('12345')).toBeNull();
  });

  it('returns null when value exceeds minimum', () => {
    const validator = minLength(5);
    expect(validator('123456')).toBeNull();
  });

  it('supports custom message', () => {
    const validator = minLength(8, 'Password too short');
    expect(validator('ab')).toBe('Password too short');
  });
});

describe('isEmail', () => {
  const validator = isEmail();

  it('returns error for empty string', () => {
    expect(validator('')).toBe('Invalid email format');
  });

  it('rejects email missing @', () => {
    expect(validator('notanemail')).toBe('Invalid email format');
  });

  it('rejects email missing domain', () => {
    expect(validator('user@')).toBe('Invalid email format');
  });

  it('rejects email missing TLD', () => {
    expect(validator('user@domain')).toBe('Invalid email format');
  });

  it('accepts valid email', () => {
    expect(validator('user@example.com')).toBeNull();
  });

  it('accepts valid email with subdomain', () => {
    expect(validator('user@mail.example.com')).toBeNull();
  });

  it('accepts email with plus addressing', () => {
    expect(validator('user+tag@example.com')).toBeNull();
  });

  it('supports custom message', () => {
    const custom = isEmail('Bad email!');
    expect(custom('notanemail')).toBe('Bad email!');
  });
});

describe('isURL', () => {
  const validator = isURL();

  it('returns error for empty string', () => {
    expect(validator('')).toBe('Invalid URL format');
  });

  it('returns error for random text', () => {
    expect(validator('not a url')).toBe('Invalid URL format');
  });

  it('accepts https URL', () => {
    expect(validator('https://example.com')).toBeNull();
  });

  it('accepts http URL', () => {
    expect(validator('http://example.com')).toBeNull();
  });

  it('rejects non-http protocols', () => {
    expect(validator('ftp://example.com')).toBe('Invalid URL format');
  });

  it('accepts URL with port', () => {
    expect(validator('https://example.com:8080')).toBeNull();
  });

  it('accepts URL with path', () => {
    expect(validator('https://example.com/path/to/resource')).toBeNull();
  });

  it('accepts URL with query string', () => {
    expect(validator('https://example.com/search?q=hello')).toBeNull();
  });

  it('supports custom message', () => {
    const custom = isURL('Bad URL!');
    expect(custom('nope')).toBe('Bad URL!');
  });
});

describe('isNumber', () => {
  const validator = isNumber();

  it('returns error for empty string', () => {
    expect(validator('')).toBe('Must be a number');
  });

  it('returns error for letters', () => {
    expect(validator('abc')).toBe('Must be a number');
  });

  it('accepts integer', () => {
    expect(validator('123')).toBeNull();
  });

  it('accepts negative integer', () => {
    expect(validator('-42')).toBeNull();
  });

  it('accepts zero', () => {
    expect(validator('0')).toBeNull();
  });

  it('accepts float string', () => {
    expect(validator('3.14')).toBeNull();
  });

  it('supports custom message', () => {
    const custom = isNumber('Not numeric!');
    expect(custom('abc')).toBe('Not numeric!');
  });
});

describe('matches', () => {
  it('returns null when pattern matches', () => {
    const validator = matches(/^\d+$/, 'Digits only');
    expect(validator('1234')).toBeNull();
  });

  it('returns error when pattern does not match', () => {
    const validator = matches(/^\d+$/, 'Digits only');
    expect(validator('abc')).toBe('Digits only');
  });
});

describe('validate', () => {
  const rules = {
    name: [required('Name is required')],
    email: [required(), isEmail('Bad email')],
    bio: [maxLength(10, 'Bio too long')],
  };

  it('returns { valid: true } when all rules pass', () => {
    const result = validate(rules, {
      name: 'Alice',
      email: 'alice@example.com',
      bio: 'Hello',
    });
    expect(result).toEqual({ valid: true });
  });

  it('returns { valid: false, errors } for failing fields', () => {
    const result = validate(rules, {
      name: '',
      email: 'bad-email',
      bio: 'A very long bio text that exceeds ten characters',
    });
    expect(result).toMatchObject({
      valid: false,
      errors: {
        name: 'Name is required',
        email: 'Bad email',
        bio: 'Bio too long',
      },
    });
  });

  it('skips after first error per field', () => {
    const result = validate(rules, {
      name: 'Alice',
      email: '', // empty triggers required first, then would also fail isEmail
      bio: '',
    });
    expect(result).toMatchObject({
      valid: false,
      errors: {
        email: 'This field is required', // first validator message, not isEmail
      },
    });
    expect(result.valid).toBe(false);
    expect((result as { errors: Record<string, string> }).errors.email).toBe('This field is required');
    // bio had no error (empty string passes maxLength since '' is under 10)
    expect((result as { errors: Record<string, string> }).errors.bio).toBeUndefined();
  });

  it('handles missing fields in values (treats as empty)', () => {
    const result = validate(
      { name: [required('Name is required')] },
      {},
    );
    expect(result).toMatchObject({
      valid: false,
      errors: {
        name: 'Name is required',
      },
    });
  });

  it('returns valid:true for empty rules object', () => {
    const result = validate({}, { foo: 'bar' });
    expect(result).toEqual({ valid: true });
  });

  it('calls normalize inside validators (required rejects null-byte-only)', () => {
    const result = validate(
      { name: [required()] },
      { name: '\x00\x00' },
    );
    expect(result).toMatchObject({
      valid: false,
      errors: {
        name: 'This field is required',
      },
    });
  });
});
