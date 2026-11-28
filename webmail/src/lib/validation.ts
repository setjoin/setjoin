export type Validator = (value: string) => string | null;

export type Rules = Record<string, Validator[]>;

export type ValidationResult =
  | { valid: true }
  | { valid: false; errors: Record<string, string> };

export function normalize(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\x00/g, '')
    .trim()
    .normalize('NFC');
}

export function required(msg = 'This field is required'): Validator {
  return (value: string) => normalize(value).length === 0 ? msg : null;
}

export function maxLength(n: number, msg?: string): Validator {
  const m = msg || `Must be at most ${n} characters`;
  return (value: string) => value.length > n ? m : null;
}

export function minLength(n: number, msg?: string): Validator {
  const m = msg || `Must be at least ${n} characters`;
  return (value: string) => value.length < n ? m : null;
}

export function isEmail(msg = 'Invalid email format'): Validator {
  return (value: string) => {
    if (value.length > 254) return 'Email must be 254 characters or less';
    if (/\.{2,}/.test(value)) return 'Email cannot contain consecutive dots';
    const localPart = value.split('@')[0] || '';
    if (/^\.|\.$/.test(localPart)) return 'Email local part cannot start or end with a dot';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value)) return msg;
    return null;
  };
}

export function isURL(msg = 'Invalid URL format'): Validator {
  return (value: string) => {
    if (value.length === 0) return msg;
    try {
      const u = new URL(value);
      return u.protocol === 'http:' || u.protocol === 'https:' ? null : msg;
    } catch {
      return msg;
    }
  };
}

export function isNumber(msg = 'Must be a number'): Validator {
  return (value: string) => {
    if (value === '') return msg;
    return isNaN(Number(value)) ? msg : null;
  };
}

export function matches(pattern: RegExp, msg: string): Validator {
  return (value: string) => pattern.test(value) ? null : msg;
}

export function validate(
  rules: Rules,
  values: Record<string, string>,
): ValidationResult {
  const errors: Record<string, string> = {};

  for (const [field, validators] of Object.entries(rules)) {
    const raw = values[field] ?? '';
    for (const validator of validators) {
      const error = validator(raw);
      if (error) {
        errors[field] = error;
        break;
      }
    }
  }

  return Object.keys(errors).length === 0
    ? { valid: true }
    : { valid: false, errors };
}
