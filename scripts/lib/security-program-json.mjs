import crypto from 'node:crypto';
import path from 'node:path';

export const SECURITY_PROGRAM_SCHEMA_PATTERN = /^setjoin\.security-program\.[a-z0-9][a-z0-9-]*\/v[1-9][0-9]*$/;

export class SecurityProgramError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'SecurityProgramError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function fail(code, message, details) {
  throw new SecurityProgramError(code, message, details);
}

function safeFieldName(value) {
  return typeof value === 'string'
    && value.length <= 80
    && !/[\0\r\n\\/]/.test(value)
    ? JSON.stringify(value)
    : `<field:${sha256Hex(value).slice(0, 12)}>`;
}

// JSON.parse deliberately accepts duplicate object names. Security-program control
// records do not: a visually shadowed field must never change an authorization or
// publication decision. This scanner validates JSON grammar while tracking every
// object scope before JSON.parse constructs the value.
export function rejectDuplicateJsonKeys(text) {
  if (typeof text !== 'string') fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', 'JSON input must be text');
  let index = 0;
  const invalid = (message) => fail(
    'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED',
    `invalid JSON near character ${index + 1}: ${message}`,
  );
  const whitespace = () => { while (index < text.length && /[\u0009\u000a\u000d\u0020]/.test(text[index])) index += 1; };

  function readString() {
    if (text[index] !== '"') invalid('expected string');
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') {
        try { return JSON.parse(text.slice(start, index)); }
        catch { invalid('invalid string'); }
      }
      if (character === '\\') {
        if (index >= text.length) invalid('unterminated escape');
        const escaped = text[index++];
        if (escaped === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(index, index + 4))) invalid('invalid unicode escape');
          index += 4;
        } else if (!'"\\/bfnrt'.includes(escaped)) {
          invalid('invalid escape');
        }
      } else if (character.charCodeAt(0) < 0x20) {
        invalid('control character in string');
      }
    }
    invalid('unterminated string');
  }

  function readValue() {
    whitespace();
    if (text[index] === '{') return readObject();
    if (text[index] === '[') return readArray();
    if (text[index] === '"') { readString(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, index)) { index += literal.length; return; }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (number) { index += number[0].length; return; }
    invalid('expected value');
  }

  function readObject() {
    index += 1;
    whitespace();
    const keys = new Set();
    if (text[index] === '}') { index += 1; return; }
    while (index < text.length) {
      whitespace();
      const key = readString();
      if (keys.has(key)) fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `duplicate JSON field ${safeFieldName(key)}`);
      keys.add(key);
      whitespace();
      if (text[index++] !== ':') invalid('expected colon');
      readValue();
      whitespace();
      if (text[index] === '}') { index += 1; return; }
      if (text[index++] !== ',') invalid('expected comma');
    }
    invalid('unterminated object');
  }

  function readArray() {
    index += 1;
    whitespace();
    if (text[index] === ']') { index += 1; return; }
    while (index < text.length) {
      readValue();
      whitespace();
      if (text[index] === ']') { index += 1; return; }
      if (text[index++] !== ',') invalid('expected comma');
    }
    invalid('unterminated array');
  }

  whitespace();
  readValue();
  whitespace();
  if (index !== text.length) invalid('trailing data');
  return text;
}

export function parseStrictJson(text) {
  rejectDuplicateJsonKeys(text);
  try {
    return JSON.parse(text);
  } catch (error) {
    fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `invalid JSON: ${error.message}`);
  }
}

export function assertClosedSchema(value, {
  schema,
  required = [],
  optional = [],
  name = schema ?? 'security-program record',
} = {}) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${name} must be an object`);
  }
  if (!SECURITY_PROGRAM_SCHEMA_PATTERN.test(schema ?? '')) {
    fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${name} has an invalid expected schema`);
  }
  if (value.schema !== schema) {
    fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${name} requires schema ${schema}`);
  }
  const allowed = new Set(['schema', ...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${name} contains unknown field ${safeFieldName(key)}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${name} is missing field ${safeFieldName(key)}`);
  }
  return value;
}

function canonicalize(value, location = '$') {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${location} contains a non-finite number`);
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${location} contains a sparse array`);
    return value.map((entry, index) => canonicalize(entry, `${location}[${index}]`));
  }
  if (typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      const childLocation = `${location}.${safeFieldName(key)}`;
      if (typeof value[key] === 'undefined') fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${childLocation} is undefined`);
      result[key] = canonicalize(value[key], childLocation);
    }
    return result;
  }
  fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', `${location} contains unsupported ${typeof value}`);
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value))}\n`;
}

export function sha256Hex(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertSafeSegment(value, location) {
  if (typeof value !== 'string' || value.length === 0 || /[\0\r\n]/.test(value)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${location} must be a non-empty single-line string`);
  }
  if (value === '.' || value === '..' || value.includes('/') || value.includes('\\')) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${location} is not a safe logical segment`);
  }
  return value;
}

export function assertRepositoryRelativePath(value, location = 'repository path') {
  if (typeof value !== 'string' || value.length === 0 || /[\0\r\n]/.test(value)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${location} must be a non-empty single-line path`);
  }
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || value.includes('\\')) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${location} must be repository-relative`);
  }
  const pieces = value.split('/');
  if (pieces.some((piece) => piece === '' || piece === '.' || piece === '..')) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${location} contains an unsafe component`);
  }
  return value;
}

export function repositoryRelativeRef(relativePath) {
  return `repo:${assertRepositoryRelativePath(relativePath)}`;
}

export function logicalArtifactRef(namespace, ...segments) {
  assertSafeSegment(namespace, 'artifact namespace');
  return `${namespace}:${segments.map((segment, index) => assertSafeSegment(segment, `artifact segment ${index + 1}`)).join('/')}`;
}
