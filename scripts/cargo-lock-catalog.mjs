#!/usr/bin/env node
// Cargo supply-chain catalog (D-CLIENTS--CARGO-001/002, CWE-494/CWE-426).
//
// Owns the mechanical half of the clients Rust registry policy:
//   check   — validate clients/Cargo.lock against the pinned known-good
//             checksum catalog (scripts/cargo-lock-pins.json), validate the
//             registry policy in clients/.cargo/config.toml and
//             clients/deny.toml against the same allowlist, and hash-verify
//             the OHOS SDK toolchain binaries the config references.
//   refresh — regenerate the catalog from the current Cargo.lock + config
//             (schemaVersion 2: packages[] plus the sdk toolchain section).
//             A conscious act for dependency/toolchain updates: the diff IS
//             the review artifact.
//   mutate  — deterministic lockfile/config/pins corruption used by
//             check-cargo-supply-chain.sh --self-test to prove the guard
//             still fires (temp copies only; never run against the real tree).
//   sdk-fixture — build a fake SDK tree + rebased config + matching pins
//             under a temp dir for the self-test's SDK drills (binaries are
//             hashed, never executed).
//
// Pins schema (schemaVersion 2): registries[], pinnedSourceTable, lockSha256,
// packages[{name,version,source,checksum}], and
// sdk { rootEnv, tools: [{ key, sha256 }] } — tool keys are paths RELATIVE to
// the SDK root so machine-specific prefixes do not churn the pins.
//
// The config/deny reader (parseTomlTables) is fail-closed by design: it
// understands a strict TOML subset (table headers with bare or "quoted"
// segments, key = "string", key = ["string", ...], comments) and ABORTS the
// guard loudly on anything else. A parser that silently skips what it does
// not understand is itself a vulnerability — an attacker could hide a
// forbidden [patch."…"] mirror or weakened deny rule behind syntax the
// parser ignores and sail through with zero violations. The same rule holds
// for value spellings: basic-string escapes are decoded before a value is
// stored, and a plain table never silently shadows an array-of-tables of the
// same name — one definition replacing the other would let a changed
// registry hide behind a second, approved one.
//
// Called by scripts/check-cargo-supply-chain.sh (run-guards.sh manifest ->
// xinchuang CI structural guards).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pinsDefault = path.join(root, 'scripts', 'cargo-lock-pins.json');
// [env] key declaring the OHOS SDK root in clients/.cargo/config.toml.
const SDK_ROOT_ENV = 'OHOS_NDK_HOME';

function fail(code, message) {
  console.error(`${code} problem=cargo_supply_chain cause=${JSON.stringify(message)}`);
  process.exit(1);
}

function usage() {
  console.error(`usage: cargo-lock-catalog.mjs check [lock config deny pins]
       cargo-lock-catalog.mjs refresh [lock pins]
       cargo-lock-catalog.mjs mutate <kind> <input> [output]
       cargo-lock-catalog.mjs sdk-fixture <dir> [absent-sdk-root]`);
  process.exit(2);
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// --- Strict TOML-subset reader (fail-closed) -------------------------------
//
// Understands EXACTLY:
//   - blank lines and comments (# to end of line)
//   - table headers [a.b."c"] and array-of-tables [[a."b"]] — dot-separated
//     segments, each a bare key ([A-Za-z0-9_-]+) or a basic "string"
//   - key = "basic string" pairs (bare or quoted keys)
//   - key = [ "string", ... ] arrays of strings, single- or multi-line,
//     with comments and trailing commas allowed inside the array
//   - key = true / key = false bare booleans (cargo-deny's
//     [licenses.private] ignore = true in clients/deny.toml)
// Everything else — dotted keys, literal ('...') strings, multi-line
// ("""...""") strings, integers/floats/dates, inline tables,
// duplicate [table] headers, duplicate keys — throws E_CARGO_SUPPLY_SYNTAX.
// Values are stored DECODED: readBasicString resolves the escapes TOML
// defines (\b \t \n \f \r \" \\ and \uXXXX/\UXXXXXXXX; anything else throws),
// so "\u004eEXT" can never be mistaken for a different path than "NEXT" —
// stat()/hash checks see the real value, and an invalid escape aborts.
// Table identity keeps the table-vs-array-table kind: a plain [name] may not
// be redefined, and a plain table + [[array-of-tables]] with the same
// canonical name is rejected outright instead of letting one definition
// replace the other in the table map (last-wins replacement would let a
// changed registry hide behind a second, approved one). Repeated [[name]]
// headers are legal TOML and merge their key-values into one entry (a key
// seen across two elements throws), so every parsed pair stays visible to
// policy checks — nothing is ever silently discarded.
// Canonical names join quoted dotted segments onto bare ones
// ([patch."a.b"] == patch.a.b) — a conservative direction: it can only
// over-match policy checks, never under-match them.

function syntaxError(source, lineNo, detail) {
  const err = new Error(
    `${source}:${lineNo}: ${detail} — the guard parses a strict TOML subset ` +
    `(table headers with bare/"quoted" segments, key = "string", ` +
    `key = ["string", ...], comments); extend scripts/cargo-lock-catalog.mjs ` +
    `deliberately to go beyond it (fail-closed: unknown syntax must never ` +
    `be silently skipped)`);
  err.code = 'E_CARGO_SUPPLY_SYNTAX';
  return err;
}

// Reads a basic string starting at line[pos] (which must be '"'); returns
// { value, pos } positioned just after the closing quote.
function readBasicString(line, pos, source, lineNo) {
  let out = '';
  let i = pos + 1;
  for (;;) {
    if (i >= line.length) throw syntaxError(source, lineNo, 'unterminated string');
    const ch = line[i];
    if (ch === '"') return { value: out, pos: i + 1 };
    if (ch === '\\') {
      const esc = line[i + 1];
      i += 2;
      switch (esc) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u':
        case 'U': {
          const width = esc === 'u' ? 4 : 8;
          const hex = line.slice(i, i + width);
          if (hex.length !== width || !/^[0-9a-fA-F]+$/.test(hex)) {
            throw syntaxError(source, lineNo, `invalid \\${esc} escape`);
          }
          try {
            out += String.fromCodePoint(parseInt(hex, 16));
          } catch {
            throw syntaxError(source, lineNo, `\\${esc}${hex} is not a Unicode scalar value`);
          }
          i += width;
          break;
        }
        default:
          throw syntaxError(source, lineNo, `unsupported escape \\${esc ?? '<eof>'}`);
      }
      continue;
    }
    out += ch;
    i += 1;
  }
}

// Reads a dot-separated key path of bare/quoted segments from line[pos];
// returns { segments, pos } positioned after the path.
function readKeyPath(line, pos, source, lineNo) {
  const segments = [];
  for (;;) {
    while (pos < line.length && /\s/.test(line[pos])) pos += 1;
    if (pos < line.length && line[pos] === '"') {
      const str = readBasicString(line, pos, source, lineNo);
      segments.push(str.value);
      pos = str.pos;
    } else {
      const start = pos;
      while (pos < line.length && /^[A-Za-z0-9_-]$/.test(line[pos])) pos += 1;
      if (pos === start) throw syntaxError(source, lineNo, 'expected a bare or "quoted" key segment');
      segments.push(line.slice(start, pos));
    }
    while (pos < line.length && /\s/.test(line[pos])) pos += 1;
    if (line[pos] === '.') {
      pos += 1;
      continue;
    }
    return { segments, pos };
  }
}

// Reads an array-of-strings value starting on lines[startIdx] at startPos
// (positioned at '['). Returns { values, endIdx, endPos } — endIdx/endPos
// locate the character just after the closing ']'.
function readStringArray(lines, startIdx, startPos, source) {
  let idx = startIdx;
  let line = lines[idx];
  let pos = startPos + 1; // past '['
  const values = [];
  let expectValue = true;
  for (;;) {
    if (pos >= line.length) {
      idx += 1;
      if (idx >= lines.length) throw syntaxError(source, startIdx + 1, 'unterminated array — no closing "]"');
      line = lines[idx];
      pos = 0;
      continue;
    }
    const ch = line[pos];
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      pos += 1;
      continue;
    }
    if (ch === '#') {
      pos = line.length; // comment: skip the rest of the line
      continue;
    }
    if (ch === ']') return { values, endIdx: idx, endPos: pos + 1 };
    if (ch === ',') {
      if (expectValue) {
        throw syntaxError(source, idx + 1, values.length === 0 ? 'array starts with ","' : 'duplicate "," in array');
      }
      expectValue = true;
      pos += 1;
      continue;
    }
    if (ch === '"') {
      if (!expectValue) throw syntaxError(source, idx + 1, 'missing "," between array elements');
      const str = readBasicString(line, pos, source, idx + 1);
      values.push(str.value);
      pos = str.pos;
      expectValue = false;
      continue;
    }
    throw syntaxError(source, idx + 1, `unsupported array element syntax at ${JSON.stringify(line.slice(pos, pos + 24))} — only "strings" are understood`);
  }
}

export function parseTomlTables(text, source = 'toml') {
  const lines = text.split('\n');
  const tables = new Map();
  let current = null;
  let currentName = null;
  for (let idx = 0; idx < lines.length; idx += 1) {
    const line = lines[idx];
    const lineNo = idx + 1;
    let pos = 0;
    while (pos < line.length && /\s/.test(line[pos])) pos += 1;
    if (pos >= line.length || line[pos] === '#') continue; // blank or comment
    if (line[pos] === '[') {
      const arrayOfTables = line[pos + 1] === '[';
      const { segments, pos: afterSegs } = readKeyPath(line, pos + (arrayOfTables ? 2 : 1), source, lineNo);
      let p = afterSegs;
      while (p < line.length && /\s/.test(line[p])) p += 1;
      const close = arrayOfTables ? ']]' : ']';
      if (!line.startsWith(close, p)) throw syntaxError(source, lineNo, `malformed table header — expected ${close}`);
      p += close.length;
      while (p < line.length && /\s/.test(line[p])) p += 1;
      if (p < line.length && line[p] !== '#') throw syntaxError(source, lineNo, 'unexpected text after table header');
      if (segments.some((seg) => seg.length === 0)) throw syntaxError(source, lineNo, 'empty table-name segment');
      const name = segments.join('.');
      // Table identity preserves the table-vs-array-table kind so one
      // definition can never silently replace another: a plain [table] may
      // not be redefined, and a plain table + [[array-of-tables]] of the
      // same canonical name is a fail-closed abort (valid TOML forbids the
      // mix, and last-wins replacement in the table map would let a changed
      // registry hide behind a second, approved-registry definition).
      // Repeated [[array-of-tables]] headers are legal and merge into one
      // entry; duplicate keys across elements throw, so nothing parsed is
      // ever dropped from policy checks.
      const existing = tables.get(name);
      if (!arrayOfTables) {
        if (existing) {
          throw syntaxError(source, lineNo, existing.kind === 'array'
            ? `table [${name}] conflicts with the [[${name}]] array-of-tables — the guard refuses to let either definition shadow the other`
            : `table [${name}] defined twice`);
        }
      } else if (existing && existing.kind !== 'array') {
        throw syntaxError(source, lineNo, `[[${name}]] conflicts with the existing plain [${name}] table — the guard refuses to let either definition shadow the other`);
      }
      if (existing && existing.kind === 'array') {
        current = existing;
      } else {
        current = { kind: arrayOfTables ? 'array' : 'table', line: lineNo, pairs: new Map() };
        tables.set(name, current);
      }
      currentName = name;
      continue;
    }
    // key = value
    const { segments, pos: afterKey } = readKeyPath(line, pos, source, lineNo);
    if (segments.length !== 1) throw syntaxError(source, lineNo, 'dotted keys are not supported by this parser');
    if (!current) throw syntaxError(source, lineNo, 'key-value pair outside any [table] header');
    let p = afterKey;
    while (p < line.length && /\s/.test(line[p])) p += 1;
    if (line[p] !== '=') throw syntaxError(source, lineNo, `expected "=" after key`);
    p += 1;
    while (p < line.length && /\s/.test(line[p])) p += 1;
    if (p >= line.length || line[p] === '#') throw syntaxError(source, lineNo, 'missing value');
    const key = segments[0];
    if (current.pairs.has(key)) throw syntaxError(source, lineNo, `duplicate key ${JSON.stringify(key)} in [${currentName}]`);
    if (line[p] === '"') {
      const str = readBasicString(line, p, source, lineNo);
      let rest = str.pos;
      while (rest < line.length && /\s/.test(line[rest])) rest += 1;
      if (rest < line.length && line[rest] !== '#') throw syntaxError(source, lineNo, 'unexpected text after string value');
      // Store the DECODED value, never the raw spelling: an escaped spelling
      // (\u004eEXT) of a path must stat/hash as the real path, not "not
      // found". readBasicString already rejected invalid escapes.
      current.pairs.set(key, { kind: 'string', value: str.value, line: lineNo });
      continue;
    }
    if (line[p] === '[') {
      const arr = readStringArray(lines, idx, p, source);
      // Nothing may follow the closing "]" but whitespace or a comment —
      // trailing text is not part of any value and must not be dropped.
      const closing = lines[arr.endIdx];
      let rest = arr.endPos;
      while (rest < closing.length && /\s/.test(closing[rest])) rest += 1;
      if (rest < closing.length && closing[rest] !== '#') {
        throw syntaxError(source, arr.endIdx + 1, 'unexpected text after "]" closing the array');
      }
      // Decoded elements straight from readBasicString.
      current.pairs.set(key, { kind: 'array', values: arr.values, line: lineNo });
      idx = arr.endIdx; // continue after the array's closing line
      continue;
    }
    const bool = /^(true|false)(?![A-Za-z0-9_-])/.exec(line.slice(p));
    if (bool) {
      let rest = p + bool[1].length;
      while (rest < line.length && /\s/.test(line[rest])) rest += 1;
      if (rest < line.length && line[rest] !== '#') throw syntaxError(source, lineNo, 'unexpected text after boolean value');
      current.pairs.set(key, { kind: 'boolean', value: bool[1] === 'true', line: lineNo });
      continue;
    }
    throw syntaxError(source, lineNo, `unsupported value syntax at ${JSON.stringify(line.slice(p, p + 24))} — only "strings", ["string", ...] arrays and true/false are understood`);
  }
  return tables;
}

function readPolicyTables(filePath) {
  try {
    return parseTomlTables(fs.readFileSync(filePath, 'utf8'), filePath);
  } catch (error) {
    fail('E_CARGO_SUPPLY_SYNTAX', error.message);
  }
}

// Parse Cargo.lock into ordered package tables. Fields beyond
// name/version/source/checksum are irrelevant to the checksum guard; the
// whole-file sha256 backstop catches any other lockfile surgery.
export function parseCargoLock(text) {
  const packages = [];
  let current = null;
  for (const [index, line] of text.split('\n').entries()) {
    const trimmed = line.trim();
    if (trimmed === '[[package]]') {
      current = { line: index + 1 };
      packages.push(current);
      continue;
    }
    if (!current) continue;
    if (trimmed.startsWith('[')) { current = null; continue; }
    const pair = trimmed.match(/^(name|version|source|checksum)\s*=\s*"([^"]*)"$/);
    if (pair) current[pair[1]] = { value: pair[2], line: index + 1 };
  }
  return packages;
}

function violation(code, message) {
  return { code, message };
}

// --- SDK toolchain hashing (CWE-426) ----------------------------------------
//
// clients/.cargo/config.toml points OHOS cross-compilation at machine-local
// SDK executables ([env] OHOS_NDK_HOME/CC_*/CXX_*, [target.*] linker/ar).
// Those binaries are filesystem inputs to every OHOS build and, unlike the
// lockfile, were previously unverified. The guard:
//   1. derives the SDK root (env OHOS_NDK_HOME, else the longest common
//      directory prefix of the referenced tool paths) and every referenced
//      binary — any absolute path under the SDK root;
//   2. pins sha256 keyed by the path RELATIVE to the SDK root, so
//      machine-specific prefixes do not churn the pins;
//   3. verifies presence + hash of every pinned binary whenever the SDK root
//      exists on this machine (hashing only — never executes one);
//   4. prints an explicit `SDK-SKIP (reason=…)` line when the SDK root is
//      absent (e.g. plain Linux CI) — greppable, never a silent pass.

function commonDirectoryPrefix(paths) {
  const split = paths.map((p) => p.split('/'));
  const first = split[0];
  const common = [];
  for (let i = 0; i < first.length - 1; i += 1) {
    const seg = first[i];
    if (split.every((parts) => parts.length > i + 1 && parts[i] === seg)) common.push(seg);
    else break;
  }
  return common.length > 0 ? common.join('/') : null;
}

export function deriveSdkTools(configTables) {
  const envTable = configTables.get('env');
  let root = null;
  if (envTable) {
    for (const [key, entry] of envTable.pairs) {
      // Parsed values are decoded basic strings; a non-string value here is
      // not a path (and arrays never were candidates).
      if (key === SDK_ROOT_ENV && entry.kind === 'string') {
        root = entry.value;
        break;
      }
    }
  }
  const isAbs = (v) => typeof v === 'string' && v.startsWith('/');
  // Seed candidates: the CC/CXX env convention and [target.*] linker/ar —
  // the constructs cargo actually consults for toolchain resolution.
  const candidates = [];
  const consider = (entry) => {
    if (entry.kind === 'string' && isAbs(entry.value)) candidates.push(entry.value);
  };
  if (envTable) {
    for (const [key, entry] of envTable.pairs) {
      if (/^(CC|CXX)(_|$)/.test(key)) consider(entry);
    }
  }
  for (const [name, table] of configTables) {
    if (name !== 'target' && !name.startsWith('target.')) continue;
    for (const [key, entry] of table.pairs) {
      if (key === 'linker' || key === 'ar') consider(entry);
    }
  }
  const underRoot = (p) => root !== null && p !== root && p.startsWith(`${root}/`);
  let toolPaths;
  if (root !== null) {
    // Root declared: every SDK-resident absolute path the config references
    // is a toolchain input, wherever in the config it appears.
    toolPaths = new Set(candidates.filter(underRoot));
    for (const table of configTables.values()) {
      for (const entry of table.pairs.values()) {
        if (entry.kind === 'string' && underRoot(entry.value)) toolPaths.add(entry.value);
      }
    }
  } else if (candidates.length > 0) {
    root = commonDirectoryPrefix(candidates);
    toolPaths = new Set(root !== null ? candidates.filter(underRoot) : candidates);
  } else {
    toolPaths = new Set();
  }
  const tools = [...toolPaths].sort().map((p) => ({
    path: p,
    key: root !== null && p.startsWith(`${root}/`) ? p.slice(root.length + 1) : p,
  }));
  return {
    root,
    rootEnv: root !== null && envTable?.pairs.has(SDK_ROOT_ENV) ? SDK_ROOT_ENV : null,
    tools,
  };
}

export function check({ lockPath, configPath, denyPath, pinsPath }) {
  const problems = [];
  let pins;
  try {
    pins = JSON.parse(fs.readFileSync(pinsPath, 'utf8'));
  } catch (error) {
    fail('E_CARGO_SUPPLY_PINS', `${pinsPath}: unreadable JSON: ${error.message}`);
  }
  if (pins.schemaVersion !== 2 || !Array.isArray(pins.registries) || pins.registries.length === 0 ||
      !Array.isArray(pins.packages) || typeof pins.lockSha256 !== 'string' ||
      typeof pins.config !== 'string' || typeof pins.deny !== 'string' ||
      !pins.sdk || !Array.isArray(pins.sdk.tools) ||
      !pins.sdk.tools.every((t) => typeof t.key === 'string' && typeof t.sha256 === 'string' && /^[0-9a-f]{64}$/.test(t.sha256))) {
    fail('E_CARGO_SUPPLY_PINS', `${pinsPath}: expected schemaVersion=2, registries[], packages[], lockSha256, config, deny, sdk.tools[{key,sha256}] — schema-1 pins are stale; run: node scripts/cargo-lock-catalog.mjs refresh`);
  }
  const registrySet = new Set(pins.registries);
  const pinned = pins.pinnedSourceTable ?? {
    table: 'source.crates-io',
    key: 'registry',
    value: pins.registries.find((r) => r.startsWith('sparse+')),
  };

  // 1. Whole-file digest: dependency-edge rewrites, ordering churn or any
  //    other lockfile surgery fails here even when every (name, version,
  //    source, checksum) tuple still matches the catalog.
  const lockSha = sha256File(lockPath);
  if (lockSha !== pins.lockSha256) {
    problems.push(violation('E_CARGO_SUPPLY_DRIFT',
      `${lockPath}: sha256 ${lockSha} != pinned ${pins.lockSha256} — the lockfile drifted from the approved catalog; if this change is intended, run: node scripts/cargo-lock-catalog.mjs refresh`));
  }

  // 2. Per-entry validation against known-good checksums.
  const lockPackages = parseCargoLock(fs.readFileSync(lockPath, 'utf8'));
  const registryPackages = [];
  const tupleKey = (p) => `${p.name.value}@${p.version.value} source=${p.source.value} checksum=${p.checksum.value}`;
  const seenTuples = new Set();
  for (const pkg of lockPackages) {
    if (!pkg.name || !pkg.version) {
      problems.push(violation('E_CARGO_SUPPLY_CHECKSUM', `${lockPath}:${pkg.line}: [[package]] without name/version`));
      continue;
    }
    if (!pkg.source) continue; // workspace member or path dependency
    registryPackages.push(pkg);
    const url = pkg.source.value.replace(/^registry\+/, '');
    if (!pkg.source.value.startsWith('registry+') || !registrySet.has(url)) {
      problems.push(violation('E_CARGO_SUPPLY_SOURCE',
        `${lockPath}:${pkg.source.line}: ${pkg.name.value}@${pkg.version.value} source ${JSON.stringify(pkg.source.value)} is outside the registry allowlist ${JSON.stringify([...registrySet])}`));
      continue;
    }
    if (!pkg.checksum || !/^[0-9a-f]{64}$/.test(pkg.checksum.value)) {
      problems.push(violation('E_CARGO_SUPPLY_CHECKSUM',
        `${lockPath}:${pkg.checksum?.line ?? pkg.name.line}: ${pkg.name.value}@${pkg.version.value} missing/malformed sha256 checksum`));
      continue;
    }
    const key = tupleKey(pkg);
    if (seenTuples.has(key)) {
      problems.push(violation('E_CARGO_SUPPLY_CHECKSUM', `${lockPath}:${pkg.name.line}: duplicate package entry ${pkg.name.value}@${pkg.version.value}`));
    }
    seenTuples.add(key);
  }
  const catalog = new Map(pins.packages.map((p) => [`${p.name}@${p.version}`, p]));
  for (const pkg of registryPackages) {
    // Packages that already failed the structural checks above are reported
    // there; without a checksum they cannot be tuple-compared.
    if (!pkg.checksum || !/^[0-9a-f]{64}$/.test(pkg.checksum.value)) continue;
    const known = catalog.get(`${pkg.name.value}@${pkg.version.value}`);
    if (!known) {
      problems.push(violation('E_CARGO_SUPPLY_UNPINNED',
        `${lockPath}:${pkg.name.line}: ${pkg.name.value}@${pkg.version.value} is not in the pinned catalog — new or changed dependency; refresh scripts/cargo-lock-pins.json consciously if intended`));
      continue;
    }
    if (known.source !== pkg.source.value || known.checksum !== pkg.checksum.value) {
      problems.push(violation('E_CARGO_SUPPLY_UNPINNED',
        `${lockPath}:${pkg.name.line}: ${pkg.name.value}@${pkg.version.value} drifted from the known-good pin (source/checksum mismatch) — possible substituted artifact`));
    }
  }
  const lockTuples = new Set(registryPackages.map((p) => `${p.name.value}@${p.version.value}`));
  for (const p of pins.packages) {
    if (!lockTuples.has(`${p.name}@${p.version}`)) {
      problems.push(violation('E_CARGO_SUPPLY_STALE',
        `${lockPath}: pinned package ${p.name}@${p.version} is absent from the lockfile — catalog is stale; refresh consciously`));
    }
  }

  // 3. Registry policy in clients/.cargo/config.toml: exactly one pinned
  //    source table for crates.io; no replacement, no mirrors, no patches.
  //    parseTomlTables aborts the guard (E_CARGO_SUPPLY_SYNTAX) on syntax it
  //    does not understand — a forbidden override cannot hide from it.
  const configTables = readPolicyTables(configPath);
  for (const [name, table] of configTables) {
    if (name === pinned.table) continue;
    if (name === 'source' || name.startsWith('source.') || name === 'patch' || name.startsWith('patch.')) {
      problems.push(violation('E_CARGO_SUPPLY_CONFIG',
        `${configPath}:${table.line}: [${name}] is not part of the registry policy (only [${pinned.table}] is sanctioned) — document any mirror in scripts/cargo-lock-pins.json + clients/deny.toml in the same change`));
    }
  }
  const pinnedTable = configTables.get(pinned.table);
  if (!pinnedTable) {
    problems.push(violation('E_CARGO_SUPPLY_CONFIG', `${configPath}: required [${pinned.table}] pin is missing`));
  } else {
    for (const [key, { value, line }] of pinnedTable.pairs) {
      if (key === 'replace-with') {
        problems.push(violation('E_CARGO_SUPPLY_CONFIG',
          `${configPath}:${line}: replace-with is not sanctioned (no documented mirror; cargo also rejects replacing crates.io with itself)`));
      }
    }
    const registryValue = pinnedTable.pairs.get(pinned.key);
    if (!registryValue || registryValue.kind !== 'string' || registryValue.value !== pinned.value) {
      problems.push(violation('E_CARGO_SUPPLY_CONFIG',
        `${configPath}:${registryValue?.line ?? pinnedTable.line}: expected ${pinned.key} = "${pinned.value}" in [${pinned.table}]`));
    }
  }

  // 4. clients/deny.toml: [sources] must deny unknown registries and git
  //    sources and allow exactly the pinned registry spellings.
  const denyTables = readPolicyTables(denyPath);
  const sources = denyTables.get('sources');
  if (!sources) {
    problems.push(violation('E_CARGO_SUPPLY_DENY', `${denyPath}: required [sources] policy section is missing`));
  } else {
    for (const key of ['unknown-registry', 'unknown-git']) {
      const entry = sources.pairs.get(key);
      if (!entry || entry.kind !== 'string' || entry.value !== 'deny') {
        problems.push(violation('E_CARGO_SUPPLY_DENY',
          `${denyPath}:${entry?.line ?? sources.line}: expected ${key} = "deny"`));
      }
    }
    const allow = sources.pairs.get('allow-registry');
    // Parsed arrays already hold decoded strings — no re-extraction from the
    // raw spelling, so escapes cannot differ from the pinned spellings.
    const allowed = allow && allow.kind === 'array' ? allow.values : null;
    if (!allowed || allowed.length !== pins.registries.length ||
        [...allowed].sort().join('|') !== [...pins.registries].sort().join('|')) {
      problems.push(violation('E_CARGO_SUPPLY_DENY',
        `${denyPath}:${allow?.line ?? sources.line}: allow-registry must equal the pinned registries ${JSON.stringify(pins.registries)}`));
    }
  }

  // 5. SDK/toolchain binaries referenced by the config (CWE-426): the OHOS
  //    cross-build links through machine-local SDK executables; pin and
  //    verify their hashes like every other build input. An absent SDK is an
  //    explicit, greppable SDK-SKIP — never a silent pass.
  const sdkPins = pins.sdk;
  const sdkDerived = deriveSdkTools(configTables);
  const sdkBefore = problems.length;
  const pinnedSdk = new Map(sdkPins.tools.map((t) => [t.key, t.sha256]));
  const derivedSdk = new Map(sdkDerived.tools.map((t) => [t.key, t.path]));
  for (const key of derivedSdk.keys()) {
    if (!pinnedSdk.has(key)) {
      problems.push(violation('E_CARGO_SUPPLY_SDK_UNPINNED',
        `${configPath}: SDK/toolchain binary ${JSON.stringify(key)} (under SDK root ${JSON.stringify(sdkDerived.root)}) is referenced by the config but not hash-pinned — refresh scripts/cargo-lock-pins.json consciously on an SDK machine`));
    }
  }
  for (const key of pinnedSdk.keys()) {
    if (!derivedSdk.has(key)) {
      problems.push(violation('E_CARGO_SUPPLY_SDK_STALE',
        `${configPath}: pinned SDK/toolchain binary ${JSON.stringify(key)} is no longer referenced by the config — refresh scripts/cargo-lock-pins.json consciously`));
    }
  }
  if (pinnedSdk.size > 0 || derivedSdk.size > 0) {
    const sdkRoot = sdkDerived.root;
    let rootPresent = false;
    try {
      rootPresent = sdkRoot !== null && fs.statSync(sdkRoot).isDirectory();
    } catch {
      rootPresent = false;
    }
    if (rootPresent) {
      for (const [key, sha] of pinnedSdk) {
        const binPath = path.join(sdkRoot, key);
        if (!fs.existsSync(binPath)) {
          problems.push(violation('E_CARGO_SUPPLY_SDK_DRIFT',
            `${binPath}: pinned SDK/toolchain binary is missing from the SDK root — re-provision the SDK or refresh the pins consciously`));
          continue;
        }
        const actual = sha256File(binPath);
        if (actual !== sha) {
          problems.push(violation('E_CARGO_SUPPLY_SDK_DRIFT',
            `${binPath}: sha256 ${actual} != pinned ${sha} — the toolchain binary changed; re-provision the SDK or refresh the pins consciously`));
        }
      }
      if (problems.length === sdkBefore && pinnedSdk.size > 0) {
        console.log(`SDK-OK (${pinnedSdk.size} toolchain binaries hash-verified; root=${sdkRoot})`);
      }
    } else {
      console.log(`SDK-SKIP (reason=SDK root ${JSON.stringify(sdkRoot)} not present on this machine; ${pinnedSdk.size} pinned toolchain binaries not re-hashed here)`);
    }
  }

  return { problems, pinnedCount: registryPackages.length, lockSha };
}

export function buildPins({ lockPath, configPath, denyPath, previousPins }) {
  const text = fs.readFileSync(lockPath, 'utf8');
  const packages = parseCargoLock(text)
    .filter((pkg) => pkg.source && pkg.name && pkg.version && pkg.checksum)
    .map((pkg) => ({
      name: pkg.name.value,
      version: pkg.version.value,
      source: pkg.source.value,
      checksum: pkg.checksum.value,
    }));
  if (packages.length === 0) fail('E_CARGO_SUPPLY_PINS', `${lockPath}: no checksummed registry packages found`);
  const sdkDerived = deriveSdkTools(readPolicyTables(configPath));
  let sdk;
  if (sdkDerived.tools.length === 0) {
    sdk = previousPins?.sdk ?? { rootEnv: sdkDerived.rootEnv, tools: [] };
  } else {
    try {
      sdk = {
        rootEnv: sdkDerived.rootEnv,
        tools: sdkDerived.tools
          .map(({ key, path: binPath }) => ({ key, sha256: sha256File(binPath) }))
          .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)),
      };
    } catch (error) {
      if (previousPins?.sdk) {
        // This machine cannot re-hash (no SDK); carry the toolchain pins
        // forward — the check still enforces config↔pins consistency, so a
        // config-side toolchain change fails loudly until an SDK machine
        // refreshes.
        sdk = previousPins.sdk;
      } else {
        fail('E_CARGO_SUPPLY_SDK', `${configPath}: cannot hash SDK toolchain binaries (${error.message}) — build the sdk pins on a machine that has the OHOS SDK`);
      }
    }
  }
  return {
    schemaVersion: 2,
    lock: path.relative(root, lockPath),
    config: path.relative(root, configPath),
    deny: path.relative(root, denyPath),
    registries: previousPins?.registries ?? [
      'sparse+https://index.crates.io/',
      'https://github.com/rust-lang/crates.io-index',
    ],
    pinnedSourceTable: previousPins?.pinnedSourceTable ?? {
      table: 'source.crates-io',
      key: 'registry',
      value: 'sparse+https://index.crates.io/',
    },
    sdk,
    lockSha256: sha256File(lockPath),
    generated: new Date().toISOString(),
    packages,
  };
}

// Deterministic corruptions for the guard self-test. Never point these at the
// real tree from automation: check-cargo-supply-chain.sh --self-test copies
// to a temp dir first.
export function mutate(kind, input, output) {
  let text = fs.readFileSync(input, 'utf8');
  switch (kind) {
    case 'tamper-checksum': {
      const marker = text.match(/^checksum = "([0-9a-f]{64})"$/m);
      if (!marker) fail('E_CARGO_SUPPLY_SELFTEST', 'tamper-checksum: no checksum line found');
      const flipped = (marker[1][0] === '0' ? '1' : '0') + marker[1].slice(1);
      text = text.replace(marker[0], `checksum = "${flipped}"`);
      break;
    }
    case 'add-package':
      text += `
[[package]]
name = "setjoin-internal-svc"
version = "0.1.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
`;
      break;
    case 'add-git-package':
      text += `
[[package]]
name = "evil-git-dep"
version = "1.0.0"
source = "git+https://evil.example/repo?branch=main#abc123"
`;
      break;
    case 'drop-checksum': {
      const block = text.match(/\[\[package\]\]\nname = "[^"]+"\nversion = "[^"]+"\nsource = "registry\+[^"]+"\nchecksum = "[0-9a-f]{64}"\n/);
      if (!block) fail('E_CARGO_SUPPLY_SELFTEST', 'drop-checksum: no registry package with checksum found');
      text = text.replace(block[0], block[0].replace(/^checksum = .*\n/m, ''));
      break;
    }
    case 'rewire-dep': {
      const deps = text.match(/^dependencies = \[\n/m);
      if (!deps) fail('E_CARGO_SUPPLY_SELFTEST', 'rewire-dep: no dependencies list found');
      text = text.replace(deps[0], 'dependencies = [\n "zzz-injected-dependency",\n');
      break;
    }
    case 'evil-mirror':
      if (!text.includes('sparse+https://index.crates.io/')) fail('E_CARGO_SUPPLY_SELFTEST', 'evil-mirror: pinned URL not found in config');
      text = text.replace('sparse+https://index.crates.io/', 'sparse+https://evil.example/index/');
      break;
    case 'extra-source':
      text += '\n[source.evil-mirror]\nregistry = "sparse+https://evil.example/index/"\n';
      break;
    case 'quoted-patch-override':
      // Valid TOML whose table name uses a quoted segment — the shape the
      // pre-r2 parser silently ignored (zero violations on an override).
      text += '\n[patch."https://github.com/rust-lang/crates.io-index"]\nsetjoin-evil-patch = "1.0.0"\n';
      break;
    case 'evil-kind-collision': {
      // The r3 probe: a plain [source.crates-io] with a CHANGED registry plus
      // a [["source.crates-io"]] array carrying the approved one. Name-keyed
      // table maps collapse the two targets (last wins) and would sail
      // through with zero violations; the guard must abort on the collision.
      if (!text.includes('sparse+https://index.crates.io/')) fail('E_CARGO_SUPPLY_SELFTEST', 'evil-kind-collision: pinned URL not found in config');
      text = text.replace('sparse+https://index.crates.io/', 'sparse+https://evil.example/index/');
      text += '\n[["source.crates-io"]]\nregistry = "sparse+https://index.crates.io/"\n';
      break;
    }
    case 'unsupported-syntax':
      // An inline-table value is OUTSIDE the strict subset: the guard must
      // abort with E_CARGO_SUPPLY_SYNTAX, never parse-skip it.
      text += '\n[source.evil]\nregistry = { path = "vendored-evil" }\n';
      break;
    case 'weaken-deny': {
      const before = text;
      text = text.replace('unknown-git = "deny"', 'unknown-git = "warn"');
      if (text === before) fail('E_CARGO_SUPPLY_SELFTEST', 'weaken-deny: unknown-git line not found');
      break;
    }
    case 'tamper-sdk-pin': {
      // Flip one hex char of the first pinned SDK toolchain hash: a modified
      // toolchain digest must surface as E_CARGO_SUPPLY_SDK_DRIFT.
      let data;
      try {
        data = JSON.parse(text);
      } catch (error) {
        fail('E_CARGO_SUPPLY_SELFTEST', `tamper-sdk-pin: input is not JSON: ${error.message}`);
      }
      if (!data.sdk || !Array.isArray(data.sdk.tools) || data.sdk.tools.length === 0) {
        fail('E_CARGO_SUPPLY_SELFTEST', 'tamper-sdk-pin: no sdk.tools in pins');
      }
      const hash = data.sdk.tools[0].sha256;
      data.sdk.tools[0].sha256 = (hash[0] === '0' ? '1' : '0') + hash.slice(1);
      text = `${JSON.stringify(data, null, 2)}\n`;
      break;
    }
    default:
      usage();
  }
  fs.writeFileSync(output, text);
}

// --- TOML serialization (fixture generator) ---------------------------------
//
// serializeTomlTables re-emits PARSED tables as the exact strict subset the
// guard parses (table headers, key = "basic string", key = ["string", ...]).
// The SDK fixture generator needs it because rebasing by patching the raw
// TOML text cannot work: a raw spelling may differ from its decoded value
// ("\u004eEXT" == "NEXT"), so a text-level replace of the decoded root misses
// and the "rebased" fixture silently keeps referencing the REAL SDK — the
// fixture pins then hash the real binaries and a tampered FIXTURE binary
// still reports SDK-OK with zero violations, making every drill vacuous.
// Rewriting decoded values and re-serializing with proper basic-string
// escaping keeps the emitted file valid TOML whose DECODED values are exactly
// the rewritten ones. Canonical table names round-trip: segments are split
// on '.', bare-safe segments emit unquoted and everything else as an escaped
// quoted segment — the parser joins them back to the same canonical name.
// escapeRoot (escape-decoding drill): occurrences of that root inside emitted
// values are re-spelled with the root's second character as \uXXXX, which
// decodes back to the identical string.

function tomlBasicStringBody(value) {
  let out = '';
  for (const ch of value) {
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else {
      const code = ch.codePointAt(0);
      out += code < 0x20 ? `\\u${code.toString(16).padStart(4, '0')}` : ch;
    }
  }
  return out;
}

function tomlKeySegment(segment) {
  return /^[A-Za-z0-9_-]+$/.test(segment) ? segment : `"${tomlBasicStringBody(segment)}"`;
}

function serializeTomlTables(tables, { escapeRoot = null } = {}) {
  const emitString = (value) => {
    let body = tomlBasicStringBody(value);
    if (escapeRoot !== null && escapeRoot.length > 1) {
      const plain = tomlBasicStringBody(escapeRoot);
      if (body.includes(plain)) {
        const alt = tomlBasicStringBody(escapeRoot.slice(0, 1)) +
          `\\u${escapeRoot.charCodeAt(1).toString(16).padStart(4, '0')}` +
          tomlBasicStringBody(escapeRoot.slice(2));
        body = body.split(plain).join(alt);
      }
    }
    return `"${body}"`;
  };
  const chunks = [];
  for (const [name, table] of tables) {
    const header = name.split('.').map(tomlKeySegment).join('.');
    chunks.push(table.kind === 'array' ? `[[${header}]]\n` : `[${header}]\n`);
    for (const [key, entry] of table.pairs) {
      if (entry.kind === 'string') {
        chunks.push(`${tomlKeySegment(key)} = ${emitString(entry.value)}\n`);
      } else if (entry.kind === 'array') {
        chunks.push(`${tomlKeySegment(key)} = [${entry.values.map(emitString).join(', ')}]\n`);
      } else {
        // parseTomlTables stores nothing else; fail loudly rather than emit a
        // value the guard's own parser would reject.
        fail('E_CARGO_SUPPLY_SELFTEST', `sdk-fixture: cannot serialize key ${JSON.stringify(key)} in [${name}] — unknown entry kind ${JSON.stringify(entry.kind)}`);
      }
    }
    chunks.push('\n');
  }
  return chunks.join('');
}

// Post-generation isolation assertion: re-READ and re-PARSE an emitted
// fixture config and prove the rebase took — a loud generator failure beats a
// vacuous drill. The config's DECODED SDK root must be exactly the expected
// root, every declared tool path must decode inside that root, the tool count
// must match the real config (nothing silently dropped or invented), and no
// decoded value anywhere may still reference the real SDK root — values are
// decoded first, so a \u004eEXT-style leftover of the real root cannot hide.
function assertFixtureIsolation(configPath, expectedRoot, realRoot, expectedToolCount) {
  const tables = parseTomlTables(fs.readFileSync(configPath, 'utf8'), configPath);
  const derived = deriveSdkTools(tables);
  const label = path.basename(configPath);
  if (derived.root !== expectedRoot) {
    fail('E_CARGO_SUPPLY_SELFTEST', `sdk-fixture: ${label} decodes to SDK root ${JSON.stringify(derived.root)}, expected ${JSON.stringify(expectedRoot)} — rebase failed`);
  }
  if (derived.tools.length !== expectedToolCount) {
    fail('E_CARGO_SUPPLY_SELFTEST', `sdk-fixture: ${label} declares ${derived.tools.length} SDK tool paths, expected ${expectedToolCount} — rebase dropped or invented tool references`);
  }
  for (const tool of derived.tools) {
    if (!tool.path.startsWith(`${expectedRoot}/`)) {
      fail('E_CARGO_SUPPLY_SELFTEST', `sdk-fixture: ${label} tool path ${JSON.stringify(tool.path)} does not decode inside the fixture root ${JSON.stringify(expectedRoot)}`);
    }
  }
  for (const [name, table] of tables) {
    for (const [key, entry] of table.pairs) {
      const values = entry.kind === 'string' ? [entry.value] : entry.kind === 'array' ? entry.values : [];
      for (const value of values) {
        if (typeof value === 'string' && value.includes(realRoot)) {
          fail('E_CARGO_SUPPLY_SELFTEST', `sdk-fixture: ${label} [${name}] ${JSON.stringify(key)} still references the real SDK root ${JSON.stringify(realRoot)} — rebase failed`);
        }
      }
    }
  }
}

// Builds a self-contained SDK fixture under dir: fake SDK binaries (hashed,
// never executed), a config rebased from the real one onto the fixture root
// (plus a config-absent.toml variant pointing at absentSdkRoot for the
// SDK-SKIP drill and a config-escaped.toml variant whose root path is
// re-spelled with \uXXXX escapes for the escape-decoding drill), and matching
// pins. The rebase operates on the PARSED, DECODED table entries and re-
// serializes them (see serializeTomlTables) — never on raw text — and every
// generated variant is re-parsed and asserted to decode only inside its new
// root (assertFixtureIsolation). Everything stays inside dir.
function sdkFixture(dir, absentSdkRoot) {
  const fixtureRoot = path.resolve(dir);
  const binDir = path.join(fixtureRoot, 'native', 'llvm', 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const realConfigPath = path.join(root, 'clients', '.cargo', 'config.toml');
  const realTables = readPolicyTables(realConfigPath);
  const realDerived = deriveSdkTools(realTables);
  const realRoot = realDerived.root;
  if (!realRoot) fail('E_CARGO_SUPPLY_SELFTEST', 'sdk-fixture: real config declares no SDK root to rebase onto');
  // Rewrite EVERY occurrence of the real root inside every decoded string
  // value and array element — the root can also sit mid-value (CFLAGS
  // "--sysroot=<root>/…") — so no reference to the real SDK survives.
  const rebaseTables = (tables, newRoot) => {
    const rewrite = (value) => value.split(realRoot).join(newRoot);
    const rebased = new Map();
    for (const [name, table] of tables) {
      const pairs = new Map();
      for (const [key, entry] of table.pairs) {
        if (entry.kind === 'string') {
          pairs.set(key, { kind: 'string', value: rewrite(entry.value), line: entry.line });
        } else if (entry.kind === 'array') {
          pairs.set(key, { kind: 'array', values: entry.values.map(rewrite), line: entry.line });
        } else {
          pairs.set(key, entry);
        }
      }
      rebased.set(name, { kind: table.kind, line: table.line, pairs });
    }
    return rebased;
  };
  const writeAndAssert = (fileName, tables, expectedRoot, opts = {}) => {
    const configPath = path.join(fixtureRoot, fileName);
    fs.writeFileSync(configPath, serializeTomlTables(tables, opts));
    assertFixtureIsolation(configPath, expectedRoot, realRoot, realDerived.tools.length);
    return configPath;
  };
  const fixtureConfigPath = writeAndAssert('config.toml', rebaseTables(realTables, fixtureRoot), fixtureRoot);
  if (absentSdkRoot) {
    const absentRoot = path.resolve(absentSdkRoot);
    writeAndAssert('config-absent.toml', rebaseTables(realTables, absentRoot), absentRoot);
  }
  // Escaped-spelling variant: identical DECODED config, but every fixture-
  // root occurrence is re-spelled with its second character escaped
  // (\u0076ar/... == var/...). Parsing must decode it back to the same root
  // and hash the same binaries; a reader that stat()ed the raw spelling would
  // report SDK-SKIP while the SDK it was meant to verify is present — a
  // fail-open bypass.
  writeAndAssert('config-escaped.toml', rebaseTables(realTables, fixtureRoot), fixtureRoot, { escapeRoot: fixtureRoot });
  const names = [
    'aarch64-unknown-linux-ohos-clang',
    'aarch64-unknown-linux-ohos-clang++',
    'x86_64-unknown-linux-ohos-clang',
    'llvm-ar',
  ];
  for (const [i, name] of names.entries()) {
    fs.writeFileSync(path.join(binDir, name), `fake setjoin sdk fixture binary ${name} #${i}\n`);
  }
  const data = buildPins({
    lockPath: path.join(root, 'clients', 'Cargo.lock'),
    configPath: fixtureConfigPath,
    denyPath: path.join(root, 'clients', 'deny.toml'),
    previousPins: JSON.parse(fs.readFileSync(pinsDefault, 'utf8')),
  });
  fs.writeFileSync(path.join(fixtureRoot, 'pins.json'), `${JSON.stringify(data, null, 2)}\n`);
  console.log(`cargo-supply-chain: sdk fixture ready under ${fixtureRoot} (rebased from ${realRoot})`);
}

function main(argv) {
  const [mode] = argv;
  if (mode === 'check') {
    const [lock, config, deny, pins] = argv.slice(1);
    const pinsPath = pins ? path.resolve(pins) : pinsDefault;
    let pinsData;
    try {
      pinsData = JSON.parse(fs.readFileSync(pinsPath, 'utf8'));
    } catch (error) {
      fail('E_CARGO_SUPPLY_PINS', `${pinsPath}: ${error.message}`);
    }
    const resolved = {
      lockPath: lock ? path.resolve(lock) : path.join(root, pinsData.lock),
      configPath: config ? path.resolve(config) : path.join(root, pinsData.config),
      denyPath: deny ? path.resolve(deny) : path.join(root, pinsData.deny),
      pinsPath,
    };
    const { problems, pinnedCount, lockSha } = check(resolved);
    for (const problem of problems) {
      console.error(`${problem.code} problem=cargo_supply_chain cause=${JSON.stringify(problem.message)}`);
    }
    if (problems.length > 0) {
      console.error(`cargo-supply-chain: FAIL (${problems.length} violation(s); ${pinnedCount} pinned packages)`);
      process.exit(1);
    }
    console.log(`cargo-supply-chain: OK (${pinnedCount} pinned packages; lock sha256=${lockSha})`);
    return;
  }
  if (mode === 'refresh') {
    const [lock, pins] = argv.slice(1);
    const lockPath = lock ? path.resolve(lock) : path.join(root, 'clients', 'Cargo.lock');
    const pinsPath = pins ? path.resolve(pins) : pinsDefault;
    let previous = null;
    // Previous approved catalog: the target file when it exists, else the
    // repo's real pins (so a scratch-location refresh still carries the
    // registries/toolchain pins forward — e.g. on machines without the SDK).
    for (const candidate of [pinsPath, pinsDefault]) {
      try {
        previous = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        break;
      } catch {
        // try the next candidate
      }
    }
    const data = buildPins({ lockPath, configPath: path.join(root, 'clients', '.cargo', 'config.toml'), denyPath: path.join(root, 'clients', 'deny.toml'), previousPins: previous });
    fs.writeFileSync(pinsPath, `${JSON.stringify(data, null, 2)}\n`);
    console.log(`cargo-supply-chain: refreshed ${path.relative(root, pinsPath)} (${data.packages.length} packages, ${data.sdk.tools.length} sdk tools; lock sha256=${data.lockSha256})`);
    return;
  }
  if (mode === 'mutate') {
    const [kind, input, output] = argv.slice(1);
    if (!kind || !input) usage();
    mutate(kind, path.resolve(input), output ? path.resolve(output) : path.resolve(input));
    return;
  }
  if (mode === 'sdk-fixture') {
    const [dir, absentSdkRoot] = argv.slice(1);
    if (!dir) usage();
    sdkFixture(dir, absentSdkRoot);
    return;
  }
  usage();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
