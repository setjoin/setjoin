#!/usr/bin/env node
/**
 * Deterministic OpenAPI 3.1 -> plain serde Rust DTO generator.
 *
 * Reads `contracts/edge/openapi/edge.v1.yaml` and emits plain
 * `serde::Serialize` / `serde::Deserialize` structs and enums into
 * `server-rust/crates/edge-contract/src/generated.rs` with ZERO OpenAPI
 * proc-macros (`utoipa`, `aide`, `schemars`, etc.).
 *
 * Nullability semantics:
 *   - required & non-null   -> `T`
 *   - required & nullable   -> `Option<T>` with `deserialize_required_nullable`
 *                              (rejects missing key, preserves explicit `null`)
 *   - optional & non-null   -> `Option<T>` with `default, skip_serializing_if`
 *   - optional & nullable   -> `Option<Option<T>>` with `default,
 *                              skip_serializing_if, deserialize_optional_nullable`
 *                              (distinguishes omitted vs explicit `null` vs value)
 *
 * Output uses deterministic ASCII codepoint sorting and is formatted to
 * satisfy `rustfmt --edition 2021 --check` directly.
 */
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

const [, , inputPath, outputPath] = process.argv;
if (!inputPath || !outputPath) {
  console.error('Usage: node gen-rust-dtos.mjs <openapi.yaml> <output.rs>');
  process.exit(2);
}

const raw = fs.readFileSync(inputPath, 'utf8');
const doc = yaml.load(raw);
if (!doc || typeof doc !== 'object' || !doc.components || !doc.components.schemas) {
  console.error(`Invalid OpenAPI document: missing components.schemas in ${inputPath}`);
  process.exit(1);
}

const asciiCompare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const RUST_KEYWORDS = new Set([
  'as', 'async', 'await', 'break', 'const', 'continue', 'crate', 'dyn', 'else',
  'enum', 'extern', 'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop',
  'match', 'mod', 'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self',
  'static', 'struct', 'super', 'trait', 'true', 'type', 'unsafe', 'use',
  'where', 'while', 'abstract', 'become', 'box', 'do', 'final', 'macro',
  'override', 'priv', 'try', 'typeof', 'unsized', 'virtual', 'yield',
]);

function schemaRustName(schemaKey) {
  const shortName = schemaKey.includes('.') ? schemaKey.split('.').pop() : schemaKey;
  return toPascalCase(shortName);
}

function toPascalCase(str) {
  return str
    .replace(/[^a-zA-Z0-9]+/g, ' ')
    .trim()
    .split(/\s+/)
    .map((part) => {
      if (!part) return '';
      if (/^[0-9]/.test(part)) return `V${part}`;
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join('');
}

function toSnakeCase(str) {
  return str
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function rustFieldIdent(wireName) {
  const snake = toSnakeCase(wireName);
  if (RUST_KEYWORDS.has(snake)) {
    return `r#${snake}`;
  }
  return snake;
}

function enumVariantName(wireValue) {
  if (wireValue === '') return 'Empty';
  if (/^[0-9]/.test(wireValue)) {
    return `V${toPascalCase(wireValue).replace(/^V/, '')}`;
  }
  return toPascalCase(wireValue);
}

function resolveRefName(ref) {
  const prefix = '#/components/schemas/';
  if (!ref.startsWith(prefix)) {
    throw new Error(`Unsupported $ref: ${ref}`);
  }
  return schemaRustName(ref.slice(prefix.length));
}

function resolveRefSchema(ref, schemas) {
  const prefix = '#/components/schemas/';
  if (!ref || !ref.startsWith(prefix)) return null;
  return schemas[ref.slice(prefix.length)] || null;
}

function isStringLikeSchema(schema, schemas) {
  if (!schema || typeof schema !== 'object') return false;
  if (schema.type === 'string') return true;
  if (schema.$ref) {
    const target = resolveRefSchema(schema.$ref, schemas);
    return target && target.type === 'string';
  }
  return false;
}

function unwrapNullableUnion(schema, schemas) {
  const branches = Array.isArray(schema.anyOf)
    ? schema.anyOf
    : Array.isArray(schema.oneOf)
      ? schema.oneOf
      : null;
  if (!branches || branches.length < 2) return null;
  const nonNull = branches.filter((s) => s && s.type !== 'null');
  const hasNull = branches.some((s) => s && s.type === 'null');
  if (!hasNull || nonNull.length === 0) return null;
  if (nonNull.length === 1) {
    return nonNull[0];
  }
  // e.g. `OfflineWindow | string | null` -> nullable `String`
  if (nonNull.every((s) => isStringLikeSchema(s, schemas))) {
    return { type: 'string' };
  }
  return null;
}

function mapSchemaType(schema, schemas) {
  if (!schema || typeof schema !== 'object') {
    return { baseRustType: 'serde_json::Value', usesValue: true, nullable: false };
  }
  if (schema.$ref) {
    const name = resolveRefName(schema.$ref);
    return { baseRustType: name, usesValue: false, nullable: false };
  }
  const nullableInner = unwrapNullableUnion(schema, schemas);
  if (nullableInner) {
    const inner = mapSchemaType(nullableInner, schemas);
    return {
      baseRustType: inner.baseRustType,
      usesValue: inner.usesValue,
      nullable: true,
    };
  }
  if (Array.isArray(schema.type)) {
    const nonNull = schema.type.filter((t) => t !== 'null');
    const hasNull = schema.type.includes('null');
    if (hasNull && nonNull.length === 1) {
      const inner = mapSchemaType({ ...schema, type: nonNull[0] }, schemas);
      return {
        baseRustType: inner.baseRustType,
        usesValue: inner.usesValue,
        nullable: true,
      };
    }
  }
  if (schema.type === 'string') {
    return { baseRustType: 'String', usesValue: false, nullable: false };
  }
  if (schema.type === 'boolean') {
    return { baseRustType: 'bool', usesValue: false, nullable: false };
  }
  if (schema.type === 'integer') {
    if (schema.format === 'int64') {
      return { baseRustType: 'i64', usesValue: false, nullable: false };
    }
    return { baseRustType: 'i32', usesValue: false, nullable: false };
  }
  if (schema.type === 'number') {
    return { baseRustType: 'serde_json::Value', usesValue: true, nullable: false };
  }
  if (schema.type === 'array') {
    const item = mapSchemaType(schema.items, schemas);
    const itemTy = item.nullable ? `Option<${item.baseRustType}>` : item.baseRustType;
    return {
      baseRustType: `Vec<${itemTy}>`,
      usesValue: item.usesValue,
      nullable: false,
    };
  }
  if (schema.type === 'object') {
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      if (Object.keys(schema.additionalProperties).length === 0) {
        return {
          baseRustType: 'std::collections::BTreeMap<String, serde_json::Value>',
          usesValue: true,
          nullable: false,
        };
      }
      const val = mapSchemaType(schema.additionalProperties, schemas);
      const valTy = val.nullable ? `Option<${val.baseRustType}>` : val.baseRustType;
      return {
        baseRustType: `std::collections::BTreeMap<String, ${valTy}>`,
        usesValue: val.usesValue,
        nullable: false,
      };
    }
    return {
      baseRustType: 'std::collections::BTreeMap<String, serde_json::Value>',
      usesValue: true,
      nullable: false,
    };
  }
  return { baseRustType: 'serde_json::Value', usesValue: true, nullable: false };
}

function docLines(text) {
  if (!text) return [];
  return String(text)
    .trim()
    .split(/\r?\n/)
    .map((line) => `/// ${line.trim()}`);
}

const schemas = doc.components.schemas;
const schemaKeys = Object.keys(schemas).sort(asciiCompare);

// Detect short-name collisions across namespaces.
const seenNames = new Map();
for (const key of schemaKeys) {
  const rustName = schemaRustName(key);
  if (seenNames.has(rustName)) {
    throw new Error(`Duplicate Rust DTO name ${rustName} from ${seenNames.get(rustName)} and ${key}`);
  }
  seenNames.set(rustName, key);
}

function collectRefs(schema, refs) {
  if (!schema || typeof schema !== 'object') return;
  if (schema.$ref) refs.add(resolveRefName(schema.$ref));
  if (schema.items) collectRefs(schema.items, refs);
  if (Array.isArray(schema.anyOf)) schema.anyOf.forEach((s) => collectRefs(s, refs));
  if (Array.isArray(schema.oneOf)) schema.oneOf.forEach((s) => collectRefs(s, refs));
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
    collectRefs(schema.additionalProperties, refs);
  }
}

// Compute which schemas transitively use `serde_json::Value` (cannot derive Eq).
const directUsesValue = new Map();
const refsMap = new Map();

for (const key of schemaKeys) {
  const schema = schemas[key];
  const rustName = schemaRustName(key);
  let usesValue = false;
  const refs = new Set();

  if (schema.type === 'object') {
    if (schema.additionalProperties !== undefined && schema.additionalProperties !== false) {
      if (typeof schema.additionalProperties === 'object' && Object.keys(schema.additionalProperties).length === 0) {
        usesValue = true;
      } else if (schema.additionalProperties === true) {
        usesValue = true;
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        const mapped = mapSchemaType(schema.additionalProperties, schemas);
        if (mapped.usesValue) usesValue = true;
      }
    }
    const props = schema.properties || {};
    for (const propSchema of Object.values(props)) {
      const mapped = mapSchemaType(propSchema, schemas);
      if (mapped.usesValue) usesValue = true;
      collectRefs(propSchema, refs);
    }
  } else if (Array.isArray(schema.anyOf) || Array.isArray(schema.oneOf)) {
    collectRefs(schema, refs);
  }
  directUsesValue.set(rustName, usesValue);
  refsMap.set(rustName, refs);
}

const transitiveUsesValue = new Map(directUsesValue);
let changed = true;
while (changed) {
  changed = false;
  for (const [name, refs] of refsMap.entries()) {
    if (transitiveUsesValue.get(name)) continue;
    for (const r of refs) {
      if (transitiveUsesValue.get(r)) {
        transitiveUsesValue.set(name, true);
        changed = true;
        break;
      }
    }
  }
}

const bodyLines = [];
let needsRequiredNullableHelper = false;
let needsOptionalNullableHelper = false;

// Emit in deterministic ASCII codepoint order by Rust type name.
const orderedEntries = schemaKeys
  .map((key) => ({ key, rustName: schemaRustName(key), schema: schemas[key] }))
  .sort((a, b) => asciiCompare(a.rustName, b.rustName));

for (const { rustName, schema } of orderedEntries) {
  // Skip TypeSpec wrapper models like Common.ForbiddenProblem or Common.NotFoundTextResponse
  // that only wrap `body: ProblemDetails` / `body: string`.
  if (
    schema.type === 'object' &&
    schema.properties &&
    Object.keys(schema.properties).length === 1 &&
    schema.properties.body &&
    (schema.properties.body.$ref === '#/components/schemas/Common.ProblemDetails' ||
      schema.properties.body.type === 'string')
  ) {
    continue;
  }

  for (const line of docLines(schema.description)) {
    bodyLines.push(line);
  }

  if (schema.type === 'string' && Array.isArray(schema.enum)) {
    bodyLines.push('#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]');
    bodyLines.push(`pub enum ${rustName} {`);
    for (const val of schema.enum) {
      const variant = enumVariantName(String(val));
      if (variant !== String(val)) {
        bodyLines.push(`    #[serde(rename = ${JSON.stringify(String(val))})]`);
      }
      bodyLines.push(`    ${variant},`);
    }
    bodyLines.push('}');
    bodyLines.push('');
    continue;
  }

  // Discriminated or untagged union of object $refs (e.g., Delivery.MessageTrace).
  const unionBranches = Array.isArray(schema.anyOf)
    ? schema.anyOf
    : Array.isArray(schema.oneOf)
      ? schema.oneOf
      : null;
  if (unionBranches && unionBranches.every((b) => b && typeof b.$ref === 'string')) {
    const canEq = !transitiveUsesValue.get(rustName);
    if (canEq) {
      bodyLines.push('#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]');
    } else {
      bodyLines.push('#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]');
    }
    bodyLines.push('#[serde(untagged)]');
    bodyLines.push(`pub enum ${rustName} {`);
    for (const branch of unionBranches) {
      const targetName = resolveRefName(branch.$ref);
      bodyLines.push(`    ${targetName}(${targetName}),`);
    }
    bodyLines.push('}');
    bodyLines.push('');
    continue;
  }

  if (schema.type === 'object') {
    const canEq = !transitiveUsesValue.get(rustName);
    if (canEq) {
      bodyLines.push('#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]');
    } else {
      bodyLines.push('#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]');
    }
    bodyLines.push(`pub struct ${rustName} {`);

    const requiredSet = new Set(Array.isArray(schema.required) ? schema.required : []);
    const props = schema.properties || {};

    for (const [wireName, propSchema] of Object.entries(props)) {
      const fieldIdent = rustFieldIdent(wireName);
      const isRequired = requiredSet.has(wireName);
      const mapped = mapSchemaType(propSchema, schemas);
      const baseType = mapped.baseRustType.replaceAll('std::collections::BTreeMap', 'BTreeMap');
      const rawFieldName = fieldIdent.startsWith('r#') ? fieldIdent.slice(2) : fieldIdent;

      const attrs = [];
      if (rawFieldName !== wireName) {
        attrs.push(`rename = ${JSON.stringify(wireName)}`);
      }

      let rustType;
      if (isRequired && !mapped.nullable) {
        rustType = baseType;
      } else if (isRequired && mapped.nullable) {
        rustType = `Option<${baseType}>`;
        attrs.push('deserialize_with = "deserialize_required_nullable"');
        needsRequiredNullableHelper = true;
      } else if (!isRequired && !mapped.nullable) {
        rustType = `Option<${baseType}>`;
        attrs.push('default');
        attrs.push('skip_serializing_if = "Option::is_none"');
      } else {
        // Optional AND nullable: distinguish omitted (`None`) vs explicit `null` (`Some(None)`) vs value (`Some(Some(v))`).
        rustType = `Option<Option<${baseType}>>`;
        attrs.push('default');
        attrs.push('skip_serializing_if = "Option::is_none"');
        attrs.push('deserialize_with = "deserialize_optional_nullable"');
        needsOptionalNullableHelper = true;
      }

      if (attrs.length > 0) {
        const attrLine = `    #[serde(${attrs.join(', ')})]`;
        if (attrLine.length > 84) {
          bodyLines.push('    #[serde(');
          attrs.forEach((a, idx) => {
            const comma = idx < attrs.length - 1 ? ',' : '';
            bodyLines.push(`        ${a}${comma}`);
          });
          bodyLines.push('    )]');
        } else {
          bodyLines.push(attrLine);
        }
      }
      bodyLines.push(`    pub ${fieldIdent}: ${rustType},`);
    }

    if (schema.additionalProperties !== undefined && schema.additionalProperties !== false) {
      bodyLines.push('    #[serde(flatten)]');
      bodyLines.push('    pub extra: BTreeMap<String, serde_json::Value>,');
    }

    bodyLines.push('}');
    bodyLines.push('');
    continue;
  }

  throw new Error(`Unsupported top-level schema kind for ${rustName}: ${JSON.stringify(schema)}`);
}

const out = [];
out.push('// @generated by contracts/edge/scripts/gen-rust-dtos.mjs from contracts/edge/openapi/edge.v1.yaml.');
out.push('// DO NOT EDIT MANUALLY. Re-run `npm run build` in `contracts/edge/`.');
out.push('');
out.push('#![allow(clippy::derive_partial_eq_without_eq)]');
out.push('');
out.push('use serde::{Deserialize, Serialize};');
out.push('use std::collections::BTreeMap;');
out.push('');

if (needsRequiredNullableHelper) {
  out.push('fn deserialize_required_nullable<\'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>');
  out.push('where');
  out.push('    D: serde::Deserializer<\'de>,');
  out.push('    T: Deserialize<\'de>,');
  out.push('{');
  out.push('    Option::<T>::deserialize(deserializer)');
  out.push('}');
  out.push('');
}

if (needsOptionalNullableHelper) {
  out.push('fn deserialize_optional_nullable<\'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>');
  out.push('where');
  out.push('    D: serde::Deserializer<\'de>,');
  out.push('    T: Deserialize<\'de>,');
  out.push('{');
  out.push('    Option::<T>::deserialize(deserializer).map(Some)');
  out.push('}');
  out.push('');
}

out.push(...bodyLines);

// Emit canonical contract metadata constants (ASCII sorted).
const paths = Object.keys(doc.paths || {}).sort(asciiCompare);
out.push('/// OpenAPI 3.1 contract version embedded at generation time.');
out.push(`pub const OPENAPI_VERSION: &str = ${JSON.stringify(String(doc.openapi || '3.1.0'))};`);
out.push('');
out.push('/// Contracted `(METHOD, path)` pairs emitted from `contracts/edge/openapi/edge.v1.yaml`.');
out.push('pub const CONTRACTED_OPERATIONS: &[(&str, &str)] = &[');
const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];
for (const p of paths) {
  const pathItem = doc.paths[p] || {};
  for (const m of HTTP_METHODS) {
    if (pathItem[m]) {
      out.push(`    (${JSON.stringify(m.toUpperCase())}, ${JSON.stringify(p)}),`);
    }
  }
}
out.push('];');
out.push('');

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, out.join('\n'), 'utf8');
console.log(`Generated ${outputPath} (${orderedEntries.length} schemas, ${paths.length} paths)`);
