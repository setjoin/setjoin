#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

function die(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function loadInventory(filename) {
  let artifact;
  try {
    artifact = JSON.parse(fs.readFileSync(filename, 'utf8'));
  } catch (error) {
    die(`E_ROUTE_INVENTORY_INVALID: cannot read ${filename}: ${error.message}`);
  }
  if (artifact.schema_version !== 1 || artifact.owner !== 'merged' ||
      !Array.isArray(artifact.operations) || artifact.operations.length === 0) {
    die(`E_ROUTE_INVENTORY_INVALID: ${filename} is not a non-empty merged schema v1 artifact`);
  }
  return artifact;
}

function pinnedPrefixes(root) {
  const filename = path.join(root, 'scripts/api-pinned-prefixes.txt');
  return fs.readFileSync(filename, 'utf8')
    .split(/\r?\n/u)
    .map((line) => line.replace(/[ \t]*#.*$/u, '').trim())
    .filter(Boolean);
}

function canonicalPath(rawPath, pins) {
  const pinned = pins.some((prefix) => rawPath === prefix || rawPath.startsWith(`${prefix}/`));
  if (!pinned && !rawPath.startsWith('/api/') && rawPath !== '/api' && rawPath !== '/') {
    return `/api${rawPath}`;
  }
  return rawPath;
}

function normalizePath(rawPath) {
  return rawPath.replace(/\{[^}]+\}/gu, '{}');
}

function normalizedOperations(artifact, root) {
  const pins = pinnedPrefixes(root);
  const seen = new Set();
  return artifact.operations.map((operation) => {
    if (typeof operation.method !== 'string' || typeof operation.path !== 'string' ||
        typeof operation.owner !== 'string' || typeof operation.visibility !== 'string' ||
        !['public', 'admin'].includes(operation.visibility)) {
      die(`E_ROUTE_INVENTORY_INVALID: malformed operation ${JSON.stringify(operation)}`);
    }
    const normalized = {
      ...operation,
      method: operation.method.toUpperCase(),
      canonicalPath: canonicalPath(operation.path, pins),
      normalizedPath: normalizePath(canonicalPath(operation.path, pins)),
    };
    const key = `${normalized.method} ${normalized.normalizedPath}`;
    if (seen.has(key)) {
      die(`E_ROUTE_INVENTORY_INVALID: duplicate normalized operation ${key}`);
    }
    seen.add(key);
    return normalized;
  });
}

const [command, filename, ...args] = process.argv.slice(2);
if (!command || !filename) {
  process.stderr.write('usage: route-inventory-json.mjs routes|visibility|describe <inventory.json> [method path]\n');
  process.exit(2);
}
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const operations = normalizedOperations(loadInventory(filename), root);

if (command === 'routes') {
  const rows = operations.map((operation) => `${operation.method} ${operation.normalizedPath}`).sort();
  process.stdout.write(`${rows.join('\n')}\n`);
} else if (command === 'visibility') {
  const visibility = new Map();
  for (const operation of operations) {
    const prior = visibility.get(operation.normalizedPath);
    if (prior && prior !== operation.visibility) {
      die(`E_ROUTE_VISIBILITY_CONFLICT: ${operation.normalizedPath} is both ${prior} and ${operation.visibility}`);
    }
    visibility.set(operation.normalizedPath, operation.visibility);
  }
  const rows = [...visibility.entries()].sort(([left], [right]) => left.localeCompare(right));
  process.stdout.write(`${rows.map(([routePath, value]) => `${routePath}\t${value}`).join('\n')}\n`);
} else if (command === 'describe') {
  const [method, routePath] = args;
  if (!method || !routePath) {
    process.stderr.write('describe requires METHOD and normalized path\n');
    process.exit(2);
  }
  const operation = operations.find((candidate) =>
    candidate.method === method.toUpperCase() && candidate.normalizedPath === routePath);
  if (!operation) {
    process.exit(1);
  }
  process.stdout.write(`owner=${operation.owner}\nmount=${operation.mount || '(gateway)'}\nmiddleware=${operation.middleware || '(none)'}\nvisibility=${operation.visibility}\n`);
} else {
  process.stderr.write(`unknown command: ${command}\n`);
  process.exit(2);
}
