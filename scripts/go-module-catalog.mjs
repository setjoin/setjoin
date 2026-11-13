#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalogPath = process.env.GO_MODULE_CATALOG
  ? path.resolve(process.env.GO_MODULE_CATALOG)
  : path.join(root, 'config', 'go-modules.json');
const allowedKinds = new Set(['service', 'library', 'adminTool', 'ciTool', 'sidecar']);
const allowedCapabilities = new Set(['build', 'test', 'lint', 'vulnerability', 'coverage', 'crossCompile']);

function fail(code, message) {
  console.error(`${code} problem=invalid_go_module_catalog cause=${JSON.stringify(message)} location=${catalogPath} fix=update_config/go-modules.json rerun="node scripts/go-module-catalog.mjs check"`);
  process.exit(1);
}

function load() {
  let value;
  try { value = JSON.parse(fs.readFileSync(catalogPath, 'utf8')); }
  catch (error) { fail('E_ARCH_R4_GOMODS_JSON', error.message); }
  if (value.schemaVersion !== 1 || !Array.isArray(value.modules)) fail('E_ARCH_R4_GOMODS_SCHEMA', 'expected schemaVersion=1 and modules[]');
  return value.modules;
}

function validate(modules) {
  const ids = new Set();
  const paths = new Set();
  for (const mod of modules) {
    if (!/^[a-z0-9][a-z0-9-]*$/.test(mod.id ?? '')) fail('E_ARCH_R4_GOMODS_ID', `invalid id ${mod.id}`);
    if (ids.has(mod.id)) fail('E_ARCH_R4_GOMODS_DUPLICATE', `duplicate id ${mod.id}`);
    if (paths.has(mod.path)) fail('E_ARCH_R4_GOMODS_DUPLICATE', `duplicate path ${mod.path}`);
    ids.add(mod.id); paths.add(mod.path);
    if (!allowedKinds.has(mod.kind)) fail('E_ARCH_R4_GOMODS_KIND', `${mod.id}: unknown kind ${mod.kind}`);
    if (typeof mod.workspace !== 'boolean') fail('E_ARCH_R4_GOMODS_WORKSPACE', `${mod.id}: workspace must be boolean`);
    if (!Array.isArray(mod.capabilities) || mod.capabilities.length === 0) fail('E_ARCH_R4_GOMODS_CAPABILITY', `${mod.id}: capabilities required`);
    for (const capability of mod.capabilities) if (!allowedCapabilities.has(capability)) fail('E_ARCH_R4_GOMODS_CAPABILITY', `${mod.id}: unknown ${capability}`);
    const artifacts = mod.artifacts ?? [];
    if (mod.capabilities.includes('build') !== (artifacts.length > 0)) fail('E_ARCH_R4_GOMODS_ARTIFACT', `${mod.id}: build capability and artifacts must agree`);
    for (const artifact of artifacts) {
      if (typeof artifact.package !== 'string' || artifact.package === '' || typeof artifact.output !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(artifact.output)) {
        fail('E_ARCH_R4_GOMODS_ARTIFACT', `${mod.id}: invalid build artifact`);
      }
    }
    if (!fs.existsSync(path.join(root, mod.path, 'go.mod'))) fail('E_ARCH_R4_GOMODS_MISSING', `${mod.id}: ${mod.path}/go.mod missing`);
    if (!mod.workspace && mod.environment?.GOWORK !== 'off') fail('E_ARCH_R4_GOMODS_ISOLATION', `${mod.id}: isolated module must set GOWORK=off`);
  }

  const discovered = [];
  const walk = (dir, depth = 0) => {
    if (depth > 3) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.') || ['node_modules', 'test-results', 'build'].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, depth + 1);
      else if (entry.isFile() && entry.name === 'go.mod') discovered.push(path.relative(root, path.dirname(full)) || '.');
    }
  };
  walk(root);
  const catalogPaths = [...paths].sort();
  const actualPaths = discovered.sort();
  if (JSON.stringify(catalogPaths) !== JSON.stringify(actualPaths)) fail('E_ARCH_R4_GOMODS_DISCOVERY', `catalog=${catalogPaths.join(',')} discovered=${actualPaths.join(',')}`);

  const work = fs.readFileSync(path.join(root, 'go.work'), 'utf8');
  for (const mod of modules) {
    const present = work.includes(`./${mod.path}`);
    if (present !== mod.workspace) fail('E_ARCH_R4_GOMODS_WORKSPACE', `${mod.id}: catalog workspace=${mod.workspace}, go.work=${present}`);
  }
}

const modules = load();
validate(modules);
const [command, value] = process.argv.slice(2);
if (!command || command === 'check') {
  console.log(`go-module-catalog: PASS (${modules.length} modules)`);
} else if (command === 'list') {
  const selected = value ? modules.filter((mod) => mod.capabilities.includes(value)) : modules;
  if (value && !allowedCapabilities.has(value)) fail('E_ARCH_R4_GOMODS_CAPABILITY', `unknown selector ${value}`);
  for (const mod of selected) {
    console.log([mod.id, mod.path, mod.workspace ? 'workspace' : 'isolated', mod.kind,
      (mod.buildTags ?? []).join(','), mod.environment?.GOWORK ?? ''].join('\t'));
  }
} else if (command === 'get') {
  const mod = modules.find((item) => item.id === value);
  if (!mod) fail('E_ARCH_R4_GOMODS_UNKNOWN', `unknown module ${value}`);
  console.log([mod.id, mod.path, mod.workspace ? 'workspace' : 'isolated', mod.kind,
    (mod.buildTags ?? []).join(','), mod.environment?.GOWORK ?? ''].join('\t'));
} else if (command === 'artifacts') {
  for (const mod of modules.filter((item) => item.capabilities.includes('build'))) {
    for (const artifact of mod.artifacts) {
      console.log([mod.id, mod.path, mod.workspace ? 'workspace' : 'isolated',
        (mod.buildTags ?? []).join(',') || '-', mod.environment?.GOWORK ?? '-', artifact.package, artifact.output].join('\t'));
    }
  }
} else {
  fail('E_ARCH_R4_GOMODS_USAGE', `unknown command ${command}`);
}
