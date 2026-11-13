#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourceDir = process.env.EXCHANGE_REPLACEMENT_SOURCE_DIR
  ? resolve(process.env.EXCHANGE_REPLACEMENT_SOURCE_DIR)
  : resolve(root, 'config/exchange-replacement');
const generatedDir = resolve(sourceDir, 'generated');
const paths = {
  registry: resolve(sourceDir, 'registry-v1.json'),
  catalog: resolve(sourceDir, 'discovery-catalog-v1.json'),
  cells: resolve(sourceDir, 'support-cells-v1.json'),
  redaction: resolve(sourceDir, 'redaction-profiles-v1.json'),
  compatibility: resolve(sourceDir, 'compatibility-v1.json'),
  json: resolve(generatedDir, 'exchange-replacement-v1.json'),
  sql: resolve(root, 'mailserver/sql/dbschema/V214__exchange_replacement_registry_projection.sql'),
  docs: resolve(generatedDir, 'exchange-replacement-docs-v1.json')
  ,comparison: resolve(generatedDir, 'exchange-replacement-comparison-v1.md')
  ,cli: resolve(root, 'mailctl/exchange_registry_v1.json')
};

const allowed = {
  category: new Set(['calendar', 'mailbox', 'resource', 'migration', 'security', 'compliance', 'directory', 'identity', 'transport', 'client', 'collaboration', 'hybrid', 'access', 'infrastructure', 'operations', 'administration']),
  mapping: new Set(['native', 'transformed', 'alternative', 'none']),
  claim: new Set(['supported', 'provisional', 'experimental', 'unassessed', 'unsupported', 'excluded']),
  phase: new Set(['assessment', 'migration', 'initial_copy', 'coexistence', 'cutover', 'rollback']),
  impact: new Set(['cosmetic', 'degraded', 'blocker'])
};

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function requireValue(condition, message) {
  if (!condition) throw new Error(`E_EXCHANGE_REGISTRY_INVALID ${message}`);
}

function unique(items, label) {
  const seen = new Set();
  for (const item of items) {
    requireValue(!seen.has(item), `duplicate ${label} ${item}`);
    seen.add(item);
  }
  return seen;
}

function validate(input) {
  requireValue(input.registry.schemaVersion === 'setjoin.exchange.registry/v1', 'unsupported registry schema');
  requireValue(input.catalog.schemaVersion === 'setjoin.exchange.discovery-catalog/v1', 'unsupported catalog schema');
  requireValue(input.compatibility.schemaVersion === 'setjoin.exchange.compatibility/v1', 'unsupported compatibility schema');
  // Version fields are typed, integral, and cross-checked against the
  // compatibility contract before they are interpolated into the generated SQL
  // projection (D-CONFIG-002: generated-artifact injection hardening). A
  // non-numeric or out-of-contract version must fail the build here, never
  // reach the emitted `INSERT ... VALUES (${registryVersion}, ...)`.
  requireValue(typeof input.registry.registryVersion === 'number' && Number.isInteger(input.registry.registryVersion) && input.registry.registryVersion >= 1, 'registry version must be an integer >= 1');
  requireValue(typeof input.catalog.catalogVersion === 'number' && Number.isInteger(input.catalog.catalogVersion) && input.catalog.catalogVersion >= 1, 'catalog version must be an integer >= 1');
  requireValue(input.compatibility.acceptedRegistryVersions.includes(input.registry.registryVersion), `registry version ${input.registry.registryVersion} is not in compatibility.acceptedRegistryVersions`);
  requireValue(input.compatibility.acceptedCatalogVersions.includes(input.catalog.catalogVersion), `catalog version ${input.catalog.catalogVersion} is not in compatibility.acceptedCatalogVersions`);
  requireValue(input.compatibility.featureDefault === 'off', 'Exchange assessment feature must default off');
  requireValue(input.compatibility.acceptedBundleSchemas.length > 0, 'compatibility bundle range is empty');
  requireValue(input.compatibility.unknownFieldPolicy === 'reject_before_import', 'unknown fields must fail before import');
  const capabilityIds = unique(input.registry.capabilities.map((item) => item.id), 'capability ID');
  const rootIds = unique(input.catalog.roots.map((item) => item.id), 'root ID');
  unique(input.catalog.probes.map((item) => item.id), 'probe ID');
  unique(input.cells.cells.map((item) => item.id), 'support-cell ID');
  unique(input.redaction.profiles.map((item) => item.id), 'redaction-profile ID');
  for (const root of input.catalog.roots) {
    // Root enumerators become collector commands the same way probes do —
    // hold them to the identical read-only Get-* allowlist grammar.
    requireValue(/^Get-[A-Za-z0-9]+$/.test(root.enumerator), `${root.id} enumerator is not allowlisted read-only Get-*`);
  }
  for (const cell of input.cells.cells) {
    requireValue(input.compatibility.collectorVersions.includes(cell.collectorVersion), `${cell.id} collectorVersion ${cell.collectorVersion} is not in compatibility.collectorVersions`);
  }
  for (const capability of input.registry.capabilities) {
    requireValue(/^EX-[A-Z0-9-]+$/.test(capability.id), `bad capability ID ${capability.id}`);
    requireValue(capability.outcome?.zh && capability.outcome?.en, `${capability.id} lacks bilingual outcome`);
    requireValue(allowed.category.has(capability.category), `${capability.id} unknown category`);
    requireValue(allowed.mapping.has(capability.mappingMaximum), `${capability.id} unknown mapping maximum`);
    requireValue(allowed.claim.has(capability.claimMaximum), `${capability.id} unknown claim maximum`);
    requireValue(capability.implementationUnits.length > 0, `${capability.id} lacks implementation unit`);
    requireValue(capability.sourceProperties.length > 0, `${capability.id} lacks source properties`);
    for (const impact of capability.phaseImpacts) {
      requireValue(allowed.phase.has(impact.phase), `${capability.id} unknown phase`);
      requireValue(allowed.impact.has(impact.impact), `${capability.id} unknown impact`);
    }
  }
  const probedCapabilities = new Set();
  for (const probe of input.catalog.probes) {
    requireValue(rootIds.has(probe.rootId), `${probe.id} references missing root ${probe.rootId}`);
    requireValue(probe.capabilityIds.length > 0, `${probe.id} has no capabilities`);
    for (const id of probe.capabilityIds) { requireValue(capabilityIds.has(id), `${probe.id} references missing capability ${id}`); probedCapabilities.add(id); }
    requireValue(/^Get-[A-Za-z0-9]+$/.test(probe.command), `${probe.id} command is not allowlisted read-only Get-*`);
  }
  for (const id of capabilityIds) requireValue(probedCapabilities.has(id), `${id} has no discovery probe`);
}

async function compile() {
  const [registry, catalog, cells, redaction, compatibility] = await Promise.all(
    [paths.registry, paths.catalog, paths.cells, paths.redaction, paths.compatibility].map(async (path) => JSON.parse(await readFile(path, 'utf8')))
  );
  const input = { registry, catalog, cells, redaction, compatibility };
  validate(input);
  const sourceDigest = createHash('sha256').update(canonical(input)).digest('hex');
  const projection = {
    schemaVersion: 'setjoin.exchange.projection/v1',
    registryVersion: registry.registryVersion,
    catalogVersion: catalog.catalogVersion,
    sourceDigest,
    generatedFrom: ['registry-v1.json', 'discovery-catalog-v1.json', 'support-cells-v1.json', 'redaction-profiles-v1.json', 'compatibility-v1.json'],
	compatibility,
    capabilities: [...registry.capabilities].sort((a, b) => a.id.localeCompare(b.id)),
    roots: [...catalog.roots].sort((a, b) => a.id.localeCompare(b.id)),
    probes: [...catalog.probes].sort((a, b) => a.id.localeCompare(b.id)),
    supportCells: [...cells.cells].sort((a, b) => a.id.localeCompare(b.id)).map((cell) => ({
      ...cell,
      digest: createHash('sha256').update(canonical(cell)).digest('hex')
    })),
    redactionProfiles: [...redaction.profiles].sort((a, b) => a.id.localeCompare(b.id))
  };
  const json = `${JSON.stringify(projection, null, 2)}\n`;
  const sqlJSON = JSON.stringify(projection).replaceAll("'", "''");
  const sql = `-- Code generated by scripts/exchange-replacement-registry.mjs; DO NOT EDIT.\n-- source-digest: ${sourceDigest}\nINSERT INTO public.exchange_registry_snapshots (registry_version, source_digest, projection)\nVALUES (${registry.registryVersion}, '${sourceDigest}', '${sqlJSON}'::jsonb)\nON CONFLICT (registry_version) DO NOTHING;\n\nINSERT INTO public.schema_migrations (version, applied_at) VALUES (214, now()) ON CONFLICT (version) DO NOTHING;\n`;
  const docs = `${JSON.stringify({ schemaVersion: 'setjoin.exchange.docs-input/v1', registryVersion: registry.registryVersion, sourceDigest, capabilities: projection.capabilities.map(({ id, outcome, category, mappingMaximum, claimMaximum, documentation }) => ({ id, outcome, category, mappingMaximum, claimMaximum, documentation })) }, null, 2)}\n`;
  const comparisonRows = projection.capabilities.map((capability) => `| ${capability.id} | ${capability.outcome.zh}<br>${capability.outcome.en} | ${capability.category} | ${capability.mappingMaximum} | ${capability.claimMaximum} | ${capability.documentation} |`).join('\n');
  const comparison = `# Setjoin 与 Exchange 功能结果目录 / Outcome catalog\n\n> 由注册表 v${registry.registryVersion} 自动生成。摘要：\`${sourceDigest}\`。所有单元当前仅表示可评估的结果范围；只有证据解析器可提升支持声明，\`unassessed\` 不等于不使用或已支持。\n> Generated from registry v${registry.registryVersion}. Only the evidence resolver may promote support claims; unassessed never means unused or supported.\n\n| Capability ID | 结果 / Outcome | Category | Mapping ceiling | Claim ceiling | Reference |\n|---|---|---|---|---|---|\n${comparisonRows}\n`;
  return { json, sql, docs, comparison, sourceDigest };
}

async function main() {
  const mode = process.argv[2];
  requireValue(mode === '--write' || mode === '--check', 'usage: exchange-replacement-registry.mjs --write|--check');
  const output = await compile();
  const expected = [[paths.json, output.json], [paths.sql, output.sql], [paths.docs, output.docs], [paths.comparison, output.comparison], [paths.cli, output.json]];
  if (mode === '--write') {
    await mkdir(generatedDir, { recursive: true });
    await Promise.all(expected.map(([path, body]) => writeFile(path, body, { mode: 0o644 })));
  } else {
    for (const [path, body] of expected) requireValue(await readFile(path, 'utf8') === body, `generated projection drift at ${path}`);
    const parsed = JSON.parse(await readFile(paths.json, 'utf8'));
    requireValue(parsed.sourceDigest === output.sourceDigest, 'compile/load/export digest mismatch');
  }
  process.stdout.write(`exchange_replacement_registry_ok digest=${output.sourceDigest}\n`);
}

main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
