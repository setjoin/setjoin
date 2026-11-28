#!/usr/bin/env node
// vendor-excalidraw-fonts.mjs — re-vendors the whiteboard font tree from the
// pinned npm artifact into static/excalidraw/fonts/ and writes the sha256
// pin manifest (excalidraw-fonts.json) that src/lib/theme/font-shards.test.ts
// enforces. Closes the D-MAILSERVER-WEBMAIL-STATIC-EXCALIDRAW-FONTS-* pin
// gap (incl. the 209-shard Xiaolai tree): before this, the committed copies
// had no automated integrity pin binding them to the pinned package.
//
// Integrity chain (no network here — npm already did that work):
//   registry tarball --sha512 (package-lock.json integrity)--> node_modules
//   node_modules/dist/prod/fonts --byte copy (this script)--> static tree
//   static tree + manifest --sha256 per file (vitest)--> pinned-clean or red
//
// Run this ONCE per package bump, then commit the refreshed static tree +
// manifest together:
//
//   node scripts/vendor-excalidraw-fonts.mjs
//
// Re-run safe: the static tree is mirrored to exactly the pinned package's
// font set — stale files (dropped/renamed shards from an older package) are
// removed BEFORE copying, so the deployed set is always pinned-clean or the
// script fails loudly. The manifest itself is deterministic (sorted keys and
// file list) so re-runs produce byte-identical output.
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const webmail = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageJsonPath = join(webmail, 'package.json');
const lockfilePath = join(webmail, 'package-lock.json');
const packageDir = join(webmail, 'node_modules/@excalidraw/excalidraw');
const sourceDir = join(packageDir, 'dist/prod/fonts');
const outputDir = join(webmail, 'static/excalidraw/fonts');
const manifestPath = join(outputDir, 'excalidraw-fonts.json');
const PACKAGE_NAME = '@excalidraw/excalidraw';

function sha256(buf) {
	return createHash('sha256').update(buf).digest('hex');
}

function fail(message) {
	console.error(`E_EXCALIDRAW_FONTS problem=vendoring-refused cause=${message}`);
	process.exit(1);
}

const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
const wantedSpec = packageJson.dependencies?.[PACKAGE_NAME];
if (!wantedSpec) fail(`${PACKAGE_NAME} missing from package.json dependencies`);
// The byte-identity contract only means something against an exact pin; a
// range would let npm resolve a different artifact than the manifest pinned.
if (!/^\d+\.\d+\.\d+$/.test(wantedSpec)) {
	fail(`package.json pin for ${PACKAGE_NAME} must be exact, got "${wantedSpec}"`);
}

const lockfile = JSON.parse(readFileSync(lockfilePath, 'utf8'));
const lockEntry = lockfile.packages?.[`node_modules/${PACKAGE_NAME}`];
if (!lockEntry) fail(`${PACKAGE_NAME} missing from package-lock.json`);
if (lockEntry.version !== wantedSpec) {
	fail(`lockfile version ${lockEntry.version} != package.json pin ${wantedSpec} — run npm install first`);
}
if (!lockEntry.resolved || !lockEntry.integrity) {
	fail('lockfile entry lacks resolved URL / integrity — cannot record provenance');
}

const installedVersion = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8')).version;
if (installedVersion !== wantedSpec) {
	fail(`installed package version ${installedVersion} != pinned ${wantedSpec} — run npm install first`);
}
if (!existsSync(sourceDir)) fail(`pinned package font tree missing: ${sourceDir}`);

// Collect the package's own font set (recursive, sorted for determinism).
function walk(dir) {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const full = join(dir, entry.name);
		return entry.isDirectory() ? walk(full) : [full];
	});
}
const sourceFiles = walk(sourceDir);
const unexpected = sourceFiles.filter((file) => !file.endsWith('.woff2'));
if (unexpected.length > 0) fail(`non-woff2 file(s) in package font tree: ${unexpected.join(', ')}`);
const relatives = sourceFiles.map((file) => relative(sourceDir, file)).sort();
if (relatives.length === 0) fail('package font tree is empty');

// Mirror BEFORE any copy: drop stale files so a removed/renamed upstream
// shard cannot survive as an unaccounted deployed asset. The manifest is
// regenerated below, so it is never a stale-file casualty.
if (existsSync(outputDir)) {
	for (const entry of walk(outputDir)) {
		const rel = relative(outputDir, entry);
		if (rel === 'excalidraw-fonts.json') continue;
		if (!relatives.includes(rel)) rmSync(entry);
	}
} else {
	mkdirSync(outputDir, { recursive: true });
}

// Files the repository deliberately replaces (licence reasons) are listed in
// the existing manifest's "replacements"; their static bytes are kept as-is.
const replacements = existsSync(manifestPath) ? (JSON.parse(readFileSync(manifestPath, 'utf8')).replacements ?? []) : [];
const replacedPaths = new Set(replacements.map((entry) => entry.path));

const files = [];
for (const rel of relatives) {
	const bytes = readFileSync(join(replacedPaths.has(rel) ? outputDir : sourceDir, rel));
	const destination = join(outputDir, rel);
	mkdirSync(join(destination, '..'), { recursive: true });
	writeFileSync(destination, bytes);
	files.push({ path: rel, bytes: bytes.length, sha256: sha256(bytes) });
}

const manifest = {
	version: 1,
	package: PACKAGE_NAME,
	packageVersion: wantedSpec,
	// Provenance of record: the registry artifact npm's own installer
	// verified against `integrity`. Per-file sha256 pins below are the
	// deployed-tree pin; upstream publishes no per-file checksums.
	source: {
		registry: lockEntry.resolved,
		tarballIntegrity: lockEntry.integrity,
		packageTree: 'node_modules/@excalidraw/excalidraw/dist/prod/fonts',
	},
	license: { spdx: 'MIT', note: 'font files ride with the pinned package, vendored verbatim, except the replacements below' },
	replacements,
	files,
};

writeFileSync(manifestPath, JSON.stringify(manifest, null, '\t') + '\n');
console.log(`[vendor-excalidraw-fonts] mirrored ${files.length} woff2 files from ${PACKAGE_NAME}@${wantedSpec} and pinned them in static/excalidraw/fonts/excalidraw-fonts.json`);
