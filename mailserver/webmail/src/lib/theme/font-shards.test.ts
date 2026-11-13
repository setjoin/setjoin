import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type Shard = {
	name: string;
	file: string;
	bytes: number;
	sha256: string;
	glyph_codepoints: number;
	unicode_ranges: string[];
};

type Weight = {
	source: string;
	source_bytes: number;
	source_sha256: string;
	covered_codepoints: number;
	product_codepoints: number;
	shards: Shard[];
};

type Manifest = {
	version: number;
	family: string;
	license: { spdx: string };
	generator: { fonttools: string; brotli: string };
	weights: Record<string, Weight>;
};

const themeDir = dirname(fileURLToPath(import.meta.url));
const webmail = resolve(themeDir, '../../..');
const staticFonts = join(webmail, 'static/fonts');
const manifest = JSON.parse(readFileSync(join(staticFonts, 'noto-sans-sc-shards.json'), 'utf8')) as Manifest;
const css = readFileSync(join(themeDir, 'fonts-cjk.generated.css'), 'utf8');

type ExcalidrawFontPin = {
	path: string;
	bytes: number;
	sha256: string;
};

type ExcalidrawManifest = {
	version: number;
	package: string;
	packageVersion: string;
	source: { registry: string; tarballIntegrity: string; packageTree: string };
	license: { spdx: string; note: string };
	replacements?: { path: string }[];
	files: ExcalidrawFontPin[];
};

const excalidrawFonts = join(webmail, 'static/excalidraw/fonts');
const excalidrawManifest = JSON.parse(
	readFileSync(join(excalidrawFonts, 'excalidraw-fonts.json'), 'utf8'),
) as ExcalidrawManifest;
const excalidrawSpec = (
	JSON.parse(readFileSync(join(webmail, 'package.json'), 'utf8')) as { dependencies: Record<string, string> }
).dependencies['@excalidraw/excalidraw'];
const excalidrawLockEntry = (
	JSON.parse(readFileSync(join(webmail, 'package-lock.json'), 'utf8')) as {
		packages: Record<string, { version?: string; resolved?: string; integrity?: string }>;
	}
).packages['node_modules/@excalidraw/excalidraw'];
const packageFonts = join(webmail, 'node_modules/@excalidraw/excalidraw/dist/prod/fonts');

function walkRelative(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		if (!entry.isDirectory()) return [entry.name];
		return walkRelative(join(dir, entry.name)).map((name) => join(entry.name, name));
	});
}

function sha256(path: string): string {
	return createHash('sha256').update(readFileSync(path)).digest('hex');
}

// Hashing the full ~13MB tree twice (static + installed package) is the
// point of the excalidraw pins below; memoize the static pass so the two
// tests share it.
let deployedHashes: Map<string, string> | undefined;
function hashesOfDeployed(): Map<string, string> {
	deployedHashes ??= new Map(
		excalidrawManifest.files.map((shard) => [shard.path, sha256(join(excalidrawFonts, shard.path))]),
	);
	return deployedHashes;
}

function expandRange(value: string): number[] {
	const match = /^U\+([0-9A-F]+)(?:-([0-9A-F]+))?$/.exec(value);
	if (!match) throw new Error(`invalid unicode range: ${value}`);
	const start = Number.parseInt(match[1], 16);
	const end = Number.parseInt(match[2] ?? match[1], 16);
	if (end < start) throw new Error(`reversed unicode range: ${value}`);
	return Array.from({ length: end - start + 1 }, (_, offset) => start + offset);
}

describe('physical CJK fallback shards', () => {
	it('keeps pinned monolithic sources outside the deployed static tree', () => {
		expect(manifest.version).toBe(1);
		expect(manifest.family).toBe('Setjoin Noto SC Fallback');
		expect(manifest.license.spdx).toBe('OFL-1.1');
		expect(manifest.generator).toEqual({ fonttools: '4.63.0', brotli: '1.2.0' });
		for (const weight of ['400', '500', '600', '700']) {
			expect(existsSync(join(staticFonts, `noto-sans-sc-${weight}.woff2`))).toBe(false);
			const source = join(webmail, manifest.weights[weight].source.replace(/^assets\//, 'assets/'));
			expect(source).not.toContain(`${join(webmail, 'static')}/`);
			expect(statSync(source).size).toBe(manifest.weights[weight].source_bytes);
			expect(sha256(source)).toBe(manifest.weights[weight].source_sha256);
		}
	});

	it('binds every declared non-overlapping range to an exact output hash', () => {
		const expectedFiles = new Set<string>();
		for (const [weight, record] of Object.entries(manifest.weights)) {
			const seen = new Set<number>();
			let declared = 0;
			for (const shard of record.shards) {
				const relative = shard.file.replace(/^\/fonts\//, '');
				expect(relative).toMatch(new RegExp(`^noto-sans-sc-${weight}-(core|r\\d{2})\\.woff2$`));
				expectedFiles.add(relative);
				const path = join(staticFonts, relative);
				expect(statSync(path).size).toBe(shard.bytes);
				expect(sha256(path)).toBe(shard.sha256);
				expect(css).toContain(`url('${shard.file}')`);
				expect(css).toContain(`unicode-range: ${shard.unicode_ranges.join(', ')};`);
				const codepoints = shard.unicode_ranges.flatMap(expandRange);
				expect(new Set(codepoints).size).toBe(codepoints.length);
				for (const codepoint of codepoints) {
					expect(seen.has(codepoint), `overlap U+${codepoint.toString(16)} at weight ${weight}`).toBe(false);
					seen.add(codepoint);
				}
				expect(codepoints.length).toBe(shard.glyph_codepoints);
				declared += shard.glyph_codepoints;
			}
			expect(declared).toBe(record.covered_codepoints);
			expect(record.shards[0].name).toBe('core');
			expect(record.shards[0].glyph_codepoints).toBe(record.product_codepoints);
		}

		const actualFiles = readdirSync(staticFonts).filter((name) => /^noto-sans-sc-\d+-(?:core|r\d{2})\.woff2$/.test(name));
		expect(actualFiles.sort()).toEqual([...expectedFiles].sort());
	});
});

describe('vendored excalidraw font shards', () => {
	it('binds the deployed tree to the exact pinned npm artifact', () => {
		expect(excalidrawManifest.version).toBe(1);
		expect(excalidrawManifest.package).toBe('@excalidraw/excalidraw');
		// The byte-identity contract only means something against an exact
		// pin: a range here would let npm resolve a different artifact than
		// the manifest's recorded provenance.
		expect(excalidrawSpec).toMatch(/^\d+\.\d+\.\d+$/);
		expect(excalidrawManifest.packageVersion).toBe(excalidrawSpec);
		expect(excalidrawLockEntry?.version).toBe(excalidrawSpec);
		// Provenance of record: the registry artifact npm's own installer
		// verified against this integrity string at install time.
		expect(excalidrawManifest.source.registry).toBe(excalidrawLockEntry?.resolved);
		expect(excalidrawManifest.source.tarballIntegrity).toBe(excalidrawLockEntry?.integrity);
		expect(excalidrawManifest.source.tarballIntegrity).toMatch(/^sha512-/);
	});

	it('pins every deployed woff2 byte-for-byte, with no extra or missing shards', () => {
		const pinned = excalidrawManifest.files.map((shard) => shard.path);
		expect(pinned).toEqual([...pinned].sort());
		const deployed = walkRelative(excalidrawFonts).filter((name) => name !== 'excalidraw-fonts.json');
		expect(deployed.sort()).toEqual(pinned);
		for (const shard of excalidrawManifest.files) {
			const path = join(excalidrawFonts, shard.path);
			expect(statSync(path).size).toBe(shard.bytes);
			expect(hashesOfDeployed().get(shard.path)).toBe(shard.sha256);
		}
	});

	it('keeps the committed copies byte-identical to the installed pinned package', () => {
		// Drift detector for the vendored-copy contract (webmail AGENTS.md):
		// a package bump without re-running scripts/vendor-excalidraw-fonts.mjs
		// fails here instead of silently serving stale/tampered shards. The
		// static side already proved it hashes to its pin above; hashing the
		// installed package copy against the SAME pin is byte-identity.
		const packageFiles = walkRelative(packageFonts).sort();
		expect(packageFiles).toEqual(excalidrawManifest.files.map((shard) => shard.path));
		// Deliberate licence replacements (manifest "replacements") differ from the package by design.
		const replaced = new Set((excalidrawManifest.replacements ?? []).map((entry) => entry.path));
		for (const shard of excalidrawManifest.files) {
			if (replaced.has(shard.path)) continue;
			expect(sha256(join(packageFonts, shard.path)), shard.path).toBe(hashesOfDeployed().get(shard.path));
		}
	}, 30_000);

	it('ships the full Xiaolai CJK fallback shard tree (XIAOLAI-001 shape)', () => {
		// The hash-looking 32-hex filename suffix pins nothing upstream — the
		// per-file sha256 above is the pin of record. 209 shards is the
		// @excalidraw/excalidraw 0.18.1 Xiaolai set; a bump that changes the
		// count must re-vendor (the byte-identity test above already forces
		// that) and update this number deliberately.
		const xiaolai = excalidrawManifest.files.filter((shard) => shard.path.startsWith('Xiaolai/'));
		expect(xiaolai.length).toBe(209);
		for (const shard of xiaolai) {
			expect(shard.path).toMatch(/^Xiaolai\/Xiaolai-Regular-[0-9a-f]{32}\.woff2$/);
		}
	});
});
