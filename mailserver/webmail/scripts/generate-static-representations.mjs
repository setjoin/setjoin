import { createHash } from 'node:crypto';
import { constants as zlibConstants, brotliCompressSync, gzipSync } from 'node:zlib';
import { lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const WEBMAIL_DIR = resolve(SCRIPT_DIR, '..');
const DEFAULT_BUILD_DIR = join(WEBMAIL_DIR, 'build');
const REPRESENTATION_MANIFEST = 'static-representations.v1.json';
const COMPRESSIBLE = new Set(['.css', '.html', '.js', '.json', '.mjs', '.svg', '.txt', '.wasm', '.webmanifest', '.xml']);

function sha256(bytes) {
	return createHash('sha256').update(bytes).digest('hex');
}

function sortedFiles(root) {
	const files = [];
	const visit = (directory) => {
		for (const name of readdirSync(directory).sort()) {
			const path = join(directory, name);
			const stat = lstatSync(path);
			if (stat.isSymbolicLink()) throw new Error(`build contains symlink: ${relative(root, path)}`);
			if (stat.isDirectory()) visit(path);
			else if (stat.isFile()) files.push(relative(root, path).replaceAll('\\', '/'));
		}
	};
	visit(root);
	return files.sort();
}

export function generateStaticRepresentations(buildDir = DEFAULT_BUILD_DIR) {
	const version = JSON.parse(readFileSync(join(buildDir, '_app/version.json'), 'utf8')).version;
	if (typeof version !== 'string' || !version) throw new Error('SvelteKit build version is missing');
	const records = [];
	for (const path of sortedFiles(buildDir)) {
		if (path === REPRESENTATION_MANIFEST || path.endsWith('.br') || path.endsWith('.gz')) continue;
		const identity = readFileSync(join(buildDir, path));
		const record = {
			path: `/${path}`,
			identityBytes: identity.byteLength,
			identitySha256: sha256(identity),
			representations: {},
		};
		if (COMPRESSIBLE.has(extname(path).toLowerCase()) && identity.byteLength > 256) {
			const gzip = gzipSync(identity, { level: 9, mtime: 0 });
			const brotli = brotliCompressSync(identity, {
				params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 5 },
			});
			if (gzip.byteLength < identity.byteLength) {
				writeFileSync(join(buildDir, `${path}.gz`), gzip);
				record.representations.gzip = { path: `/${path}.gz`, bytes: gzip.byteLength, sha256: sha256(gzip) };
			}
			if (brotli.byteLength < identity.byteLength) {
				writeFileSync(join(buildDir, `${path}.br`), brotli);
				record.representations.br = { path: `/${path}.br`, bytes: brotli.byteLength, sha256: sha256(brotli) };
			}
		}
		record.representations = Object.fromEntries(Object.entries(record.representations).sort(([a], [b]) => a.localeCompare(b)));
		records.push(record);
	}
	const manifest = {
		schemaVersion: 1,
		buildId: version,
		parameters: { gzip: { level: 9, mtime: 0 }, brotli: { quality: 5 } },
		assets: records,
	};
	writeFileSync(join(buildDir, REPRESENTATION_MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`);
	return manifest;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const manifest = generateStaticRepresentations();
	const encoded = manifest.assets.filter((asset) => Object.keys(asset.representations).length > 0).length;
	process.stdout.write(`static-representations build=${manifest.buildId} assets=${manifest.assets.length} encoded=${encoded}\n`);
}
