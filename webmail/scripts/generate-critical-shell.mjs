import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveCriticalShellMembers } from './performance-report.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const WEBMAIL_DIR = resolve(SCRIPT_DIR, '..');
const buildDir = join(WEBMAIL_DIR, 'build');
const manifestPath = join(WEBMAIL_DIR, '.svelte-kit/output/client/.vite/manifest.json');

function sha256(bytes) {
	return createHash('sha256').update(bytes).digest('hex');
}

export function generateCriticalShell({ outputDir = buildDir, clientManifestPath = manifestPath } = {}) {
	const version = JSON.parse(readFileSync(join(outputDir, '_app/version.json'), 'utf8')).version;
	if (typeof version !== 'string' || version.length === 0) throw new Error('SvelteKit build version is missing');
	const members = deriveCriticalShellMembers({ buildDir: outputDir, manifestPath: clientManifestPath }).map((path) => {
		const bytes = readFileSync(join(outputDir, path));
		return { path: `/${path}`, identityBytes: bytes.byteLength, sha256: sha256(bytes) };
	});
	const manifest = {
		schemaVersion: 1,
		protocolVersion: 1,
		buildId: version,
		members,
	};
	mkdirSync(outputDir, { recursive: true });
	writeFileSync(join(outputDir, 'critical-shell.v1.json'), `${JSON.stringify(manifest, null, 2)}\n`);
	return manifest;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const manifest = generateCriticalShell();
	process.stdout.write(`critical-shell build=${manifest.buildId} members=${manifest.members.length}\n`);
}
