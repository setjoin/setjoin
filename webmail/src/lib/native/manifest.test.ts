/// <reference types="node" />
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Read the real committed manifest from disk. Resolve via node:path join (not
// `new URL('../../../static/...', import.meta.url)`): SvelteKit's Vite plugin
// rewrites `static/`-relative URLs to the dev-server asset origin (http://...),
// which `fileURLToPath` rejects. This sibling-of-theme-tests pattern stays on
// the filesystem. The per-file node reference keeps svelte-check happy without
// touching the project tsconfig.
const here = dirname(fileURLToPath(import.meta.url)); // src/lib/native
const manifestPath = join(here, '../../../static/manifest.webmanifest');

describe('pwa manifest', () => {
	it('is valid JSON with the required installability fields', () => {
		const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
		expect(m.name).toBe('setjoin');
		expect(m.display).toBe('standalone');
		expect(m.start_url).toBe('/');
		expect(Array.isArray(m.icons)).toBe(true);
		expect(m.icons.length).toBeGreaterThanOrEqual(1);
	});
});
