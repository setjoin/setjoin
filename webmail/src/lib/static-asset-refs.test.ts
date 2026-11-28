import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Root-relative asset references must exist under static/. The gateway's SPA
// catch-all serves index.html for ANY unmatched GET, so a broken <img src>
// never 404s — it silently renders a broken image (the AppRail logo shipped
// pointing at /logo-mark.svg while the file lives at /brand/logo-mark.svg).
const SRC = join(__dirname, '..');
const STATIC = join(SRC, '..', 'static');

function svelteFiles(dir: string): string[] {
	return readdirSync(dir).flatMap((name) => {
		const p = join(dir, name);
		if (statSync(p).isDirectory()) return svelteFiles(p);
		return name.endsWith('.svelte') ? [p] : [];
	});
}

describe('static asset references', () => {
	it('every root-relative image/font src in a .svelte file exists in static/', () => {
		const missing: string[] = [];
		for (const file of svelteFiles(SRC)) {
			const text = readFileSync(file, 'utf-8');
			for (const m of text.matchAll(/(?:src|href)="(\/[^"]+\.(?:svg|png|ico|webp|woff2?))"/g)) {
				if (!existsSync(join(STATIC, m[1]))) {
					missing.push(`${file.slice(SRC.length + 1)} → ${m[1]}`);
				}
			}
		}
		expect(missing, `references to files absent from static/ (the SPA catch-all masks these as silent broken images):\n${missing.join('\n')}`).toEqual([]);
	});
});
