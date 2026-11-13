import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { CAPABILITIES } from './capabilityCatalog';

// Recursively collect .svelte files under a dir.
function svelteFiles(dir: string): string[] {
	const out: string[] = [];
	for (const e of readdirSync(dir, { withFileTypes: true })) {
		const p = join(dir, e.name);
		if (e.isDirectory()) out.push(...svelteFiles(p));
		else if (e.name.endsWith('.svelte')) out.push(p);
	}
	return out;
}

describe('capabilityCatalog drift guard', () => {
	it('covers every permission gated in the admin UI (catalog ⊇ gated admin perms)', () => {
		const roots = ['src/routes/admin', 'src/lib/components/admin'];
		const gated = new Set<string>();
		const re = /hasPermission\(\$adminPermissions,\s*'([a-z._]+)'\)/g;
		for (const root of roots) {
			for (const f of svelteFiles(root)) {
				const src = readFileSync(f, 'utf8');
				let m: RegExpExecArray | null;
				while ((m = re.exec(src)) !== null) gated.add(m[1]);
			}
		}
		const catalog = new Set(CAPABILITIES.map((c) => c.perm));
		const missing = [...gated].filter((p) => !catalog.has(p));
		expect(missing, `gated perms missing from capabilityCatalog.ts: ${missing.join(', ')}`).toEqual([]);
	});

	it('has exactly one entry per perm (perm-keyed, no duplicates)', () => {
		const perms = CAPABILITIES.map((c) => c.perm);
		expect(new Set(perms).size).toBe(perms.length);
	});
});
