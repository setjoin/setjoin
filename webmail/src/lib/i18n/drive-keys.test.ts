import { describe, it, expect } from 'vitest';
import en from './en';
import de from './de';
import zh from './zh';

const BZ_CODES = ['BZ139', 'BZ140', 'BZ141', 'BZ142', 'BZ143', 'BZ144', 'BZ145', 'BZ147', 'BZ148'];

function driveKeys(bundle: Record<string, string>): string[] {
	return Object.keys(bundle).filter((k) => k.startsWith('drive.'));
}

// Every static `t('drive.…')` literal referenced anywhere under the Drive
// app's own source — the completeness gate the plan calls for (no dead or
// missing keys). Dynamic template-literal calls (t(`drive.errors.${code}`),
// t(`drive.members.role.${role}`), t(`drive.space.classification…${c}`)) are
// asserted separately below via their known enumerations, since a static
// regex scan can't resolve an interpolated suffix.
function scanSourceForDriveKeys(): Set<string> {
	const modules = import.meta.glob(
		['/src/lib/components/drive/**/*.{svelte,ts}', '/src/routes/drive/**/*.svelte'],
		{ query: '?raw', import: 'default', eager: true },
	) as Record<string, string>;
	const found = new Set<string>();
	const re = /t\('(drive\.[a-zA-Z0-9_.]+)'/g;
	for (const src of Object.values(modules)) {
		for (const m of src.matchAll(re)) found.add(m[1]);
	}
	return found;
}

describe('drive i18n keys', () => {
	it('en/de/zh define exactly the same drive.* key set', () => {
		const enKeys = new Set(driveKeys(en));
		const deKeys = new Set(driveKeys(de));
		const zhKeys = new Set(driveKeys(zh));
		expect([...deKeys].sort()).toEqual([...enKeys].sort());
		expect([...zhKeys].sort()).toEqual([...enKeys].sort());
	});

	it('every drive.* value is a non-empty string in all three bundles', () => {
		for (const k of driveKeys(en)) {
			expect(typeof en[k], `en[${k}]`).toBe('string');
			expect(en[k].length, `en[${k}] empty`).toBeGreaterThan(0);
			expect(typeof de[k], `de[${k}]`).toBe('string');
			expect(de[k].length, `de[${k}] empty`).toBeGreaterThan(0);
			expect(typeof zh[k], `zh[${k}]`).toBe('string');
			expect(zh[k].length, `zh[${k}] empty`).toBeGreaterThan(0);
		}
	});

	it('every literal drive.* key referenced in the Drive app source exists in en (no dead/missing keys)', () => {
		const referenced = scanSourceForDriveKeys();
		expect(referenced.size).toBeGreaterThan(0); // sanity: the scan actually found something
		for (const k of referenced) {
			expect(en[k], `referenced but missing from en: ${k}`).toBeDefined();
		}
	});

	it('drive.errors.BZ139-BZ148 (the P1 allocation) are all present', () => {
		for (const code of BZ_CODES) {
			const key = `drive.errors.${code}`;
			expect(en[key], `en missing ${key}`).toBeTruthy();
			expect(de[key], `de missing ${key}`).toBeTruthy();
			expect(zh[key], `zh missing ${key}`).toBeTruthy();
		}
	});

	it('the dynamic-key families (role, classification, classification tooltip) are fully enumerated', () => {
		for (const role of ['manager', 'editor', 'viewer']) {
			expect(en[`drive.members.role.${role}`]).toBeTruthy();
		}
		for (const c of ['regular', 'secure', 'gxp']) {
			expect(en[`drive.space.classification.${c}`]).toBeTruthy();
			expect(en[`drive.space.classification.tooltip.${c}`]).toBeTruthy();
		}
	});
});
