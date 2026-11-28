import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import en from './en';
import de from './de';
import zh from './zh';

function chatComplianceKeys(bundle: Record<string, string>): string[] {
	return Object.keys(bundle).filter((k) => k.startsWith('admin.chatCompliance.'));
}

// Every static `t('admin.chatCompliance.…')` literal referenced anywhere
// under the chat-compliance admin console's own source — the completeness
// gate the plan calls for (no dead or missing keys), in the image of
// chat-keys.test.ts. Plain node:fs (capabilityCatalog.test.ts's own pattern)
// rather than import.meta.glob: vite's glob treats the `(access)` route
// group's parentheses as extglob syntax and silently matches nothing.
function chatComplianceSourceFiles(): string[] {
	const dir = join(process.cwd(), 'src/routes/admin/(access)/chat-compliance');
	const out: string[] = [];
	for (const e of readdirSync(dir, { withFileTypes: true })) {
		if (e.isFile() && (e.name.endsWith('.svelte') || e.name.endsWith('.ts'))) {
			out.push(join(dir, e.name));
		}
	}
	return out;
}

function scanSourceForChatComplianceKeys(): Set<string> {
	const found = new Set<string>();
	const re = /t\('(admin\.chatCompliance\.[a-zA-Z0-9_.]+)'/g;
	for (const f of chatComplianceSourceFiles()) {
		const src = readFileSync(f, 'utf8');
		for (const m of src.matchAll(re)) found.add(m[1]);
	}
	return found;
}

describe('chat compliance admin i18n keys', () => {
	it('en/de/zh define exactly the same admin.chatCompliance.* key set', () => {
		const enKeys = new Set(chatComplianceKeys(en));
		const deKeys = new Set(chatComplianceKeys(de));
		const zhKeys = new Set(chatComplianceKeys(zh));
		expect([...deKeys].sort()).toEqual([...enKeys].sort());
		expect([...zhKeys].sort()).toEqual([...enKeys].sort());
	});

	it('every admin.chatCompliance.* value is a non-empty string in all three bundles', () => {
		for (const k of chatComplianceKeys(en)) {
			expect(typeof en[k], `en[${k}]`).toBe('string');
			expect(en[k].length, `en[${k}] empty`).toBeGreaterThan(0);
			expect(typeof de[k], `de[${k}]`).toBe('string');
			expect(de[k].length, `de[${k}] empty`).toBeGreaterThan(0);
			expect(typeof zh[k], `zh[${k}]`).toBe('string');
			expect(zh[k].length, `zh[${k}] empty`).toBeGreaterThan(0);
		}
	});

	it('zh is a real translation, not an en/de stub', () => {
		for (const k of chatComplianceKeys(en)) {
			// wormMode.governance/compliance are legitimately loanwords rendered
			// verbatim in zh (as elsewhere in the compliance vocabulary).
			if (k === 'admin.chatCompliance.sheet.wormMode.governance' || k === 'admin.chatCompliance.sheet.wormMode.compliance') continue;
			expect(zh[k], `zh[${k}] === en[${k}] (looks stubbed)`).not.toBe(en[k]);
		}
	});

	it('every literal admin.chatCompliance.* key referenced in the console source exists in en (no dead/missing keys)', () => {
		const referenced = scanSourceForChatComplianceKeys();
		expect(referenced.size).toBeGreaterThan(0); // sanity: the scan actually found something
		for (const k of referenced) {
			expect(en[k], `referenced but missing from en: ${k}`).toBeDefined();
		}
	});

	// Global Constraints pins this vocabulary EXACTLY — the two labels must
	// never be conflated (a regular channel's number is a DESTROY CEILING; a
	// gxp channel's is a WORM KEEP-FLOOR) and 'gxp' must never render raw.
	it('the classification + retention-label vocabulary is pinned exactly', () => {
		expect(en['admin.chatCompliance.class.regular']).toBe('Standard');
		expect(en['admin.chatCompliance.class.gxp']).toBe('Records (WORM)');
		expect(zh['admin.chatCompliance.class.gxp']).toBe('合规存证（不可篡改）');
		expect(de['admin.chatCompliance.class.gxp']).toBe('Aufbewahrung (WORM)');

		expect(en['admin.chatCompliance.retention.destroyCeiling']).toBe(
			'Permanently delete messages older than {n} days'
		);
		expect(zh['admin.chatCompliance.retention.destroyCeiling']).toBe('超过 {n} 天后永久销毁（不可恢复）');
		expect(de['admin.chatCompliance.retention.destroyCeiling']).toBe(
			'Nachrichten älter als {n} Tage endgültig löschen'
		);

		expect(en['admin.chatCompliance.retention.wormFloor']).toBe(
			'Messages cannot be edited or deleted for {n} days'
		);
		expect(zh['admin.chatCompliance.retention.wormFloor']).toBe('{n} 天内不可编辑或删除（WORM 保存期限）');
		expect(de['admin.chatCompliance.retention.wormFloor']).toBe('Nachrichten sind {n} Tage lang unveränderlich');

		// The CN compliance reading of 保存期限/保留 N 天 as a bare floor is the
		// exact opposite of a destroy-ceiling — must never appear on that label.
		expect(zh['admin.chatCompliance.retention.destroyCeiling']).not.toContain('保留');
	});

	// N7 — the purge confirm must never imply the whole backlog is destroyed
	// in a single night.
	it('the purge confirm copy states the nightly-drain rate, not a one-night completion', () => {
		expect(en['admin.chatCompliance.purge.confirmMessage']).toContain('runs nightly');
		expect(en['admin.chatCompliance.purge.confirmMessage']).toContain('until the backlog is cleared');
	});

	// Chat A4b Task 9 (Global Constraints): "legal hold" and "custodian" are a
	// pinned zh vocabulary — 法律保全 / 保管人, never a different rendering.
	it('the Holds tab vocabulary (legal hold / custodian) is pinned exactly', () => {
		expect(zh['admin.chatCompliance.tab.holds']).toBe('法律保全');
		expect(zh['admin.chatCompliance.holds.scope.custodian']).toBe('保管人');
		expect(en['admin.chatCompliance.tab.holds']).toBe('Holds');
		expect(en['admin.chatCompliance.holds.scope.custodian']).toBe('Custodian');
	});

	// Chat A4b Task 10 / review F7: the console's record-floor disclaimer is
	// pinned to be character-for-character IDENTICAL to exportDisclaimers[2]
	// in mailserver/internal/admin/admin_chat_ediscovery_export.go — the two
	// surfaces previously drifted; this is the machine guard that stops it
	// happening again. The Go literal is duplicated here (not imported — this
	// is a .ts test, Go is not importable) with a pointer back to its home so
	// a future edit to either string is forced to keep both in sync.
	it('the eDiscovery record-floor disclaimer is verbatim-identical to exportDisclaimers[2] (admin_chat_ediscovery_export.go)', () => {
		const goExportDisclaimer2 =
			'The audit chain proves what the destroyedElems leaves say and nothing more: it does not prove that a specific held message was not destroyed, and no claim is made about records that never existed.';
		expect(en['admin.chatCompliance.ediscovery.recordFloorDisclaimer']).toBe(goExportDisclaimer2);
	});
});
