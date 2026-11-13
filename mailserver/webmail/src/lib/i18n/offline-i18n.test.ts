import { describe, it, expect } from 'vitest';
import en from '$lib/i18n/en';
import de from '$lib/i18n/de';
import zh from '$lib/i18n/zh';
import { t } from '$lib/i18n';

describe('offline.* i18n', () => {
	it('announces async outcomes via dedicated live-region keys', () => {
		for (const k of ['offline.live.synced','offline.live.unlocked','offline.live.unlock_failed','offline.live.relocked','offline.live.blocked'])
			expect((en as Record<string,string>)[k]).toBeTruthy();
	});
	it('interpolates the count + showing-of keys', () => {
		expect(t('offline.issues.count_plural', { n: '3' })).toContain('3');
		expect(t('offline.conflict.showing_of', { shown: '50', total: '9999' })).toContain('9999');
		expect(t('offline.status.syncing', { done: '2', total: '5' })).toMatch(/2.*5/);
	});
	it('de and zh mirror every offline.* key (no untranslated gaps in parity)', () => {
		const offlineKeys = Object.keys(en as Record<string,string>).filter((k) => k.startsWith('offline.'));
		for (const k of offlineKeys) {
			expect((de as Record<string,string>)[k], `de missing ${k}`).toBeDefined();
			expect((zh as Record<string,string>)[k], `zh missing ${k}`).toBeDefined();
		}
	});
	it('zh ships real translations, not English placeholders', () => {
		// Language-neutral values (numeric/symbolic) that are legitimately identical across locales.
		const NEUTRAL = new Set(['offline.issues.count_overflow']);
		const E = en as Record<string,string>, Z = zh as Record<string,string>;
		const offlineKeys = Object.keys(E).filter((k) => k.startsWith('offline.') && !NEUTRAL.has(k));
		for (const k of offlineKeys) {
			expect(Z[k], `zh[${k}] is an untranslated English placeholder`).not.toBe(E[k]);
		}
	});

	// ── admin.offline.* + settings.offline.* parity guard (Fix 2: zh/de must ship real translations) ──
	it('de and zh mirror every admin.offline.* + settings.offline.* key', () => {
		const E = en as Record<string,string>;
		const adminKeys = Object.keys(E).filter(
			(k) => k.startsWith('admin.offline.') || k.startsWith('settings.offline.')
		);
		for (const k of adminKeys) {
			expect((de as Record<string,string>)[k], `de missing ${k}`).toBeDefined();
			expect((zh as Record<string,string>)[k], `zh missing ${k}`).toBeDefined();
		}
	});
	it('zh ships real translations for admin.offline.* + settings.offline.*', () => {
		// Proper nouns / language-neutral values legitimately identical across locales.
		const NEUTRAL = new Set([
			'admin.offline.devices.platform.ios',
			'admin.offline.devices.platform.android',
			'admin.offline.explainer.and',        // 'AND' as logical operator kept in zh
		]);
		const E = en as Record<string,string>, Z = zh as Record<string,string>;
		const keys = Object.keys(E).filter(
			(k) => (k.startsWith('admin.offline.') || k.startsWith('settings.offline.')) && !NEUTRAL.has(k)
		);
		for (const k of keys) {
			if (Z[k] !== undefined) {
				expect(Z[k], `zh[${k}] is an untranslated English placeholder`).not.toBe(E[k]);
			}
		}
	});
});
