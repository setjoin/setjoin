import { describe, it, expect } from 'vitest';
import en from './en';
import zh from './zh';
import de from './de';
import { t, switchLocale } from './index';

const KEYS = [
	'onboarding.apps.title', 'onboarding.apps.body',
	'onboarding.compose.title', 'onboarding.compose.body',
	'onboarding.compose.hint',
	'onboarding.search.title', 'onboarding.search.body',
	'onboarding.search.hint',
	'onboarding.organize.title', 'onboarding.organize.body',
	'onboarding.skip', 'onboarding.back', 'onboarding.next', 'onboarding.next_instead', 'onboarding.done',
	'onboarding.progress', 'onboarding.replay', 'onboarding.show_tour',
	'onboarding.replay_card_title', 'onboarding.replay_desc', 'onboarding.complete_toast',
];

describe('onboarding i18n keys', () => {
	it('exist in all three bundles', () => {
		for (const k of KEYS) {
			expect(en[k], `en ${k}`).toBeTruthy();
			expect(zh[k], `zh ${k}`).toBeTruthy();
			expect(de[k], `de ${k}`).toBeTruthy();
		}
	});

	it('progress interpolates current/total', async () => {
		await switchLocale('en');
		expect(t('onboarding.progress', { current: '2', total: '4' })).toBe('Step 2 of 4');
	});
});
