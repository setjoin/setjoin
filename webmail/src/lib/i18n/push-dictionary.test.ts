import { describe, expect, it } from 'vitest';
import en from './en';
import de from './de';
import zh from './zh';
import { PUSH_DICTIONARY, pushText, type PushKey, type PushLocale } from './push.generated';

describe('service-worker push dictionary', () => {
	it('is an exact two-key projection of every product catalog', () => {
		const catalogs = { en, de, zh };
		const expected = ['chat.list.unknownDm', 'chat.push.mentionPrefix'];
		for (const locale of Object.keys(PUSH_DICTIONARY) as PushLocale[]) {
			expect(Object.keys(PUSH_DICTIONARY[locale]).sort()).toEqual(expected);
			for (const key of expected as PushKey[]) {
				expect(pushText(locale, key)).toBe(catalogs[locale][key]);
			}
		}
	});

	it('does not expose unrelated product strings', () => {
		expect(JSON.stringify(PUSH_DICTIONARY)).not.toContain('login.');
		expect(JSON.stringify(PUSH_DICTIONARY)).not.toContain('admin.');
	});
});
