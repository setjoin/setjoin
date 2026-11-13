import { describe, it, expect, beforeEach, vi } from 'vitest';
import { t, setLocale, registerBundle, locale, localeCode, meta, formatNumber, formatDate, formatRelativeTime, formatMessage, dir } from './index';
import { get } from 'svelte/store';

describe('i18n framework', () => {
	beforeEach(() => {
		setLocale('en');
	});

	// ── Active-catalog switching (test setup preloads isolated chunks) ──

	describe('preloaded catalog switching', () => {
		it('zh and de resolve synchronously after the test-only preload', () => {
			setLocale('zh');
			expect(t('tags.Inbox')).not.toBe('tags.Inbox'); // resolved, not the raw key
			setLocale('de');
			expect(t('tags.Inbox')).not.toBe('tags.Inbox');
			setLocale('en');
		});

		it('t() returns the active-locale translation immediately after setLocale', () => {
			setLocale('zh');
			const zhInbox = t('tags.Inbox');
			setLocale('en');
			const enInbox = t('tags.Inbox');
			expect(enInbox).toBe('Inbox');
			expect(zhInbox).not.toBe(enInbox); // zh differs from en (no English fallback)
		});
	});

	// ── localeCode: BCP-47 tag for native Intl calls (MailRow/CalendarApp/printAgenda) ──

	describe('localeCode', () => {
		it('resolves the active locale to its BCP-47 tag from the live store', () => {
			setLocale('en');
			expect(localeCode()).toBe('en-US');
			setLocale('de');
			expect(localeCode()).toBe('de-DE');
			setLocale('zh');
			expect(localeCode()).toBe('zh-CN');
			setLocale('en');
		});

		it('drives Intl month names off the store (de month abbreviations differ from en)', () => {
			const march = new Date(2026, 2, 15);
			setLocale('en');
			const en = march.toLocaleDateString(localeCode(), { month: 'short', day: 'numeric' });
			setLocale('de');
			const de = march.toLocaleDateString(localeCode(), { month: 'short', day: 'numeric' });
			setLocale('en');
			// en 'Mar' vs de 'März'/'Mrz' — the German label never contains the English 'Mar'.
			expect(en).toContain('Mar');
			expect(de).not.toContain('Mar');
			expect(en).not.toBe(de);
		});
	});

	// ── Existing tag translation tests ──

	describe('tag translations', () => {
		it('translates tags.Inbox to English', () => {
			expect(t('tags.Inbox')).toBe('Inbox');
		});

		it('translates tags.Sent to English', () => {
			expect(t('tags.Sent')).toBe('Sent');
		});

		it('translates tags.Trash to English', () => {
			expect(t('tags.Trash')).toBe('Trash');
		});

		it('translates tags.Spam to English', () => {
			expect(t('tags.Spam')).toBe('Spam');
		});

		it('translates tags.Inbox to Chinese when zh bundle registered', () => {
			registerBundle('zh', {
				'tags.Inbox': '收件箱',
				'tags.Sent': '已发送',
				'tags.Drafts': '草稿',
				'tags.Trash': '已删除',
				'tags.Spam': '垃圾邮件',
				'tags.Archive': '存档',
			});
			setLocale('zh');
			expect(t('tags.Inbox')).toBe('收件箱');
			expect(t('tags.Sent')).toBe('已发送');
		});

		it('falls back to English key when locale missing', () => {
			setLocale('en');
			registerBundle('de', {
				'tags.Inbox': 'Posteingang',
			});
			setLocale('de');
			expect(t('tags.Inbox')).toBe('Posteingang');
			expect(t('tags.Trash')).toBe('Trash');
		});

		it('returns key string when no translation exists', () => {
			expect(t('tags.UnknownTag')).toBe('tags.UnknownTag');
		});
	});

	// ── A1: LocaleMeta ──

	describe('locale metadata (A1)', () => {
		it('returns en metadata with correct fields', () => {
			setLocale('en');
			const m = meta();
			expect(m.code).toBe('en');
			expect(m.direction).toBe('ltr');
			expect(m.displayName).toBe('English');
			expect(m.firstDayOfWeek).toBe(0);
		});

		it('returns zh metadata with correct fields', () => {
			setLocale('zh');
			const m = meta();
			expect(m.code).toBe('zh');
			expect(m.direction).toBe('ltr');
			expect(m.displayName).toBe('中文');
			expect(m.firstDayOfWeek).toBe(1);
		});

		it('returns de metadata with correct fields', () => {
			setLocale('de');
			const m = meta();
			expect(m.code).toBe('de');
			expect(m.direction).toBe('ltr');
			expect(m.displayName).toBe('Deutsch');
			expect(m.firstDayOfWeek).toBe(1);
		});

		it('has dateFormat keys for every locale', () => {
			for (const l of ['en', 'de', 'zh'] as const) {
				setLocale(l);
				const m = meta();
				expect(m.dateFormat).toBeDefined();
				expect(m.dateFormat.short).toBeTruthy();
				expect(m.dateFormat.medium).toBeTruthy();
				expect(m.dateFormat.long).toBeTruthy();
				expect(m.dateFormat.full).toBeTruthy();
			}
		});

		it('has numberFormat keys for every locale', () => {
			for (const l of ['en', 'de', 'zh'] as const) {
				setLocale(l);
				const m = meta();
				expect(m.numberFormat).toBeDefined();
				expect(m.numberFormat.decimal).toBeTruthy();
				expect(m.numberFormat.percent).toBeTruthy();
				expect(m.numberFormat.currency).toBeTruthy();
			}
		});

		it('falls back to en for unknown locale', () => {
			setLocale('en');
			const m = meta();
			expect(m.code).toBe('en');
		});
	});

	// ── A2: formatNumber ──

	describe('formatNumber (A2)', () => {
		it('formats numbers in English locale', () => {
			setLocale('en');
			expect(formatNumber(1234567.89)).toBe('1,234,567.89');
		});

		it('formats numbers in German locale', () => {
			setLocale('de');
			expect(formatNumber(1234567.89)).toBe('1.234.567,89');
		});

		it('formats numbers in Chinese locale', () => {
			setLocale('zh');
			expect(formatNumber(1234567.89)).toBe('1,234,567.89');
		});

		it('formats percentages', () => {
			setLocale('en');
			expect(formatNumber(0.75, 'percent')).toBe('75%');
		});

		it('formats currency', () => {
			setLocale('en');
			const result = formatNumber(1234.56, 'currency', 'USD');
			expect(result).toContain('1,234.56');
		});

		it('defaults to decimal style', () => {
			setLocale('en');
			expect(formatNumber(42)).toBe('42');
		});
	});

	// ── A3: formatDate ──

	describe('formatDate (A3)', () => {
		it('formats dates in English locale (long)', () => {
			setLocale('en');
			const result = formatDate(new Date(2026, 4, 31), 'long');
			expect(result).toBe('May 31, 2026');
		});

		it('formats dates in German locale (long)', () => {
			setLocale('de');
			const result = formatDate(new Date(2026, 4, 31), 'long');
			expect(result).toBe('31. Mai 2026');
		});

		it('formats dates in Chinese locale (long)', () => {
			setLocale('zh');
			const result = formatDate(new Date(2026, 4, 31), 'long');
			expect(result).toBe('2026年5月31日');
		});

		it('formats dates from string input', () => {
			setLocale('en');
			const result = formatDate('2026-05-31', 'medium');
			expect(result).toBe('May 31, 2026');
		});

		it('formats dates from timestamp', () => {
			setLocale('en');
			const date = new Date(2026, 4, 31);
			const result = formatDate(date.getTime(), 'medium');
			expect(result).toBe('May 31, 2026');
		});

		it('formats dates with short style', () => {
			setLocale('en');
			const result = formatDate(new Date(2026, 4, 31), 'short');
			expect(result).toBeTruthy();
			expect(result.length).toBeGreaterThan(0);
		});

		it('defaults to medium style', () => {
			setLocale('en');
			const result = formatDate(new Date(2026, 4, 31));
			expect(result).toBe('May 31, 2026');
		});
	});

	// ── A4: formatRelativeTime ──

	describe('formatRelativeTime (A4)', () => {
		it('formats relative time in English', () => {
			setLocale('en');
			expect(formatRelativeTime(-3, 'day')).toBe('3 days ago');
		});

		it('formats relative time in German', () => {
			setLocale('de');
			expect(formatRelativeTime(-3, 'day')).toBe('vor 3 Tagen');
		});

		it('formats relative time in Chinese', () => {
			setLocale('zh');
			expect(formatRelativeTime(-3, 'day')).toBe('3天前');
		});

		it('formats future relative time in English', () => {
			setLocale('en');
			expect(formatRelativeTime(2, 'hour')).toBe('in 2 hours');
		});

		it('formats relative time for minutes', () => {
			setLocale('en');
			const result = formatRelativeTime(-5, 'minute');
			expect(result).toBe('5 minutes ago');
		});

		it('formats relative time for weeks', () => {
			setLocale('en');
			const result = formatRelativeTime(-2, 'week');
			expect(result).toBe('2 weeks ago');
		});
	});

	// ── A5: ICU MessageFormat ──

	describe('formatMessage — ICU MessageFormat (A5)', () => {
		it('substitutes simple variables', () => {
			expect(formatMessage('Hello {name}', { name: 'World' })).toBe('Hello World');
		});

		it('handles multiple variables', () => {
			expect(formatMessage('{greeting}, {name}!', { greeting: 'Hi', name: 'Cat' }))
				.toBe('Hi, Cat!');
		});

		it('handles plural: =0', () => {
			const pattern = '{count, plural, =0{No users} one{1 user} other{{count} users}}';
			expect(formatMessage(pattern, { count: 0 })).toBe('No users');
		});

		it('handles plural: one', () => {
			const pattern = '{count, plural, =0{No users} one{1 user} other{{count} users}}';
			expect(formatMessage(pattern, { count: 1 })).toBe('1 user');
		});

		it('handles plural: other with nested variable substitution', () => {
			const pattern = '{count, plural, =0{No users} one{1 user} other{{count} users}}';
			expect(formatMessage(pattern, { count: 5 })).toBe('5 users');
		});

		it('handles plural: =n exact match', () => {
			const pattern = '{count, plural, =0{zero} =1{one} other{other}}';
			expect(formatMessage(pattern, { count: 0 })).toBe('zero');
			expect(formatMessage(pattern, { count: 1 })).toBe('one');
			expect(formatMessage(pattern, { count: 2 })).toBe('other');
		});

		it('handles select: male', () => {
			const pattern = '{gender, select, male{He} female{She} other{They}} wrote';
			expect(formatMessage(pattern, { gender: 'male' })).toBe('He wrote');
		});

		it('handles select: female', () => {
			const pattern = '{gender, select, male{He} female{She} other{They}} wrote';
			expect(formatMessage(pattern, { gender: 'female' })).toBe('She wrote');
		});

		it('handles select: other fallback', () => {
			const pattern = '{gender, select, male{He} female{She} other{They}} wrote';
			expect(formatMessage(pattern, { gender: 'unknown' })).toBe('They wrote');
		});

		it('handles select: missing value falls back to other', () => {
			const pattern = '{gender, select, male{He} female{She} other{They}} wrote';
			expect(formatMessage(pattern, {})).toBe('They wrote');
		});

		it('keeps text without ICU patterns unchanged', () => {
			expect(formatMessage('No pattern here', {})).toBe('No pattern here');
		});

		it('keeps unmatched simple variable reference', () => {
			expect(formatMessage('Hello {name}', {})).toBe('Hello {name}');
		});

		it('handles multiple ICU patterns in one string', () => {
			const pattern = 'Team: {team, select, red{Red Team} blue{Blue Team} other{Unknown}} — {count, plural, one{1 member} other{{count} members}}';
			expect(formatMessage(pattern, { team: 'red', count: 1 })).toBe('Team: Red Team — 1 member');
		});
	});

	// ── A6: t() with ICU auto-detection ──

	describe('t() with ICU auto-detection (A6)', () => {
		it('detects plural syntax and delegates to formatMessage', () => {
			registerBundle('de', {
				'test.plural': '{count, plural, =0{No users} one{1 user} other{{count} users}}',
			});
			setLocale('de');
			expect(t('test.plural', { count: '5' })).toBe('5 users');
		});

		it('detects select syntax and delegates to formatMessage', () => {
			registerBundle('de', {
				'test.select': '{gender, select, male{He} female{She} other{They}}',
			});
			setLocale('de');
			expect(t('test.select', { gender: 'male' })).toBe('He');
		});

		it('uses simple param substitution for non-ICU patterns', () => {
			registerBundle('de', {
				'test.simple': 'Hello, {name}!',
			});
			setLocale('de');
			expect(t('test.simple', { name: 'Alice' })).toBe('Hello, Alice!');
		});

		it('backward compat: en param substitution works without clobbering', () => {
			setLocale('en');
			expect(t('login.password_min_length', { min: '8' })).toBe('Password must be at least 8 characters');
		});

		it('backward compat: en no-params lookup works without clobbering', () => {
			setLocale('en');
			expect(t('admin.dashboard')).toBe('Dashboard');
		});
	});

	// ── A7: dir() ──

	describe('dir() and setLocale document.dir (A7)', () => {
		it('returns ltr for en', () => {
			setLocale('en');
			expect(dir()).toBe('ltr');
		});

		it('returns ltr for zh', () => {
			setLocale('zh');
			expect(dir()).toBe('ltr');
		});

		it('returns ltr for de', () => {
			setLocale('de');
			expect(dir()).toBe('ltr');
		});

			it('setLocale sets document.documentElement.dir', () => {
			setLocale('en');
			expect(document.documentElement.dir).toBe('ltr');
			setLocale('zh');
			expect(document.documentElement.dir).toBe('ltr');
			setLocale('de');
			expect(document.documentElement.dir).toBe('ltr');
		});
	});

	// ── B1: detectLocale browser-language auto-detection (§11.2) ──

	describe('detectLocale() — browser language detection', () => {
		it('returns stored locale when localStorage has a valid value', async () => {
			const { detectLocale } = await import('./index');
			localStorage.setItem('locale', 'zh');
			expect(detectLocale()).toBe('zh');
			localStorage.removeItem('locale');
		});

		it('returns stored locale over browser language', async () => {
			const { detectLocale } = await import('./index');
			vi.stubGlobal('navigator', { ...navigator, language: 'de-DE', languages: undefined });
			localStorage.setItem('locale', 'zh');
			expect(detectLocale()).toBe('zh');
			localStorage.removeItem('locale');
			vi.unstubAllGlobals();
		});

		it('returns zh when browser language starts with zh and no stored choice', async () => {
			const { detectLocale } = await import('./index');
			localStorage.removeItem('locale');
			vi.stubGlobal('navigator', { language: 'zh-CN', languages: undefined });
			expect(detectLocale()).toBe('zh');
			vi.unstubAllGlobals();
		});

		it('returns zh for zh-Hans and zh-TW variants', async () => {
			const { detectLocale } = await import('./index');
			localStorage.removeItem('locale');
			vi.stubGlobal('navigator', { language: 'zh-Hans', languages: undefined });
			expect(detectLocale()).toBe('zh');
			vi.unstubAllGlobals();
		});

		it('returns de when browser language starts with de and no stored choice', async () => {
			const { detectLocale } = await import('./index');
			localStorage.removeItem('locale');
			vi.stubGlobal('navigator', { language: 'de-DE', languages: undefined });
			expect(detectLocale()).toBe('de');
			vi.unstubAllGlobals();
		});

		it('returns en when browser language is something else (fr, ja)', async () => {
			const { detectLocale } = await import('./index');
			localStorage.removeItem('locale');
			vi.stubGlobal('navigator', { language: 'fr-FR', languages: undefined });
			expect(detectLocale()).toBe('en');
			vi.unstubAllGlobals();
		});

		it('returns en when browser language is undefined', async () => {
			const { detectLocale } = await import('./index');
			localStorage.removeItem('locale');
			vi.stubGlobal('navigator', { language: undefined, languages: undefined });
			expect(detectLocale()).toBe('en');
			vi.unstubAllGlobals();
		});

		it('uses navigator.languages when available (before navigator.language)', async () => {
			const { detectLocale } = await import('./index');
			localStorage.removeItem('locale');
			vi.stubGlobal('navigator', { language: 'en-US', languages: ['zh-CN', 'en-US'] });
			expect(detectLocale()).toBe('zh');
			vi.unstubAllGlobals();
		});
	});

	// ── Task 1: M5 i18n keys ──

	describe('M5 i18n keys (login + settings)', () => {
		it('has all 45 new M5 keys with exact English values', async () => {
			const enMod = await import('./en');
			const en = enMod.default as Record<string, string>;

			// Login step-1
			expect(en['login.continue']).toBe('Continue');
			expect(en['login.remember_device']).toBe('Remember this device for 30 days');
			expect(en['login.checking']).toBe('Checking…');
			expect(en['login.passkey_instead']).toBe('Use a passkey instead');
			expect(en['login.forgot_password']).toBe('Forgot password?');
			expect(en['login.footer_self_hosted']).toBe('self-hosted with setjoin');
			expect(en['login.footer_data_local']).toBe('All data stays on your hardware.');

			// MFA step-2
			expect(en['mfa.totp_title']).toBe('Two-step verification');
			expect(en['mfa.totp_subtitle']).toBe('Enter the 6-digit code from your authenticator app.');
			expect(en['mfa.totp_placeholder']).toBe('000 000');
			expect(en['mfa.verifying']).toBe('Verifying…');
			expect(en['mfa.sign_in']).toBe('Sign in');

			// Login threat
			expect(en['login.threat.captcha_title']).toBe('Security check');
			expect(en['login.threat.rate_limited']).toBe('Too many attempts. Wait a moment and try again.');
			expect(en['login.threat.blocked']).toBe('Access is blocked from this location.');

			// Settings cards
			expect(en['settings.profile_card']).toBe('Profile');
			expect(en['settings.display_name']).toBe('Display name');
			expect(en['settings.email_disabled_hint']).toBe('Address is managed by your administrator.');
			expect(en['settings.save_profile']).toBe('Save changes');
			expect(en['settings.profile_saved']).toBe('Profile saved');
			expect(en['settings.appearance_card']).toBe('Appearance & language');
			expect(en['settings.theme']).toBe('Theme');
			expect(en['settings.theme_light']).toBe('Light');
			expect(en['settings.theme_dark']).toBe('Dark');
			expect(en['settings.theme_system']).toBe('System');
			expect(en['settings.compact_rows']).toBe('Compact rows');
			expect(en['settings.compact_rows_desc']).toBe('Tighter mail list density');
			expect(en['settings.mail_card']).toBe('Mail');
			expect(en['settings.undo_window']).toBe('Undo send window');
			expect(en['settings.undo_5s']).toBe('5 seconds');
			expect(en['settings.undo_10s']).toBe('10 seconds');
			expect(en['settings.undo_30s']).toBe('30 seconds');
			expect(en['settings.snooze_morning']).toBe('"Tomorrow morning" snooze time');
			expect(en['settings.bundle_newsletters']).toBe('Bundle newsletters');
			expect(en['settings.bundle_newsletters_desc']).toBe('Group messages tagged Newsletters into a daily row');
			expect(en['settings.keyboard_shortcuts']).toBe('Keyboard shortcuts');
			expect(en['settings.keyboard_shortcuts_desc']).toBe('e archive · s snooze · c compose · / search');
			expect(en['settings.desktop_notifications']).toBe('Desktop notifications');
			expect(en['settings.desktop_notifications_desc']).toBe('Only for messages tagged Urgent');
			expect(en['settings.security_card']).toBe('Security');
			expect(en['settings.add_passkey']).toBe('Add passkey');
			expect(en['settings.change_password']).toBe('Change password');
			expect(en['settings.totp_enrolled']).toBe('Authenticator app, enrolled {date}');
			expect(en['settings.passkey_added']).toBe('Added {date} · {device}');
			expect(en['settings.saved']).toBe('Saved');
			expect(en['settings.subtitle']).toBe('Your preferences. Server administration lives in the admin consoles.');
		});
	});

	// ── C1: Key Coverage Assertion (CI gate) ──

	describe('key coverage assertion (C1)', () => {
		// P4: the three S/MIME encrypt-failure markers + the toggle-time hint must
		// exist in every locale (the compose UX maps the stable marker → these keys;
		// a missing key would render the raw key string, never the human copy).
		it('has all four smime encrypt error keys in every locale', async () => {
			const keys = [
				'compose.smime_encrypt_no_cert',
				'compose.smime_encrypt_no_sender_cert',
				'compose.smime_encrypt_no_journal_cert',
				'compose.smime_encrypt_no_cert_hint',
			];
			for (const mod of [await import('./en'), await import('./zh'), await import('./de')]) {
				const bundle = mod.default as Record<string, string>;
				for (const k of keys) {
					expect(bundle[k]).toBeTruthy();
				}
			}
		});

		it('every en key exists in zh bundle', async () => {
			const enMod = await import('./en');
			const zhMod = await import('./zh');
			const en = enMod.default as Record<string, string>;
			const zh = zhMod.default as Record<string, string>;
			const enKeys = Object.keys(en);
			const zhKeys = new Set(Object.keys(zh));

			const missingInZh: string[] = [];
			for (const key of enKeys) {
				if (!zhKeys.has(key)) {
					missingInZh.push(key);
				}
			}
			expect(missingInZh).toEqual([]);
		});

		it('every en key exists in de bundle', async () => {
			const enMod = await import('./en');
			const deMod = await import('./de');
			const en = enMod.default as Record<string, string>;
			const de = deMod.default as Record<string, string>;
			const enKeys = Object.keys(en);
			const deKeys = new Set(Object.keys(de));

			const missingInDe: string[] = [];
			for (const key of enKeys) {
				if (!deKeys.has(key)) {
					missingInDe.push(key);
				}
			}
			expect(missingInDe).toEqual([]);
		});

		it('zh bundle has no extra keys beyond en', async () => {
			const enMod = await import('./en');
			const zhMod = await import('./zh');
			const en = enMod.default as Record<string, string>;
			const zh = zhMod.default as Record<string, string>;
			const enKeys = new Set(Object.keys(en));
			const zhKeys = Object.keys(zh);

			const extraInZh: string[] = [];
			for (const key of zhKeys) {
				if (!enKeys.has(key)) {
					extraInZh.push(key);
				}
			}
			expect(extraInZh).toEqual([]);
		});

		it('de bundle has no extra keys beyond en', async () => {
			const enMod = await import('./en');
			const deMod = await import('./de');
			const en = enMod.default as Record<string, string>;
			const de = deMod.default as Record<string, string>;
			const enKeys = new Set(Object.keys(en));
			const deKeys = Object.keys(de);

			const extraInDe: string[] = [];
			for (const key of deKeys) {
				if (!enKeys.has(key)) {
					extraInDe.push(key);
				}
			}
			expect(extraInDe).toEqual([]);
		});

		it('all three bundles have the same number of keys', async () => {
			const enMod = await import('./en');
			const zhMod = await import('./zh');
			const deMod = await import('./de');
			const enLen = Object.keys(enMod.default as Record<string, string>).length;
			const zhLen = Object.keys(zhMod.default as Record<string, string>).length;
			const deLen = Object.keys(deMod.default as Record<string, string>).length;

			expect(zhLen).toBe(enLen);
			expect(deLen).toBe(enLen);
		});
	});

	// ── SP1 Phase 6: contacts-cert + encryption-marker + lock-idiom keys ──

	describe('SP1 Phase 6 i18n keys (contacts-cert / encrypt-markers / lock)', () => {
		it('contacts cert title exists in all three locales and is non-empty', () => {
			for (const locale of ['en', 'zh', 'de'] as const) {
				setLocale(locale);
				const val = t('settings.contacts_certs.title');
				expect(val).not.toBe('settings.contacts_certs.title');
				expect(val.length).toBeGreaterThan(0);
			}
		});

		it('compose.smime_encrypt_no_cert resolves with address interpolation in all locales', () => {
			for (const locale of ['en', 'zh', 'de'] as const) {
				setLocale(locale);
				const val = t('compose.smime_encrypt_no_cert', { addresses: 'bob@example.com' });
				expect(val).not.toBe('compose.smime_encrypt_no_cert');
				expect(val.length).toBeGreaterThan(0);
			}
		});

		it('inbox.encrypted_indicator exists in all three locales and is non-empty', () => {
			for (const locale of ['en', 'zh', 'de'] as const) {
				setLocale(locale);
				const val = t('inbox.encrypted_indicator');
				expect(val).not.toBe('inbox.encrypted_indicator');
				expect(val.length).toBeGreaterThan(0);
			}
		});

		it('all contacts_certs sub-keys exist in en bundle', async () => {
			const enMod = await import('./en');
			const en = enMod.default as Record<string, string>;
			const required = [
				'settings.contacts_certs.title',
				'settings.contacts_certs.empty_title',
				'settings.contacts_certs.empty_body',
				'settings.contacts_certs.import_heading',
				'settings.contacts_certs.label',
				'settings.contacts_certs.cert_file',
				'settings.contacts_certs.import_btn',
				'settings.contacts_certs.importing',
				'settings.contacts_certs.import_error',
				'settings.contacts_certs.delete',
				'settings.contacts_certs.delete_confirm',
				'settings.contacts_certs.address',
				'settings.contacts_certs.source',
				'settings.contacts_certs.expires',
				'settings.contacts_certs.source_harvested',
				'settings.contacts_certs.source_imported',
				'settings.contacts_certs.expired',
				'settings.contacts_certs.signing_only',
				'settings.contacts_certs.expiring_soon',
				'compose.smime_encrypt_no_cert',
				'compose.smime_encrypt_no_sender_cert',
				'compose.smime_encrypt_no_journal_cert',
				'inbox.encrypted_indicator',
				'inbox.encrypted_placeholder',
			];
			for (const key of required) {
				expect(en[key], `missing key: ${key}`).toBeTruthy();
			}
		});
	});
});
