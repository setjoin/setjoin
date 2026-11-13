import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { WelcomeEmailConfig } from '$lib/admin/client';

// ── admin client mocks (established seam — see emailActionStore.svelte.test.ts) ──
const adminGetWelcomeEmail = vi.fn();
const adminPutWelcomeEmail = vi.fn();
const adminTestSendWelcomeEmail = vi.fn();

vi.mock('$lib/admin/client', () => ({
	adminGetWelcomeEmail: (...a: unknown[]) => adminGetWelcomeEmail(...a),
	adminPutWelcomeEmail: (...a: unknown[]) => adminPutWelcomeEmail(...a),
	adminTestSendWelcomeEmail: (...a: unknown[]) => adminTestSendWelcomeEmail(...a)
}));

import {
	WelcomeForm,
	validateEnglish,
	hasErrors,
	configsEqual,
	insertAt,
	lintPlaceholders,
	nearestToken,
	localeStatus,
	emptyLocale
} from './welcomeForm.svelte';

function cfgWith(en: { subject?: string; body_text?: string; body_html?: string }): WelcomeEmailConfig {
	return {
		enabled: true,
		default_locale: 'en',
		locales: {
			en: { subject: '', body_text: '', body_html: '', ...en },
			zh: emptyLocale(),
			de: emptyLocale()
		}
	};
}

beforeEach(() => {
	adminGetWelcomeEmail.mockReset();
	adminPutWelcomeEmail.mockReset();
	adminTestSendWelcomeEmail.mockReset();
});

// ── C5: en-required validation gate ──
describe('validateEnglish (C5)', () => {
	it('flags missing en subject and body', () => {
		const errs = validateEnglish(cfgWith({}));
		expect(errs.subject).toBe('admin.welcome_email.err_subject');
		expect(errs.body).toBe('admin.welcome_email.err_body');
		expect(hasErrors(errs)).toBe(true);
	});

	it('passes when en subject and body are present', () => {
		const errs = validateEnglish(cfgWith({ subject: 'Hi', body_text: 'Welcome' }));
		expect(errs.subject).toBe('');
		expect(errs.body).toBe('');
		expect(hasErrors(errs)).toBe(false);
	});

	it('treats whitespace-only as empty', () => {
		const errs = validateEnglish(cfgWith({ subject: '   ', body_text: '\n\t' }));
		expect(hasErrors(errs)).toBe(true);
	});
});

// ── setField immutability (A4) ──
describe('WelcomeForm.setField', () => {
	it('replaces the locales object and locale object immutably', () => {
		const form = new WelcomeForm();
		const beforeCfg = form.cfg;
		const beforeLocales = form.cfg.locales;
		const beforeEn = form.cfg.locales.en;
		form.setField('subject', 'Hello');
		expect(form.cfg).not.toBe(beforeCfg);
		expect(form.cfg.locales).not.toBe(beforeLocales);
		expect(form.cfg.locales.en).not.toBe(beforeEn);
		expect(form.cfg.locales.en.subject).toBe('Hello');
		// Sibling locales are untouched references-wise in value.
		expect(form.cfg.locales.zh.subject).toBe('');
	});

	it('clears the subject error once the field gets content', () => {
		const form = new WelcomeForm();
		form.validate(); // sets both errors (empty en)
		expect(form.subjectError).not.toBe('');
		form.setField('subject', 'Now filled');
		expect(form.subjectError).toBe('');
	});
});

// ── C3: caret-aware insertion ──
describe('insertAt (C3) + insertPlaceholder', () => {
	it('inserts at the caret and returns the new caret position', () => {
		const res = insertAt('Hi , welcome', '{{DisplayName}}', 3, 3);
		expect(res.value).toBe('Hi {{DisplayName}}, welcome');
		expect(res.caret).toBe(3 + '{{DisplayName}}'.length);
	});

	it('replaces a selection range', () => {
		const res = insertAt('Hi XXX!', '{{Email}}', 3, 6);
		expect(res.value).toBe('Hi {{Email}}!');
	});

	it('insertPlaceholder mutates the active locale field and returns caret', () => {
		const form = new WelcomeForm();
		form.setField('body_text', 'AB');
		const caret = form.insertPlaceholder('body_text', '{{Username}}', 1, 1);
		expect(form.cfg.locales.en.body_text).toBe('A{{Username}}B');
		expect(caret).toBe(1 + '{{Username}}'.length);
	});
});

// ── C7: true value-equality dirty (clears on revert) ──
describe('configsEqual + dirty (C7)', () => {
	it('dirty clears when a field is reverted to its saved value', async () => {
		adminGetWelcomeEmail.mockResolvedValue(cfgWith({ subject: 'Orig', body_text: 'Body' }));
		const form = new WelcomeForm();
		await form.load();
		expect(form.isDirty).toBe(false);

		form.setField('subject', 'Changed');
		expect(form.isDirty).toBe(true);

		form.setField('subject', 'Orig'); // back to saved value
		expect(form.isDirty).toBe(false);
	});

	it('configsEqual is structural, not reference', () => {
		const a = cfgWith({ subject: 'x', body_text: 'y' });
		const b = cfgWith({ subject: 'x', body_text: 'y' });
		expect(a).not.toBe(b);
		expect(configsEqual(a, b)).toBe(true);
		b.locales.en.body_html = '<p>diff</p>';
		expect(configsEqual(a, b)).toBe(false);
	});

	it('discard reverts all locales to the saved snapshot', async () => {
		adminGetWelcomeEmail.mockResolvedValue(cfgWith({ subject: 'S', body_text: 'B' }));
		const form = new WelcomeForm();
		await form.load();
		form.setField('subject', 'edited');
		form.setField('body_text', 'edited', 'zh');
		expect(form.isDirty).toBe(true);
		form.discard();
		expect(form.isDirty).toBe(false);
		expect(form.cfg.locales.en.subject).toBe('S');
		expect(form.cfg.locales.zh.body_text).toBe('');
	});
});

// ── C9: placeholder lint ──
describe('lintPlaceholders (C9)', () => {
	it('flags {{Displayname}} and suggests {{DisplayName}}', () => {
		const findings = lintPlaceholders('Hi {{Displayname}}');
		expect(findings).toHaveLength(1);
		expect(findings[0].kind).toBe('unknown');
		expect(findings[0].name).toBe('Displayname');
		expect(findings[0].suggestion).toBe('DisplayName');
	});

	it('catches an unbalanced {{', () => {
		const findings = lintPlaceholders('Hi {{DisplayName broken');
		expect(findings.some((f) => f.kind === 'unbalanced')).toBe(true);
	});

	it('accepts the canonical tokens with no findings', () => {
		const findings = lintPlaceholders('Hi {{DisplayName}}, your address is {{Email}}.');
		expect(findings).toHaveLength(0);
	});

	it('flags a spaced {{ Email }} as not-canonical (sent literally)', () => {
		const findings = lintPlaceholders('Open {{ Email }}');
		expect(findings.some((f) => f.kind === 'unknown' && f.suggestion === 'Email')).toBe(true);
	});

	it('nearestToken is case-insensitive', () => {
		expect(nearestToken('email')).toBe('Email');
		expect(nearestToken('webmailurl')).toBe('WebmailURL');
	});
});

// ── C1: locale status ──
describe('localeStatus (C1)', () => {
	// "Usable" must match the backend: notify.resolveWelcomeTemplate uses a
	// locale only when its subject is non-empty; otherwise recipients fall back
	// to the default locale. The status dot tells the same truth, so it cannot
	// turn green on a body-only locale the backend will silently skip.
	it('optional locale is complete when it has a subject', () => {
		expect(localeStatus({ subject: 'x', body_text: '', body_html: '' }, false)).toBe('complete');
	});
	it('optional locale with a body but NO subject is fallback, not complete', () => {
		expect(localeStatus({ subject: '', body_text: 'written but unused', body_html: '' }, false)).toBe(
			'fallback'
		);
	});
	it('required (en) needs BOTH subject and body to be complete', () => {
		expect(localeStatus({ subject: 'x', body_text: 'y', body_html: '' }, true)).toBe('complete');
		expect(localeStatus({ subject: 'x', body_text: '', body_html: '' }, true)).toBe('empty_required');
		expect(localeStatus({ subject: '', body_text: 'y', body_html: '' }, true)).toBe('empty_required');
	});
	it('empty_required for a required empty locale', () => {
		expect(localeStatus(emptyLocale(), true)).toBe('empty_required');
	});
	it('fallback for an optional empty locale', () => {
		expect(localeStatus(emptyLocale(), false)).toBe('fallback');
	});
});

// ── save / sendTest call the client with the right payload (A4) ──
describe('WelcomeForm.save + sendTest', () => {
	it('save PUTs the config when valid and updates the saved snapshot', async () => {
		adminGetWelcomeEmail.mockResolvedValue(cfgWith({ subject: 'S', body_text: 'B' }));
		adminPutWelcomeEmail.mockResolvedValue(undefined);
		const form = new WelcomeForm();
		await form.load();
		form.setField('subject', 'New subject');
		const ok = await form.save();
		expect(ok).toBe(true);
		expect(adminPutWelcomeEmail).toHaveBeenCalledTimes(1);
		const sent = adminPutWelcomeEmail.mock.calls[0][0] as WelcomeEmailConfig;
		expect(sent.locales.en.subject).toBe('New subject');
		// Snapshot advanced → no longer dirty.
		expect(form.isDirty).toBe(false);
	});

	it('save refuses and does not call the client when en is empty', async () => {
		adminGetWelcomeEmail.mockResolvedValue(cfgWith({}));
		const form = new WelcomeForm();
		await form.load();
		const ok = await form.save();
		expect(ok).toBe(false);
		expect(adminPutWelcomeEmail).not.toHaveBeenCalled();
		expect(form.subjectError).toBe('admin.welcome_email.err_subject');
		expect(form.activeLocale).toBe('en');
	});

	it('sendTest POSTs the active locale content', async () => {
		adminGetWelcomeEmail.mockResolvedValue(cfgWith({ subject: 'S', body_text: 'B' }));
		adminTestSendWelcomeEmail.mockResolvedValue(undefined);
		const form = new WelcomeForm();
		await form.load();
		form.activeLocale = 'zh';
		form.setField('subject', '你好', 'zh');
		await form.sendTest();
		expect(adminTestSendWelcomeEmail).toHaveBeenCalledTimes(1);
		const req = adminTestSendWelcomeEmail.mock.calls[0][0] as { locale: string; subject: string };
		expect(req.locale).toBe('zh');
		expect(req.subject).toBe('你好');
	});
});
