// welcomeForm.svelte.ts — the testable form logic behind the welcome-email
// admin editor (`(system)/welcome-email/+page.svelte`). The page is a thin
// view over this rune class plus the pure helpers below; all validation,
// dirty-tracking, placeholder linting, and client calls live here so they can
// be unit-tested without a DOM (A4 + the 10/10 craft amendments C5/C7/C9).

import {
	adminGetWelcomeEmail,
	adminPutWelcomeEmail,
	adminTestSendWelcomeEmail,
	type WelcomeEmailConfig,
	type WelcomeLocaleContent
} from '$lib/admin/client';

export const LOCALES = ['en', 'zh', 'de'] as const;
export type LocaleId = (typeof LOCALES)[number];

/** Canonical, case-sensitive personalization tokens (mirror the Go whitelist). */
export const WELCOME_TOKEN_NAMES = [
	'DisplayName',
	'Email',
	'Username',
	'OrgName',
	'WebmailURL'
] as const;
export type WelcomeTokenName = (typeof WELCOME_TOKEN_NAMES)[number];

/** The visible `{{Token}}` chip labels (learnable exact casing — C4). */
export const WELCOME_TOKENS = WELCOME_TOKEN_NAMES.map((n) => `{{${n}}}`);

/** The i18n key for each token's self-documenting tooltip (C4). */
export const TOKEN_HELP_KEY: Record<WelcomeTokenName, string> = {
	DisplayName: 'admin.welcome_email.token_displayname',
	Email: 'admin.welcome_email.token_email',
	Username: 'admin.welcome_email.token_username',
	OrgName: 'admin.welcome_email.token_orgname',
	WebmailURL: 'admin.welcome_email.token_webmailurl'
};

export function emptyLocale(): WelcomeLocaleContent {
	return { subject: '', body_text: '', body_html: '' };
}

/** A fresh, fully-populated config (used before the server load resolves). */
export function emptyConfig(): WelcomeEmailConfig {
	const locales: Record<string, WelcomeLocaleContent> = {};
	for (const loc of LOCALES) locales[loc] = emptyLocale();
	return { enabled: false, default_locale: 'en', locales };
}

/** Backfill any missing locale so bound inputs are always safe. */
export function normalizeConfig(cfg: WelcomeEmailConfig): WelcomeEmailConfig {
	const locales: Record<string, WelcomeLocaleContent> = { ...cfg.locales };
	for (const loc of LOCALES) {
		if (!locales[loc]) locales[loc] = emptyLocale();
	}
	return { ...cfg, locales };
}

// ── C7: true value-equality (deep equal), so reverting a field clears dirty ──

export function configsEqual(a: WelcomeEmailConfig, b: WelcomeEmailConfig): boolean {
	if (a.enabled !== b.enabled || a.default_locale !== b.default_locale) return false;
	const keys = new Set([...Object.keys(a.locales), ...Object.keys(b.locales)]);
	for (const k of keys) {
		const la = a.locales[k] ?? emptyLocale();
		const lb = b.locales[k] ?? emptyLocale();
		if (la.subject !== lb.subject || la.body_text !== lb.body_text || la.body_html !== lb.body_html) {
			return false;
		}
	}
	return true;
}

// ── C3: caret-aware insertion (pure core; the DOM glue lives in the page) ──

export interface InsertResult {
	value: string;
	caret: number;
}

/** Insert `token` into `value` at [start,end), returning the new value + caret. */
export function insertAt(value: string, token: string, start: number, end: number): InsertResult {
	const s = Math.max(0, Math.min(start, value.length));
	const e = Math.max(s, Math.min(end, value.length));
	const next = value.slice(0, s) + token + value.slice(e);
	return { value: next, caret: s + token.length };
}

// ── C1: per-locale status (drives the tab status dots + aria labels) ──

export type LocaleStatus = 'complete' | 'empty_required' | 'fallback';

export function localeStatus(content: WelcomeLocaleContent | undefined, required: boolean): LocaleStatus {
	const c = content ?? emptyLocale();
	const hasSubject = c.subject.trim() !== '';
	if (required) {
		// en is sent only when both subject and body are present (validateRequired).
		return hasSubject && c.body_text.trim() !== '' ? 'complete' : 'empty_required';
	}
	// zh/de: the backend (notify.resolveWelcomeTemplate) uses this locale only
	// when it has a subject; a body-only locale is skipped and recipients fall
	// back to the default. The dot must say "fallback", not "complete".
	return hasSubject ? 'complete' : 'fallback';
}

// ── C9: edit-time placeholder lint (pure string work, no template engine) ──

export type LintKind = 'unknown' | 'unbalanced';
export interface LintFinding {
	kind: LintKind;
	/** Bare captured name for `unknown` (e.g. "Displayname"). */
	name?: string;
	/** Suggested bare canonical name for `unknown` (e.g. "DisplayName"). */
	suggestion?: string;
}

/** Case-insensitive nearest canonical token name for a mistyped capture. */
export function nearestToken(name: string): WelcomeTokenName {
	const lower = name.trim().toLowerCase();
	// Exact case-insensitive match wins.
	const exact = WELCOME_TOKEN_NAMES.find((t) => t.toLowerCase() === lower);
	if (exact) return exact;
	// Otherwise smallest Levenshtein distance (deterministic, first on tie).
	let best: WelcomeTokenName = WELCOME_TOKEN_NAMES[0];
	let bestD = Infinity;
	for (const t of WELCOME_TOKEN_NAMES) {
		const d = levenshtein(lower, t.toLowerCase());
		if (d < bestD) {
			bestD = d;
			best = t;
		}
	}
	return best;
}

function levenshtein(a: string, b: string): number {
	const m = a.length;
	const n = b.length;
	const dp = Array.from({ length: m + 1 }, (_, i) => i);
	for (let j = 1; j <= n; j++) {
		let prev = dp[0];
		dp[0] = j;
		for (let i = 1; i <= m; i++) {
			const tmp = dp[i];
			dp[i] = Math.min(
				dp[i] + 1,
				dp[i - 1] + 1,
				prev + (a[i - 1] === b[j - 1] ? 0 : 1)
			);
			prev = tmp;
		}
	}
	return dp[m];
}

/**
 * Scan one field's text for placeholder problems. A `{{...}}` is OK only when
 * its EXACT literal form equals a canonical `{{Token}}` (case- and
 * space-sensitive, matching the Go substitution). Anything else is flagged
 * "unknown" with a nearest-match suggestion; a leftover lone `{{` is flagged
 * "unbalanced". De-duplicated, stable order.
 */
export function lintPlaceholders(text: string): LintFinding[] {
	const findings: LintFinding[] = [];
	const seen = new Set<string>();
	const valid = new Set<string>(WELCOME_TOKENS);
	const re = /\{\{\s*([^{}]*?)\s*\}\}/g;
	let m: RegExpExecArray | null;
	let cleaned = text;
	while ((m = re.exec(text)) !== null) {
		const literal = m[0];
		const name = m[1];
		if (valid.has(literal)) continue; // exact canonical form — fine
		const suggestion = nearestToken(name);
		const dedupe = `unknown:${name}`;
		if (!seen.has(dedupe)) {
			seen.add(dedupe);
			findings.push({ kind: 'unknown', name, suggestion });
		}
	}
	// Strip every balanced `{{...}}` (valid or not), then look for a lone brace pair.
	cleaned = text.replace(/\{\{[^{}]*?\}\}/g, '');
	if ((cleaned.includes('{{') || cleaned.includes('}}')) && !seen.has('unbalanced')) {
		seen.add('unbalanced');
		findings.push({ kind: 'unbalanced' });
	}
	return findings;
}

// ── C5: en-required validation gate ──

export interface ValidationErrors {
	/** i18n key for the subject error, or '' when valid. */
	subject: string;
	/** i18n key for the body error, or '' when valid. */
	body: string;
}

/** Validate the required English subject + plain-text body. */
export function validateEnglish(cfg: WelcomeEmailConfig): ValidationErrors {
	const en = cfg.locales['en'] ?? emptyLocale();
	return {
		subject: en.subject.trim() === '' ? 'admin.welcome_email.err_subject' : '',
		body: en.body_text.trim() === '' ? 'admin.welcome_email.err_body' : ''
	};
}

export function hasErrors(e: ValidationErrors): boolean {
	return e.subject !== '' || e.body !== '';
}

// ── The rune class the page binds to ──

export class WelcomeForm {
	cfg = $state<WelcomeEmailConfig>(emptyConfig());
	/** Last-saved snapshot (C7 deep-equal baseline; structuredClone copy). */
	saved = $state<WelcomeEmailConfig>(emptyConfig());
	activeLocale = $state<LocaleId>('en');
	loading = $state(true);
	saving = $state(false);
	testing = $state(false);
	loadError = $state('');
	subjectError = $state('');
	bodyError = $state('');

	/** True when the current config differs from the last saved snapshot (C7). */
	isDirty = $derived(!configsEqual(this.cfg, this.saved));

	/** The content object for the active locale (always defined). */
	current = $derived(this.cfg.locales[this.activeLocale] ?? emptyLocale());

	private snapshot(cfg: WelcomeEmailConfig): WelcomeEmailConfig {
		// $state.snapshot unwraps the runes Proxy so structuredClone can deep-copy
		// it (C7: a true value-equality baseline, immune to later mutation).
		return structuredClone($state.snapshot(cfg)) as WelcomeEmailConfig;
	}

	async load(): Promise<void> {
		this.loading = true;
		this.loadError = '';
		try {
			const got = normalizeConfig(await adminGetWelcomeEmail());
			this.cfg = got;
			this.saved = this.snapshot(got);
		} catch (e) {
			this.loadError = e instanceof Error ? e.message : 'Failed to load';
		} finally {
			this.loading = false;
		}
	}

	/** Immutable field set on the given locale (default: active). */
	setField(field: keyof WelcomeLocaleContent, value: string, locale: LocaleId = this.activeLocale): void {
		const next: WelcomeLocaleContent = { ...(this.cfg.locales[locale] ?? emptyLocale()), [field]: value };
		this.cfg = { ...this.cfg, locales: { ...this.cfg.locales, [locale]: next } };
		// Clear a field error as soon as the offending field gains content.
		if (locale === 'en' && field === 'subject' && value.trim() !== '') this.subjectError = '';
		if (locale === 'en' && field === 'body_text' && value.trim() !== '') this.bodyError = '';
	}

	/** Caret-aware placeholder insertion into the active locale's field. */
	insertPlaceholder(field: 'subject' | 'body_text', token: string, start: number, end: number): number {
		const cur = this.cfg.locales[this.activeLocale]?.[field] ?? '';
		const res = insertAt(cur, token, start, end);
		this.setField(field, res.value);
		return res.caret;
	}

	/** Run the en-required validation; returns true when valid (C5). */
	validate(): boolean {
		const errs = validateEnglish(this.cfg);
		this.subjectError = errs.subject;
		this.bodyError = errs.body;
		return !hasErrors(errs);
	}

	/** Set enabled (C8 confirms the ON→OFF case before calling this). */
	setEnabled(on: boolean): void {
		this.cfg = { ...this.cfg, enabled: on };
	}

	setDefaultLocale(loc: string): void {
		this.cfg = { ...this.cfg, default_locale: loc };
	}

	/** Persist the whole config. Returns true on success. */
	async save(): Promise<boolean> {
		if (!this.validate()) {
			this.activeLocale = 'en';
			return false;
		}
		this.saving = true;
		try {
			await adminPutWelcomeEmail(this.cfg);
			this.saved = this.snapshot(this.cfg);
			return true;
		} finally {
			this.saving = false;
		}
	}

	/** C7: revert every locale to the last saved snapshot. */
	discard(): void {
		this.cfg = this.snapshot(this.saved);
		this.subjectError = '';
		this.bodyError = '';
	}

	/** Test-send the active locale's content to the signed-in admin. */
	async sendTest(): Promise<void> {
		const c = this.cfg.locales[this.activeLocale] ?? emptyLocale();
		this.testing = true;
		try {
			await adminTestSendWelcomeEmail({
				locale: this.activeLocale,
				subject: c.subject,
				body_text: c.body_text,
				body_html: c.body_html
			});
		} finally {
			this.testing = false;
		}
	}
}
