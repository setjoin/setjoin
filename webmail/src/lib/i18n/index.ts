// i18n/index.ts — lightweight Svelte 5 i18n framework.
// Source language: English. Translation keys in en.ts / de.ts / zh.ts.
import { writable, get } from 'svelte/store';
import { formatMessage } from './icu';
import { i18nRuntime } from './runtime.svelte';

export type Locale = 'en' | 'de' | 'zh';
export type Translations = Record<string, string>;

const bundles: Partial<Record<Locale, Translations>> = {};
const inflight = new Map<Locale, Promise<Translations>>();
const loaders: Record<Locale, () => Promise<{ default: Translations }>> = {
	en: () => import('./en'),
	de: () => import('./de'),
	zh: () => import('./zh'),
};

export const locale = writable<Locale>('en');

// ── A1: Locale metadata ──

export interface LocaleMeta {
	code: Locale;
	direction: 'ltr' | 'rtl';
	displayName: string;
	firstDayOfWeek: 0 | 1;
	dateFormat: { short: string; medium: string; long: string; full: string };
	numberFormat: { decimal: string; percent: string; currency: string };
}

export const META: Record<Locale, LocaleMeta> = {
	en: {
		code: 'en',
		direction: 'ltr',
		displayName: 'English',
		firstDayOfWeek: 0,
		dateFormat: {
			short: 'M/d/yy',
			medium: 'MMM d, yyyy',
			long: 'MMMM d, yyyy',
			full: 'EEEE, MMMM d, yyyy',
		},
		numberFormat: {
			decimal: '#,##0.###',
			percent: '#,##0%',
			currency: '¤#,##0.00',
		},
	},
	de: {
		code: 'de',
		direction: 'ltr',
		displayName: 'Deutsch',
		firstDayOfWeek: 1,
		dateFormat: {
			short: 'dd.MM.yy',
			medium: 'dd.MM.yyyy',
			long: 'd. MMMM yyyy',
			full: 'EEEE, d. MMMM yyyy',
		},
		numberFormat: {
			decimal: '#.###,##',
			percent: '#.###,##%',
			currency: '¤#.##0,00',
		},
	},
	zh: {
		code: 'zh',
		direction: 'ltr',
		displayName: '中文',
		firstDayOfWeek: 1,
		dateFormat: {
			short: 'y/M/d',
			medium: 'y年M月d日',
			long: 'y年M月d日',
			full: 'y年M月d日 EEEE',
		},
		numberFormat: {
			decimal: '#,##0.###',
			percent: '#,##0%',
			currency: '¤#,##0.00',
		},
	},
};

/** Get metadata for the active locale. */
export function meta(): LocaleMeta {
	const current = get(locale);
	return META[current] ?? META.en;
}

// ── A7: direction ──

/** Get the text direction for the active locale. */
export function dir(): 'ltr' | 'rtl' {
	return meta().direction;
}

// ── A2: formatNumber ──

const LOCALE_MAP: Record<string, string> = { en: 'en-US', de: 'de-DE', zh: 'zh-CN' };

/**
 * Resolve the active Locale to its BCP-47 tag for native `Intl` calls
 * (`en`→`en-US`, `de`→`de-DE`, `zh`→`zh-CN`). Exported so call sites with bespoke
 * `Intl` option sets (MailRow timestamps, CalendarApp, printAgenda) drive the
 * locale from the live store instead of hardcoding a literal.
 */
export function localeCode(): string {
	const current = get(locale);
	return LOCALE_MAP[current] ?? 'en-US';
}

/**
 * Format a number using Intl.NumberFormat with the active locale.
 * Wraps `Intl.NumberFormat` using the active locale.
 */
export function formatNumber(
	value: number,
	style: 'decimal' | 'percent' | 'currency' = 'decimal',
	currency?: string,
): string {
	const opts: Intl.NumberFormatOptions = { style };
	if (style === 'currency' && currency) {
		opts.currency = currency;
	}
	return new Intl.NumberFormat(localeCode(), opts).format(
		style === 'percent' ? value : value,
	);
}

// ── A3: formatDate ──

/**
 * Format a date using Intl.DateTimeFormat with the active locale.
 * Wraps `Intl.DateTimeFormat` using the active locale.
 */
export function formatDate(
	value: Date | string | number,
	style: 'short' | 'medium' | 'long' | 'full' = 'medium',
): string {
	const date = value instanceof Date ? value : new Date(value);
	return new Intl.DateTimeFormat(localeCode(), { dateStyle: style }).format(date);
}

/**
 * Format a date+time using Intl.DateTimeFormat with the active locale and a
 * 24-hour clock (project voice rule). Used for scheduled-send / reminder copy.
 */
export function formatDateTime(value: Date | string | number): string {
	const date = value instanceof Date ? value : new Date(value);
	return new Intl.DateTimeFormat(localeCode(), {
		weekday: 'short',
		day: 'numeric',
		month: 'short',
		hour: '2-digit',
		minute: '2-digit',
		hour12: false,
	}).format(date);
}

// ── A4: formatRelativeTime ──

/**
 * Format a relative time using Intl.RelativeTimeFormat with the active locale.
 * Wraps `Intl.RelativeTimeFormat` using the active locale.
 */
export function formatRelativeTime(value: number, unit: Intl.RelativeTimeFormatUnit): string {
	return new Intl.RelativeTimeFormat(localeCode(), { numeric: 'always' }).format(value, unit);
}

// ── Re-export ICU ──

export { formatMessage } from './icu';

// ── setLocale ──

function commitLocale(l: Locale, catalog: Translations, persist: boolean): void {
	bundles[l] = catalog;
	i18nRuntime.catalog = catalog;
	i18nRuntime.locale = l;
	i18nRuntime.revision += 1;
	locale.set(l);
	if (persist && typeof localStorage !== 'undefined') localStorage.setItem('locale', l);
	if (typeof document !== 'undefined') {
		document.documentElement.lang = l;
		document.documentElement.dir = META[l]?.direction ?? 'ltr';
	}
	if (typeof navigator !== 'undefined' && navigator.serviceWorker?.controller) {
		navigator.serviceWorker.controller.postMessage({ type: 'SETJOIN_PUSH_LOCALE', locale: l });
	}
}

/** Commit an already-loaded locale synchronously (primarily compatibility/tests). */
export function setLocale(l: Locale): void {
	const catalog = bundles[l];
	if (!catalog) throw new Error(`Locale ${l} is not loaded; call switchLocale() first`);
	commitLocale(l, catalog, true);
}

/** Load and validate a catalog without changing the active UI. */
export async function loadLocale(l: Locale): Promise<Translations> {
	const existing = bundles[l];
	if (existing) return existing;
	const pending = inflight.get(l);
	if (pending) return pending;
	const promise = loaders[l]().then((module) => {
		const catalog = module.default;
		if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog)) {
			throw new Error(`Invalid ${l} locale catalog`);
		}
		for (const [key, value] of Object.entries(catalog)) {
			if (!key || typeof value !== 'string') throw new Error(`Invalid ${l} locale entry`);
		}
		bundles[l] = catalog;
		return catalog;
	}).finally(() => inflight.delete(l));
	inflight.set(l, promise);
	return promise;
}

/** Load first, then atomically switch. Failure leaves locale/focus/state intact. */
export async function switchLocale(l: Locale): Promise<void> {
	const catalog = await loadLocale(l);
	commitLocale(l, catalog, true);
}

/** Resolve persisted/browser language before the first localized mount. */
export async function bootstrapLocale(l: Locale = detectLocale()): Promise<Locale> {
	const catalog = await loadLocale(l);
	commitLocale(l, catalog, false);
	return l;
}

// ── t() with ICU auto-detection ──

/**
 * Look up a translation key, optionally substituting parameters.
 *
 * If the translation value contains ICU MessageFormat syntax (`, plural,` or `, select,`),
 * it delegates to `formatMessage`. Otherwise, simple `{param}` string replacement is used.
 */
export function t(key: string, params?: Record<string, string>): string {
	// Reading the runes proxy makes every Svelte render-site reactive without a
	// destructive root-wide keyed remount.
	const bundle = i18nRuntime.catalog;
	void i18nRuntime.revision;
	let text = bundle[key] ?? bundles.en?.[key] ?? key;
	if (params) {
		// A6: auto-detect ICU syntax
		if (text.includes(', plural,') || text.includes(', select,')) {
			text = formatMessage(text, params as Record<string, unknown>);
		} else {
			for (const [k, v] of Object.entries(params)) {
				text = text.replaceAll(`{${k}}`, v);
			}
		}
	}
	return text;
}

export function registerBundle(l: string, trans: Translations) {
	if (l === 'en' || l === 'de' || l === 'zh') bundles[l] = trans;
}

export function detectLocale(): Locale {
	// 1. Explicit persisted choice wins always (§11.2 rule 1).
	if (typeof localStorage !== 'undefined') {
		const stored = localStorage.getItem('locale') as Locale | null;
		if (stored && (stored === 'en' || stored === 'de' || stored === 'zh')) return stored;
	}

	// 2. Browser / system language (§11.2 rule 2).
	//    Match the primary subtag (lowercase, split on '-').
	//    zh/zh-CN/zh-Hans/zh-SG → zh; de/DE/de-AT → de.
	if (typeof navigator !== 'undefined') {
		// navigator.languages may be an empty array in test environments (jsdom).
		// Always include navigator.language as a fallback.
		const langs = (navigator.languages && navigator.languages.length > 0)
			? navigator.languages
			: [navigator.language];
		for (const lang of langs) {
			if (!lang) continue;
			const primary = lang.toLowerCase().split('-')[0];
			if (primary === 'zh') return 'zh';
			if (primary === 'de') return 'de';
		}
	}

	// 3. English default (§11.2 rule 3).
	return 'en';
}
