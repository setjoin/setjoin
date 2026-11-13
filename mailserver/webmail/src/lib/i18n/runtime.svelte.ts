import type { Locale, Translations } from './index';

/**
 * Runes-aware translation authority. Components that call t() during render
 * track these properties directly, so an atomic catalog commit updates text
 * without remounting the root tree (and therefore without losing focus/forms).
 */
export const i18nRuntime = $state<{
	locale: Locale;
	catalog: Translations;
	revision: number;
}>({
	locale: 'en',
	catalog: {},
	revision: 0,
});
