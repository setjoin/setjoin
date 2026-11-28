import { bootstrapLocale } from '$lib/i18n';

// The deployed app is an SPA. Disabling SSR prevents a prerendered English
// tree from flashing before the browser-selected catalog is available.
export const ssr = false;

export async function load(): Promise<{ localeReady: true }> {
	await bootstrapLocale();
	return { localeReady: true };
}
