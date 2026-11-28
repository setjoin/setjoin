// Shared theme/density apply-and-persist logic used by both settings pages
// (src/routes/settings/+page.svelte and src/routes/settings/appearance/+page.svelte).
// Resolves the mode/density, writes localStorage, and toggles the documentElement
// dataset attribute that theme/*.css reads.
//
// NOT used by src/app.html's pre-paint anti-FOUC inline script — that script runs
// before Vite processing and cannot import a TS module, so it keeps its own
// standalone copy of the same resolve logic by necessity.

export type ThemeMode = 'system' | 'dark' | 'light';
export type Density = 'comfortable' | 'compact';

export function applyTheme(mode: ThemeMode): void {
	if (typeof window === 'undefined') return;
	localStorage.setItem('sj-theme', mode);
	const dark =
		mode === 'dark' || (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
	if (dark) {
		document.documentElement.dataset.theme = 'dark';
	} else {
		delete document.documentElement.dataset.theme;
	}
}

export function applyDensity(density: Density): void {
	if (typeof window === 'undefined') return;
	localStorage.setItem('density', density);
	if (density === 'compact') {
		document.documentElement.dataset.density = 'compact';
	} else {
		delete document.documentElement.dataset.density;
	}
}
