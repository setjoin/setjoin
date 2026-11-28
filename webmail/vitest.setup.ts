import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';
import { loadLocale, setLocale } from '$lib/i18n';

// Production loads exactly one active catalog before mount. Tests switch among
// all locales synchronously, so preload the three isolated chunks explicitly in
// the test-only setup rather than pulling them into the production entry chunk.
await Promise.all([loadLocale('en'), loadLocale('de'), loadLocale('zh')]);
setLocale('en');

// Node 26+ declares a global `localStorage` (undefined without --localstorage-file)
// that shadows the jsdom-provided one. Polyfill with an in-memory store.
const store = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  value: {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => { store.set(key, value); },
    removeItem: (key: string) => { store.delete(key); },
    clear: () => { store.clear(); },
    get length() { return store.size; },
    key: (index: number) => [...store.keys()][index] ?? null,
  },
  writable: true,
  configurable: true,
});

// Mock SvelteKit modules
vi.mock('$app/environment', () => ({ dev: true, browser: true, building: false, version: 'test-build' }));
vi.mock('$app/navigation', () => ({ goto: vi.fn(), invalidateAll: vi.fn() }));

// Mock $app/state — provides the page object used by layouts and pages.
// Tests can override pathname via vi.mocked(page).url.pathname.
vi.mock('$app/state', () => ({
	page: {
		url: { pathname: '/inbox', searchParams: new URLSearchParams(), hash: '' },
		params: {},
		route: { id: '/inbox' },
		status: 200,
		error: null,
		data: {}
	}
}));

// TipTap / ProseMirror browser API stubs for jsdom. Guarded by `typeof
// document !== 'undefined'`: this setup file runs for EVERY test file
// regardless of its own `// @vitest-environment` pragma (the Drive sync
// engine's tests run under `node` — no DOM at all — since the engine is
// deliberately Svelte/DOM-free, spec §4.3's adapter-pure rule).
if (typeof document !== 'undefined') {
	if (typeof document.getSelection !== 'function') {
		Object.defineProperty(document, 'getSelection', {
			value: () => null,
			writable: true,
			configurable: true,
		});
	}
	if (typeof (document as any).elementFromPoint !== 'function') {
		(document as any).elementFromPoint = () => document.body;
	}
	if (typeof (document as any).caretPositionFromPoint !== 'function') {
		(document as any).caretPositionFromPoint = () => null;
	}
}

// Global fetch guard — any fetch a test did not explicitly stub is a phantom
// network call: fail loudly with method + URL instead of silently "succeeding".
// Tests opt in with vi.stubGlobal('fetch', ...) or stubFetchRoutes() from
// $lib/test-utils. Assigned directly (not vi.stubGlobal) so that a test's
// vi.unstubAllGlobals() restores this guard, not the real network fetch.
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
	const url = input instanceof Request ? input.url : String(input);
	const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
	throw new Error(
		`Unstubbed fetch: ${method} ${url} — stub this call in the test ` +
			`(vi.stubGlobal('fetch', …) or stubFetchRoutes() from $lib/test-utils)`
	);
}) as typeof fetch;
