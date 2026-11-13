// Authenticated-bootstrap composable: the shared guard sequence for route
// initial loads (WP5, decision 5A).
//
// What it does, in order, on mount (never under SSR):
//   1. probes the session via `$lib/stores/session.ts:loadSessionStore`
//      (which fetches `/.well-known/jmap` through the `$lib/http` seam with
//      `loginRedirect: null` — the probe itself never redirects);
//   2. runs the caller's loader ONLY after authentication is PROVEN —
//      `loadSessionStore` catches its own failures and may retain a STALE
//      session object, so its resolution alone is not proof. Proof is a
//      session document this probe freshly produced: non-null AND a different
//      reference than the pre-probe snapshot (a failed load leaves the store
//      untouched — reference-equal stale state or null; a success always
//      installs the newly decoded document);
//   3. aborts the loader's signal on unmount, so in-flight work settles.
//
// What it deliberately does NOT do:
//   - it never redirects by itself. Expiry/anonymous handling stays in the
//     auth (`checkAuth`) and HTTP (`$lib/http.ts`) seams: a loader request
//     that hits a 401 is redirected BY THE SEAM, not here;
//   - it does not gate post-action redirects (e.g. settings/security's
//     `goto('/login')` after revoking the CURRENT session) — those are domain
//     behavior, not bootstrap;
//   - it performs no browser/network work under SSR.
//
// Caller contract (component setup, so `onMount` registration stays
// synchronous):
//   authedBootstrap(
//     (signal) => myResource.load({ signal }),
//     { onUnproven: () => { loading = false; } }   // settle a stranded spinner
//   );

import { onMount } from 'svelte';
import { browser } from '$app/environment';
import { get } from 'svelte/store';
import { jmapSession, loadSessionStore } from '$lib/stores/session';

/** The loader runs after proven authentication; aborting the signal cancels it. */
export type AuthedBootstrapLoader = (signal: AbortSignal) => void | Promise<void>;

export interface AuthedBootstrapOptions {
	/**
	 * Invoked exactly once when the probe did NOT prove a fresh authenticated
	 * session (anonymous visitor, or an unavailable probe that left the store
	 * null/stale). Protected loaders never run in that state, so a page whose
	 * initial `loading` flag defaults to true would strand its spinner — settle
	 * it here (the page's silent-empty/default surface stays the anonymous
	 * outcome; redirects belong to the auth seams, never this callback).
	 * NOT invoked when the unmount already aborted the bootstrap.
	 */
	onUnproven?: () => void;
}

/**
 * True only when the just-finished probe produced a FRESH session document.
 * A failed probe retains the previous store value — a reference-equal stale
 * session or null — and neither is authentication proof.
 */
async function sessionProven(): Promise<boolean> {
	const before = get(jmapSession);
	await loadSessionStore();
	const after = get(jmapSession);
	return after !== null && after !== before;
}

/**
 * Register an authenticated initial-load bootstrap for the calling component.
 * Must be called during component setup (it registers `onMount` synchronously
 * and returns cleanup through it). No-ops under SSR.
 */
export function authedBootstrap(
	loader: AuthedBootstrapLoader,
	options: AuthedBootstrapOptions = {}
): void {
	if (!browser) return;
	onMount(() => {
		const controller = new AbortController();
		void (async () => {
			// The probe runs before the loader and is itself cancellable context:
			// an unmount during the probe skips the loader entirely.
			const proven = await sessionProven();
			if (controller.signal.aborted) return;
			if (!proven) {
				options.onUnproven?.();
				return;
			}
			await loader(controller.signal);
		})();
		return () => controller.abort();
	});
}
