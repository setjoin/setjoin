// touRemediation.ts — reactive store for the ToU-remediation blocked state.
// Set by http.ts when a 403 with remediation:"terms" is received;
// consumed by +layout.svelte to fetch pending ToUs and mount TermsAcceptance.
// ponytail: plain writable — same pattern as deviceBlock.ts.
import { writable } from 'svelte/store';

export interface TouRemediationState {
	pending: boolean;
	/** The tou_id hint from the 403 body (informational; GET /terms/pending is authoritative). */
	touId?: number;
}

export const touRemediation = writable<TouRemediationState>({ pending: false });
