// riskRemediation.ts — reactive store for the risk-remediation blocked state.
// Set by http.ts when a 403 with remediation:"risk" is received;
// consumed by +layout.svelte to mount RiskRemediation.
// ponytail: plain writable — same pattern as touRemediation.ts.
import { writable } from 'svelte/store';

export interface RiskRemediationState {
	pending: boolean;
	signals?: string[];
	correlationId?: string;
}

export const riskRemediation = writable<RiskRemediationState>({ pending: false });
