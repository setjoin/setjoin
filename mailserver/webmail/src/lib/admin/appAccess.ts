/** App-access entitlement helpers (B8). */

/** Maps apps that have a global feature toggle to that toggle key.  Mail has no global toggle. */
export const GLOBAL_FEATURE_MAP: Record<string, string | undefined> = {
	calendar: 'feature.caldav',
	contacts: 'feature.carddav',
	tasks: 'feature.tasks',
	chat: 'feature.chat',
	drive: 'feature.drive',
	meet: 'feature.meet',
};

export interface EffectiveAccess {
	/** Whether the app is effectively accessible to the user. */
	effective: boolean;
	/** True when the block is caused by a global feature toggle being off. */
	limitedGlobally: boolean;
}

/**
 * Derives effective access from a global toggle state and a per-user entitlement.
 * global=false → blocked globally regardless of perUser.
 * global=true ∧ perUser=false → blocked by admin per-user override.
 * global=true ∧ perUser=true → allowed.
 */
export function effectiveAccess(global: boolean, perUser: boolean): EffectiveAccess {
	if (!global) {
		return { effective: false, limitedGlobally: true };
	}
	return { effective: perUser, limitedGlobally: false };
}
