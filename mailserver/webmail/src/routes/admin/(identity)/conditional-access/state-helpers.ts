// state-helpers.ts — pure helpers for the CA admin console (no side-effects, no imports).
// All i18n rendering uses keys returned here, never raw English strings.

export type CAState = 'off' | 'report_only' | 'on';

/** i18n key for the tri-state label — the page renders t(stateLabelKey(s)). */
export function stateLabelKey(state: string): string {
	if (state === 'on') return 'admin.ca.state.on';
	if (state === 'report_only') return 'admin.ca.state.report_only';
	return 'admin.ca.state.off';
}

export function stateBadgeVariant(state: string): 'success' | 'warning' | 'neutral' {
	if (state === 'on') return 'success';
	if (state === 'report_only') return 'warning';
	return 'neutral';
}

/** Back-compat paste path: parse a comma-separated id list into numbers. */
export function parseIdList(raw: string): number[] {
	return raw
		.split(',')
		.map((p) => p.trim())
		.filter(Boolean)
		.map(Number)
		.filter((n) => Number.isFinite(n) && !Number.isNaN(n));
}

/** True iff the form requires a typed confirm before save. */
export function needsTypedConfirm(form: {
	state: string;
	scope_type: string;
	action: string;
}): boolean {
	return form.state === 'on' &&
		form.scope_type === 'global' &&
		(form.action === 'block' || form.action === 'step_up');
}

/**
 * Mirrors ca_lockout_guard: an admin "remains reachable" iff excluded by user-id,
 * break-glass, OR membership in an excluded user-group.
 */
export function preflightImpact(args: {
	adminIds: number[];
	excludeUsers: number[];
	excludeGroups: number[];
	breakGlass: number[];
	adminGroups: Record<number, number[]>;
}): { remaining: number; willReject: boolean } {
	const exU = new Set([...args.excludeUsers, ...args.breakGlass]);
	const exG = new Set(args.excludeGroups);
	const remaining = args.adminIds.filter(
		(id) => exU.has(id) || (args.adminGroups[id] ?? []).some((g) => exG.has(g))
	).length;
	return { remaining, willReject: remaining === 0 };
}

/** Localizable fallback key (+ params) for when the server returns no HINT/detail. */
export type ErrorKey = { key: string; params?: Record<string, unknown> };

export function errorKey(status: number): ErrorKey {
	if (status === 409) return { key: 'admin.ca.error.lockout' };
	if (status === 400) return { key: 'admin.ca.error.invalid' };
	return { key: 'admin.ca.error.save', params: { status } };
}

/**
 * Returns the server detail/HINT verbatim when present (it carries the actionable
 * reducer HINT); otherwise a localizable ErrorKey the page renders with t().
 */
export function saveErrorMessage(status: number, detail: string): string | ErrorKey {
	return detail ? detail : errorKey(status);
}

/**
 * Returns the promote mode for the dangerous-action dialog.
 * 'remediation' → strand-all-admins panel (no confirm); 'confirm' → type-to-confirm;
 * 'none' → no dialog needed.
 */
export function promoteMode(
	form: { state: string; scope_type: string; action: string },
	remaining: number
): 'remediation' | 'confirm' | 'none' {
	if (!needsTypedConfirm(form)) return 'none';
	return remaining === 0 ? 'remediation' : 'confirm';
}
