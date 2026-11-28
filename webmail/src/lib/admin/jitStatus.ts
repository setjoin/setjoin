// Pure JIT-activation status helpers — shared by the My-roles surface, the
// activate dialog, and the policy editor. Kept framework-free so it unit-tests
// without rendering.
import type { MyRole } from './client';

export type JitStatus = 'standing' | 'dormant' | 'active' | 'expiring';

/** Duration presets (minutes) offered by the activate dialog, ascending. */
export const DURATION_PRESETS = [15, 30, 60, 120, 240, 480] as const;

/** Threshold (ms) below which an active window reads "expiring" (amber). */
export const EXPIRING_MS = 5 * 60_000;

/** Remaining ms until the active window ends; ≤0 when the role isn't active. */
export function remainingMs(role: Pick<MyRole, 'activatedUntil'>, now: number): number {
	if (!role.activatedUntil) return 0;
	return new Date(role.activatedUntil).getTime() - now;
}

/**
 * Status for the dot+icon+label:
 *  - standing : not eligible (always-on grant)
 *  - dormant  : eligible, no live window
 *  - active   : eligible, >5 min left
 *  - expiring : eligible, ≤5 min left
 */
export function roleStatus(role: MyRole, now: number): JitStatus {
	if (!role.eligible) return 'standing';
	const rem = remainingMs(role, now);
	if (rem <= 0) return 'dormant';
	return rem <= EXPIRING_MS ? 'expiring' : 'active';
}

/** Whole minutes remaining, rounded up (shows "1 min left" until the final second). */
export function remainingMinutes(role: Pick<MyRole, 'activatedUntil'>, now: number): number {
	return Math.max(0, Math.ceil(remainingMs(role, now) / 60_000));
}

/** Split a clean duration into a localizable {n, unit}; exact-hour multiples read as hours. */
export function splitWindow(minutes: number): { n: number; unit: 'min' | 'hr' } {
	return minutes % 60 === 0 ? { n: minutes / 60, unit: 'hr' } : { n: minutes, unit: 'min' };
}
