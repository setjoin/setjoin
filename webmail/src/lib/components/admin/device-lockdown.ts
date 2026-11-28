// device-lockdown.ts — pure helpers for the device-approval-queue admin console.
// Testable seam: no Svelte, no DOM, no i18n runtime — only data transforms.

import type { IconName } from '$lib/components/Icon.svelte';

export type EnrollState = 'unenrolled' | 'enrolled' | 'approved' | 'revoked';
export type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger';

interface BadgeDef {
	variant: BadgeVariant;
	icon: IconName;
	key: string;
}

// ponytail: local map for CA-2 enrollment lifecycle (not the shared approval/wipe lifecycle).
// Mirrors shared-doc §3 token discipline: variant tokens come from §1 quick-reference.
const BADGE: Record<EnrollState, BadgeDef> = {
	unenrolled: { variant: 'neutral',  icon: 'CircleDashed', key: 'admin.device_lockdown.state.unenrolled' },
	enrolled:   { variant: 'warning',  icon: 'Clock',        key: 'admin.device_lockdown.state.enrolled' },
	approved:   { variant: 'success',  icon: 'ShieldCheck',  key: 'admin.device_lockdown.state.approved' },
	revoked:    { variant: 'danger',   icon: 'ShieldX',      key: 'admin.device_lockdown.state.revoked' },
};

export function enrollBadge(state: string): BadgeDef {
	return BADGE[state as EnrollState] ?? BADGE.unenrolled;
}

// Which lifecycle actions are legal from a given state.
// Mirrors the BZ095 reducer rules: enrolled → approve or revoke; approved → revoke only.
export function actionsFor(state: string): Array<'approve' | 'revoke'> {
	if (state === 'enrolled') return ['approve', 'revoke'];
	if (state === 'approved') return ['revoke'];
	return [];
}

// 'caught_up' = nothing pending (good); 'no_match' = a filter/search found nothing.
// Never conflate: caught_up is warm/green; no_match is neutral.
export function queueEmptyKind(f: { state: string; query: string }): 'caught_up' | 'no_match' {
	return f.state === 'enrolled' && !f.query ? 'caught_up' : 'no_match';
}

// Relative age string for display (e.g. "2h ago"). Absolute time belongs in title/tooltip.
export function relativeAge(iso: string, now = Date.now()): string {
	const d = Math.max(0, now - new Date(iso).getTime());
	const h = Math.floor(d / 3_600_000);
	const m = Math.floor(d / 60_000);
	if (h >= 24) return `${Math.floor(h / 24)}d`;
	if (h >= 1) return `${h}h`;
	if (m >= 1) return `${m}m`;
	return 'just now';
}

// Locale-grouped count for the waiting-count badge + truncation footer.
export function formatCount(n: number): string {
	return new Intl.NumberFormat().format(n);
}
