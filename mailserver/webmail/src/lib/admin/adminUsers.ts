// Admin Users helpers — extracted from admin/(mail)/users/+page.svelte (M7 Task 10).
// Admin-kit §4.5: role badge variants, status badge mapping.

import type { ComponentProps } from 'svelte';
import type Badge from '$lib/components/ui/Badge.svelte';

type BadgeVariant = ComponentProps<typeof Badge>['variant'];

/**
 * Maps admin role strings to M1 Badge variants per admin-kit §4.5.
 * super_admin → accent, user_admin → info, auditor → warning, user → neutral.
 */
export function roleBadgeVariant(role: string): BadgeVariant {
	switch (role) {
		case 'super_admin': return 'accent';
		case 'user_admin': return 'info';
		case 'auditor': return 'warning';
		case 'user': return 'neutral';
		default: return 'neutral';
	}
}

/**
 * Maps user status to a {variant, label} pair per admin-kit §4.5.
 * active → success, locked → danger, pending → neutral.
 */
export function statusBadge(status: string): { variant: BadgeVariant; label: string } {
	switch (status) {
		case 'active': return { variant: 'success', label: 'Active' };
		case 'locked': return { variant: 'danger', label: 'Locked' };
		case 'pending': return { variant: 'neutral', label: 'Pending' };
		default: return { variant: 'neutral', label: status };
	}
}

/**
 * MFA display value (mono-friendly). Falls back to em-dash for empty.
 */
export function mfaDisplay(mfa: string | undefined | null): string {
	if (!mfa) return '—';
	return mfa;
}

/**
 * Formats storage bytes as a human-readable string.
 */
export function storageDisplay(bytes: number | undefined | null): string {
	if (bytes == null) return '—';
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}
