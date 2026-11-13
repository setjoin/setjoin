/** Badge helpers matching admin-kit §4.5 Users spec. */

export type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';

/**
 * Maps admin role names to M1 Badge variant names.
 * admin-kit §4.5: super_admin→accent, user_admin→info, auditor→warning, user/rest→neutral
 */
export function roleBadgeVariant(role: string): BadgeVariant {
	switch (role) {
		case 'super_admin': return 'accent';
		case 'user_admin': return 'info';
		case 'auditor': return 'warning';
		default: return 'neutral';
	}
}

/**
 * Maps admin-kit user status to M1 Badge variant.
 * admin-kit §4.5: active→success, locked→danger, pending→neutral
 */
export function statusBadgeVariant(status: string): BadgeVariant {
	switch (status) {
		case 'active': return 'success';
		case 'locked': return 'danger';
		case 'pending': return 'neutral';
		default: return 'neutral';
	}
}

/**
 * Human-readable label for user status.
 * admin-kit §4.5: active→"Active", locked→"Locked", pending→"Pending"
 */
export function statusBadgeLabel(status: string): string {
	switch (status) {
		case 'active': return 'Active';
		case 'locked': return 'Locked';
		case 'pending': return 'Pending';
		default: return status;
	}
}
