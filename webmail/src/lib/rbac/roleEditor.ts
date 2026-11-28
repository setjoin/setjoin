import type { AdminRole } from '$lib/admin/roles';

/**
 * Seed form state for the RoleEditorDialog.
 *
 * clone mode — name is blanked (user must give the clone a new name),
 *              permissions are copied from the source role.
 * edit  mode — name and permissions are loaded from the source role.
 * create mode — both are empty/empty-set (role may be null).
 */
export interface EditorForm {
	name: string;
	description: string;
	selected: Set<string>;
}

export function seedEditorForm(
	mode: 'create' | 'edit' | 'clone',
	role: AdminRole | null | undefined
): EditorForm {
	return {
		name: mode === 'clone' ? '' : (role?.name ?? ''),
		description: role?.description ?? '',
		selected: new Set(role?.permissions ?? [])
	};
}
