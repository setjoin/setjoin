import type { EffectivePerms } from '$lib/admin/roles';

/**
 * Pure helper for AccessPreview source attribution.
 *
 * sourceFor — given the effective permissions data and a permission key,
 * returns a comma-joined string of role names whose source entries include
 * that key.  Returns '' when data is null or no source grants the key.
 */
export function sourceFor(
	data: EffectivePerms | null | undefined,
	key: string
): string {
	return (data?.sources ?? [])
		.filter((s) => s.permissions.includes(key))
		.map((s) => s.roleName)
		.join(', ');
}
