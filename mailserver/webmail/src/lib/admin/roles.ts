import { adminFetch } from './transport';

export interface PermissionCatalogEntry {
	key: string;
	category: string;
	description: string;
	isSensitive: boolean;
}

export interface AdminRole {
	id: number;
	name: string;
	description: string;
	permissions: string[];
	domainScope?: number | null;
	isBuiltin: boolean;
	memberCount: number;
	createdAt: string;
	updatedAt: string;
	sodClass?: string | null;
}

export interface RoleMember {
	userId: number;
	userEmail: string;
	displayName: string;
	domainOverride?: number | null;
	grantedBy: number;
	grantedAt: string;
	expiresAt?: string | null;
	/** Whether the caller has sufficient authority to remove or reassign this member.
	 *  Matches the same admin_effective_authority computation as admin_protection_check.
	 *  Undefined on older API responses — treat as manageable=true for backwards compat.
	 */
	manageable?: boolean;
	/** Scope of this assignment: 'ou' = one department subtree, 'set' = a scope-set, null = whole domain. */
	scopeType?: 'ou' | 'set' | null;
	/** Department id ('ou') or scope-set id ('set') this assignment is scoped to. */
	scopeId?: number | null;
	/** Name of the scope-set when scopeType==='set' (joined server-side); absent when the set was removed. */
	setName?: string;
}

export interface RoleDetail {
	role: AdminRole;
	members: RoleMember[];
}

export interface EffectivePerms {
	permissions: string[];
	domainScope?: number | null;
	sources: Array<{
		roleGroupId: number;
		roleName: string;
		permissions: string[];
		effectiveScope?: number | null;
	}>;
	consoles: string[];
}

export async function adminPermissionCatalog(): Promise<PermissionCatalogEntry[]> {
	const res = await adminFetch('/admin/permissions');
	return (await res.json()) as PermissionCatalogEntry[];
}

export async function adminListRoles(): Promise<AdminRole[]> {
	const res = await adminFetch('/admin/roles');
	return (await res.json()) as AdminRole[];
}

export async function adminGetRole(id: number): Promise<RoleDetail> {
	const res = await adminFetch('/admin/roles/' + id);
	return (await res.json()) as RoleDetail;
}

export async function adminCreateRole(
	data: { name: string; description: string; permissions: string[]; domainScope?: number | null },
	reason?: string
): Promise<{ id: number }> {
	const headers: Record<string, string> = {};
	if (reason) headers['X-Audit-Reason'] = reason;
	const res = await adminFetch('/admin/roles', { method: 'POST', body: JSON.stringify(data), headers });
	return (await res.json()) as { id: number };
}

export async function adminUpdateRole(
	id: number,
	patch: { name?: string; description?: string; permissions?: string[]; domainScope?: number | null },
	reason?: string
): Promise<void> {
	const headers: Record<string, string> = {};
	if (reason) headers['X-Audit-Reason'] = reason;
	await adminFetch('/admin/roles/' + id, { method: 'PUT', body: JSON.stringify(patch), headers });
}

export async function adminDeleteRole(id: number, reason?: string): Promise<void> {
	const headers: Record<string, string> = {};
	if (reason) headers['X-Audit-Reason'] = reason;
	await adminFetch('/admin/roles/' + id, { method: 'DELETE', headers });
}

export async function adminAssignMember(
	roleId: number,
	body: { userId: number; domainOverride?: number | null; expiresAt?: string | null; scopeType?: 'ou' | 'set' | null; scopeId?: number | null; eligible?: boolean },
	reason?: string
): Promise<{ id: number }> {
	const headers: Record<string, string> = {};
	if (reason) headers['X-Audit-Reason'] = reason;
	const res = await adminFetch('/admin/roles/' + roleId + '/members', {
		method: 'POST',
		body: JSON.stringify(body),
		headers,
	});
	return (await res.json()) as { id: number };
}

export async function adminRemoveMember(roleId: number, userId: number, reason?: string): Promise<void> {
	const headers: Record<string, string> = {};
	if (reason) headers['X-Audit-Reason'] = reason;
	await adminFetch('/admin/roles/' + roleId + '/members/' + userId, { method: 'DELETE', headers });
}

export async function adminEffectivePermissions(userId: number): Promise<EffectivePerms> {
	const res = await adminFetch('/admin/users/' + userId + '/effective-permissions');
	return (await res.json()) as EffectivePerms;
}

export interface SodModeStatus {
	enabled: boolean;
	violations: Array<{ violationType: string; subject: string; detail: string }>;
}

export async function adminGetSodMode(): Promise<SodModeStatus> {
	const res = await adminFetch('/admin/dengbao/sod-mode');
	return (await res.json()) as SodModeStatus;
}

export async function adminSetSodMode(enabled: boolean, reason?: string): Promise<{ enabled: boolean }> {
	const headers: Record<string, string> = {};
	if (reason) headers['X-Audit-Reason'] = reason;
	const res = await adminFetch('/admin/dengbao/sod-mode', {
		method: 'PUT',
		body: JSON.stringify({ enabled }),
		headers,
	});
	return (await res.json()) as { enabled: boolean };
}
