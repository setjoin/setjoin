import { createEdgeClient, toEdgeProblemError } from '$lib/edge/client';

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

export interface SodModeStatus {
	enabled: boolean;
	violations: Array<{ violationType: string; subject: string; detail: string }>;
}

const rolesEdge = createEdgeClient({
	cache: 'no-store',
	loginRedirect: '/login',
	forbiddenMessage: 'Admin access required'
});

function reasonHeader(reason?: string): { 'X-Audit-Reason'?: string } | undefined {
	return reason ? { 'X-Audit-Reason': reason } : undefined;
}

function adminError(error: unknown, response: Response): Error {
	if (error && typeof error === 'object' && 'error' in error && typeof (error as { error?: unknown }).error === 'string') {
		return new Error((error as { error: string }).error);
	}
	return toEdgeProblemError(error, response);
}

export async function adminPermissionCatalog(): Promise<PermissionCatalogEntry[]> {
	const { data, error, response } = await rolesEdge.GET('/api/admin/permissions');
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data as PermissionCatalogEntry[];
}

export async function adminListRoles(): Promise<AdminRole[]> {
	const { data, error, response } = await rolesEdge.GET('/api/admin/roles');
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data as AdminRole[];
}

export async function adminGetRole(id: number): Promise<RoleDetail> {
	const { data, error, response } = await rolesEdge.GET('/api/admin/roles/{id}', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data as RoleDetail;
}

export async function adminCreateRole(
	body: { name: string; description: string; permissions: string[]; domainScope?: number | null },
	reason?: string
): Promise<{ id: number }> {
	const { data, error, response } = await rolesEdge.POST('/api/admin/roles', {
		params: { header: reasonHeader(reason) },
		body
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data;
}

export async function adminUpdateRole(
	id: number,
	patch: { name?: string; description?: string; permissions?: string[]; domainScope?: number | null },
	reason?: string
): Promise<void> {
	const { error, response } = await rolesEdge.PUT('/api/admin/roles/{id}', {
		params: { path: { id }, header: reasonHeader(reason) },
		body: patch
	});
	if (!response.ok || error !== undefined) {
		throw adminError(error, response);
	}
}

export async function adminDeleteRole(id: number, reason?: string): Promise<void> {
	const { error, response } = await rolesEdge.DELETE('/api/admin/roles/{id}', {
		params: { path: { id }, header: reasonHeader(reason) }
	});
	if (!response.ok || error !== undefined) {
		throw adminError(error, response);
	}
}

export async function adminAssignMember(
	roleId: number,
	body: { userId: number; domainOverride?: number | null; expiresAt?: string | null; scopeType?: 'ou' | 'set' | null; scopeId?: number | null; eligible?: boolean },
	reason?: string
): Promise<{ id: number }> {
	const { data, error, response } = await rolesEdge.POST('/api/admin/roles/{id}/members', {
		params: { path: { id: roleId }, header: reasonHeader(reason) },
		body
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data;
}

export async function adminRemoveMember(roleId: number, userId: number, reason?: string): Promise<void> {
	const { error, response } = await rolesEdge.DELETE('/api/admin/roles/{id}/members/{userId}', {
		params: { path: { id: roleId, userId }, header: reasonHeader(reason) }
	});
	if (!response.ok || error !== undefined) {
		throw adminError(error, response);
	}
}

export async function adminEffectivePermissions(userId: number): Promise<EffectivePerms> {
	const { data, error, response } = await rolesEdge.GET('/api/admin/users/{id}/effective-permissions', {
		params: { path: { id: userId } }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return {
		...data,
		consoles: data.consoles ?? []
	};
}

export async function adminGetSodMode(): Promise<SodModeStatus> {
	const { data, error, response } = await rolesEdge.GET('/api/admin/dengbao/sod-mode');
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data;
}

export async function adminSetSodMode(enabled: boolean, reason?: string): Promise<{ enabled: boolean }> {
	const { data, error, response } = await rolesEdge.PUT('/api/admin/dengbao/sod-mode', {
		params: { header: reasonHeader(reason) },
		body: { enabled }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw adminError(error, response);
	}
	return data;
}
