// Directory store — department tree and member browsing for HAB-style directory
import { getAccountId, jmapCall } from '$lib/jmap/client';
import type { DirectoryAddress } from '$lib/types/jmap';

// ContactCard/* requires the contacts capability — jmapCall derives it from
// the method name via the c4 capability table (client.ts usingFor).

let _accountId = '-1';

export function setDirectoryAccountId(id: string) {
	_accountId = id;
}

async function resolvedDirectoryAccountId(): Promise<string> {
	if (_accountId !== '-1') return _accountId;
	const primaryAccountId = await getAccountId();
	if (!primaryAccountId) throw new Error('No primary JMAP account');
	return primaryAccountId;
}

export async function directoryTree() {
	const accountId = await resolvedDirectoryAccountId();
	const res = await jmapCall([['ContactCard/directoryTree', { accountId }, 't']]);
	const r = res.methodResponses[0];
	if (r[0] !== 'ContactCard/directoryTree') throw new Error((r[1] as any)?.description || 'Failed to load directory');
	return (r[1] as any).list as DirectoryNode[];
}

export async function directoryMembers(departmentId: number, offset = 0, limit = 50) {
	const accountId = await resolvedDirectoryAccountId();
	const res = await jmapCall([['ContactCard/directoryMembers',
		{ accountId, departmentId, offset, limit }, 'm']]);
	const r = res.methodResponses[0];
	if (r[0] !== 'ContactCard/directoryMembers') throw new Error((r[1] as any)?.description || 'Failed to load members');
	return r[1] as DirectoryMembersResponse;
}

export async function directorySearch(query: string, limit = 50) {
	const accountId = await resolvedDirectoryAccountId();
	const res = await jmapCall([['ContactCard/directorySearch',
		{ accountId, query, limit }, 's']]);
	const r = res.methodResponses[0];
	if (r[0] !== 'ContactCard/directorySearch') throw new Error((r[1] as any)?.description || 'Search failed');
	return (r[1] as any).list as DirectoryMember[];
}

export interface DirectoryNode {
	id: string;
	name: string;
	parentId: string | null;
	path: string;
	depth: number;
	memberCount: number;
	hasManagers: boolean;
}

export interface DirectoryMember {
	id: string;
	email: string;
	// ARCH-004: full address set (primary ∪ aliases ∪ UPN), org-wide + address-aware.
	addresses?: DirectoryAddress[];
	displayName: string;
	firstName: string | null;
	lastName: string | null;
	phone: string | null;
	jobTitle: string | null;
	department: string | null;
	isManager: boolean;
	avatar: { blobId: string } | null;
}

export interface DirectoryMembersResponse {
	accountId: string;
	departmentId: string;
	list: DirectoryMember[];
	total: number;
	offset: number;
}
