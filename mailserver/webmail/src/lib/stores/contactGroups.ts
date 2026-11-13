import { writable } from 'svelte/store';
import {
	contactGroupQuery,
	contactGroupGet,
	contactGroupSet,
	contactGroupExpand
} from '$lib/jmap/client';
import type { ContactGroup, ContactGroupMember, ExpandedRecipient } from '$lib/types/jmap';

// Personal contact groups (A4 — user-created distribution lists). Mirrors the
// contacts store structure; every op delegates to the ContactGroup/* JMAP helpers.
export const contactGroups = writable<ContactGroup[]>([]);

export function resetGroups(): void {
	contactGroups.set([]);
}

export async function loadGroups(): Promise<void> {
	const { ids } = await contactGroupQuery();
	if (!ids.length) {
		contactGroups.set([]);
		return;
	}
	const list = await contactGroupGet(ids);
	contactGroups.set(list);
}

export async function createGroup(name: string): Promise<string | undefined> {
	const res = await contactGroupSet({ k1: { name } }, null, null);
	await loadGroups();
	return res.created?.k1?.id;
}

export async function renameGroup(id: string, name: string): Promise<void> {
	await contactGroupSet(null, { [id]: { name } }, null);
	await loadGroups();
}

export async function deleteGroup(id: string): Promise<void> {
	await contactGroupSet(null, null, [id]);
	await loadGroups();
}

export async function setMembers(
	groupId: string,
	add: ContactGroupMember[],
	remove: ContactGroupMember[]
): Promise<void> {
	await contactGroupSet(null, null, null, { groupId, add, remove });
	await loadGroups();
}

export async function expandGroup(id: string): Promise<ExpandedRecipient[]> {
	return contactGroupExpand(id);
}
