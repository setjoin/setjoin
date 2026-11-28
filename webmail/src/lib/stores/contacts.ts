import { get, writable } from 'svelte/store';
import {
	addressBookGet,
	contactQuery,
	contactGet,
	contactSet,
	contactFindDuplicates,
	contactMerge,
	galSearch
} from '$lib/jmap/client';
import type { DuplicateCluster } from '$lib/jmap/client';
import type { AddressBook, ContactCard, JmapMethodResponse } from '$lib/types/jmap';

export const addressBooks = writable<AddressBook[]>([]);
export const contacts = writable<ContactCard[]>([]);
export const selectedAddressBookId = writable<string | null>(null);
export const galResults = writable<ContactCard[]>([]);
export const viewMode = writable<'list' | 'grid'>('list');
export const searchText = writable<string>('');
export const isGAL = writable<boolean>(false);
// Find-duplicates: the clusters, plus a by-id map of the involved contacts so the
// UI can render names without another round-trip.
export const duplicates = writable<DuplicateCluster[]>([]);
export const duplicateContacts = writable<Record<string, ContactCard>>({});

export function reset() {
	addressBooks.set([]);
	contacts.set([]);
	selectedAddressBookId.set(null);
	galResults.set([]);
	viewMode.set('list');
	searchText.set('');
	isGAL.set(false);
	duplicates.set([]);
	duplicateContacts.set({});
}

export async function loadAddressBooks(): Promise<void> {
	const list = await addressBookGet();
	addressBooks.set(list);
	if (list.length > 0) {
		selectedAddressBookId.update((id) => id || list[0].id);
	}
}

// Monotonic load token — see CalendarEventsStore.load (stores/calendarEvents.svelte.ts): only the newest
// of concurrently racing loads may write the store.
let contactsLoadSeq = 0;

export async function loadContacts(abId: string | null, text = '', signal?: AbortSignal): Promise<void> {
	if (!abId) return;
	const seq = ++contactsLoadSeq;
	const filter = text ? { inAddressBook: abId, text } : { inAddressBook: abId };
	const result = await contactQuery(filter, null, 0, 100, signal);
	const list = result.ids && result.ids.length > 0 ? await contactGet(result.ids, undefined, signal) : [];
	if (seq !== contactsLoadSeq) return; // superseded by a newer load
	contacts.set(list);
}

export async function searchGAL(text: string, signal?: AbortSignal): Promise<void> {
	if (!text) {
		galResults.set([]);
		return;
	}
	const list = await galSearch(text, 50, signal);
	galResults.set(list);
}

export async function createContact(contactData: Partial<ContactCard>): Promise<string | undefined> {
	const result = (await contactSet({ k1: contactData }, null, null)) as JmapMethodResponse;
	return result.created?.k1?.id;
}

export async function updateContact(id: string, contactData: Partial<ContactCard>): Promise<void> {
	await contactSet(null, { [id]: contactData }, null);
}

export async function deleteContact(id: string): Promise<void> {
	await contactSet(null, null, [id]);
}

// Detect duplicate clusters and fetch the involved contacts' details in one hop
// so the UI can render names for the keep/drop choice.
export async function findDuplicates(): Promise<void> {
	const clusters = await contactFindDuplicates();
	duplicates.set(clusters);
	const ids = [...new Set(clusters.flatMap((c) => c.contactIds))];
	if (ids.length > 0) {
		const list = await contactGet(ids);
		duplicateContacts.set(Object.fromEntries(list.map((c) => [c.id, c])));
	} else {
		duplicateContacts.set({});
	}
}

// Merge dropId into keepId, then refresh the visible contact list + re-detect so
// both the list and the duplicates view reflect the merge.
export async function merge(keepId: string, dropId: string): Promise<void> {
	await contactMerge(keepId, dropId);
	await loadContacts(get(selectedAddressBookId), get(searchText));
	await findDuplicates();
}
