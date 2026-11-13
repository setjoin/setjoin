// Saved-search JMAP client — thin wrappers over SavedSearch/{list,set,delete}.
//
// The gateway resolves the mailbox id from the auth context (never the request)
// and the reducer carries the ownership predicate. This module only shapes the
// call and surfaces the method-level error envelope as a thrown Error. IDs come
// back as strings from the reducer; we re-String() defensively.

import { jmapCall, getAccountId } from './client';
import type { JmapMethodResponse, SavedSearch } from '$lib/types/jmap';

/** Throw if the gateway returned a method-level error envelope (name "error"). */
function assertOk(resp: JmapMethodResponse): JmapMethodResponse {
	if (resp && typeof resp.type === 'string') {
		throw new Error(resp.description || resp.type);
	}
	return resp;
}

/** Normalize a raw saved-search row (ids may be numbers server-side). */
function normalize(row: SavedSearch): SavedSearch {
	return { id: String(row.id), name: row.name, query: row.query, position: row.position };
}

/** List the account's saved searches, ordered by position. */
export async function savedSearchList(): Promise<SavedSearch[]> {
	const accountId = await getAccountId();
	const data = await jmapCall([['SavedSearch/list', { accountId }, '0']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
	return ((resp.list as SavedSearch[]) ?? []).map(normalize);
}

/** Create a saved search from a name + raw query string. Returns the created row. */
export async function savedSearchSet(name: string, query: string): Promise<SavedSearch> {
	const accountId = await getAccountId();
	const data = await jmapCall([['SavedSearch/set', { accountId, name, query }, '0']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
	return normalize(resp.created as unknown as SavedSearch);
}

/** Delete a saved search by id. */
export async function savedSearchDelete(id: string): Promise<void> {
	const accountId = await getAccountId();
	const data = await jmapCall([['SavedSearch/delete', { accountId, id }, '0']]);
	assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}
