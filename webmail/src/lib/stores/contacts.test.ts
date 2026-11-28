import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';

vi.mock('$lib/jmap/client', () => ({
	addressBookGet: vi.fn().mockResolvedValue([]),
	contactQuery: vi.fn().mockResolvedValue({ ids: ['1'] }),
	contactGet: vi.fn().mockResolvedValue([
		{ id: '1', displayName: 'Ann A', emails: [{ type: 'work', address: 'a@x.test' }] },
		{ id: '2', displayName: 'Ann', emails: [{ type: 'home', address: 'a@x.test' }] }
	]),
	contactSet: vi.fn().mockResolvedValue({}),
	contactFindDuplicates: vi
		.fn()
		.mockResolvedValue([{ email: 'a@x.test', contactIds: ['1', '2'] }]),
	contactMerge: vi.fn().mockResolvedValue(undefined),
	galSearch: vi.fn().mockResolvedValue([])
}));

import {
	duplicates,
	duplicateContacts,
	selectedAddressBookId,
	findDuplicates,
	merge,
	reset
} from './contacts';
import * as client from '$lib/jmap/client';

describe('contacts store — find & merge duplicates', () => {
	beforeEach(() => {
		reset();
		vi.clearAllMocks();
	});

	it('findDuplicates surfaces the clusters and fetches involved contacts', async () => {
		await findDuplicates();
		expect(client.contactFindDuplicates).toHaveBeenCalledOnce();
		expect(get(duplicates)).toEqual([{ email: 'a@x.test', contactIds: ['1', '2'] }]);
		// The involved contacts are fetched once (deduped ids) for the keep/drop UI.
		expect(client.contactGet).toHaveBeenCalledWith(['1', '2']);
		const byId = get(duplicateContacts);
		expect(byId['1'].displayName).toBe('Ann A');
		expect(byId['2'].displayName).toBe('Ann');
	});

	it('findDuplicates with no clusters clears the map without a contactGet', async () => {
		(client.contactFindDuplicates as ReturnType<typeof vi.fn>).mockResolvedValueOnce([]);
		await findDuplicates();
		expect(get(duplicates)).toEqual([]);
		expect(get(duplicateContacts)).toEqual({});
		expect(client.contactGet).not.toHaveBeenCalled();
	});

	it('merge calls the client with keep/drop ids then refreshes list + re-detects', async () => {
		selectedAddressBookId.set('ab-1');
		await merge('1', '2');
		expect(client.contactMerge).toHaveBeenCalledWith('1', '2');
		// Refresh: reload the selected address book…
		expect(client.contactQuery).toHaveBeenCalledWith(
			{ inAddressBook: 'ab-1' },
			null,
			0,
			100,
			undefined
		);
		// …and re-run duplicate detection.
		expect(client.contactFindDuplicates).toHaveBeenCalledOnce();
	});
});
