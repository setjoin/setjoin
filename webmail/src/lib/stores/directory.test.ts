import { beforeEach, describe, expect, it, vi } from 'vitest';

const { getAccountId, jmapCall } = vi.hoisted(() => ({
	getAccountId: vi.fn(),
	jmapCall: vi.fn(),
}));

vi.mock('$lib/jmap/client', () => ({ getAccountId, jmapCall }));

import { directorySearch, setDirectoryAccountId } from './directory';

describe('directory account resolution', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		setDirectoryAccountId('-1');
		getAccountId.mockResolvedValue('42');
		jmapCall.mockResolvedValue({
			methodResponses: [['ContactCard/directorySearch', { list: [] }, 's']],
		});
	});

	it('resolves the current-account sentinel to the primary JMAP account', async () => {
		await directorySearch('bob', 8);

		expect(getAccountId).toHaveBeenCalledOnce();
		expect(jmapCall).toHaveBeenCalledWith([
			['ContactCard/directorySearch', { accountId: '42', query: 'bob', limit: 8 }, 's'],
		]);
	});

	it('preserves an explicitly selected address-book account', async () => {
		setDirectoryAccountId('73');
		await directorySearch('alice', 5);

		expect(getAccountId).not.toHaveBeenCalled();
		expect(jmapCall).toHaveBeenCalledWith([
			['ContactCard/directorySearch', { accountId: '73', query: 'alice', limit: 5 }, 's'],
		]);
	});

	it('fails before JMAP when no primary account is available', async () => {
		getAccountId.mockResolvedValue(null);

		await expect(directorySearch('bob')).rejects.toThrow('No primary JMAP account');
		expect(jmapCall).not.toHaveBeenCalled();
	});
});
