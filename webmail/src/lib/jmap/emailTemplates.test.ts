import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the client seam so we assert the method shaping + response parsing in
// isolation (mirrors the savedsearches / quicksteps client wrappers).
const jmapCall = vi.fn();
vi.mock('./client', () => ({
	jmapCall: (...args: unknown[]) => jmapCall(...args),
	getAccountId: vi.fn(async () => 'a1'),
}));

import { emailTemplateList, emailTemplateSet, emailTemplateDelete } from './emailTemplates';

function resp(payload: Record<string, unknown>) {
	return { methodResponses: [['EmailTemplate/x', payload, '0']] };
}

describe('emailTemplates client', () => {
	beforeEach(() => jmapCall.mockReset());

	it('emailTemplateList calls EmailTemplate/list and normalizes ids to strings', async () => {
		jmapCall.mockResolvedValue(
			resp({ list: [{ id: 7, name: 'Follow-up', subject: 'Hi', bodyHtml: '<p>x</p>' }] })
		);
		const out = await emailTemplateList();
		expect(jmapCall).toHaveBeenCalledWith([['EmailTemplate/list', { accountId: 'a1' }, '0']]);
		expect(out).toEqual([{ id: '7', name: 'Follow-up', subject: 'Hi', bodyHtml: '<p>x</p>' }]);
	});

	it('emailTemplateList returns [] when list is absent', async () => {
		jmapCall.mockResolvedValue(resp({}));
		expect(await emailTemplateList()).toEqual([]);
	});

	it('emailTemplateSet calls EmailTemplate/set with name/subject/bodyHtml and returns the row', async () => {
		jmapCall.mockResolvedValue(
			resp({ created: { id: 9, name: 'Ping', subject: 'S', bodyHtml: '<b>b</b>' } })
		);
		const row = await emailTemplateSet('Ping', 'S', '<b>b</b>');
		expect(jmapCall).toHaveBeenCalledWith([
			['EmailTemplate/set', { accountId: 'a1', name: 'Ping', subject: 'S', bodyHtml: '<b>b</b>' }, '0'],
		]);
		expect(row).toEqual({ id: '9', name: 'Ping', subject: 'S', bodyHtml: '<b>b</b>' });
	});

	it('emailTemplateDelete calls EmailTemplate/delete with the stringified id', async () => {
		jmapCall.mockResolvedValue(resp({ result: { deleted: true, id: '3' } }));
		await emailTemplateDelete('3');
		expect(jmapCall).toHaveBeenCalledWith([['EmailTemplate/delete', { accountId: 'a1', id: '3' }, '0']]);
	});

	it('throws when the gateway returns a method-level error envelope', async () => {
		jmapCall.mockResolvedValue(resp({ type: 'invalidArguments', description: 'name required' }));
		await expect(emailTemplateSet('', '', '')).rejects.toThrow('name required');
	});
});
