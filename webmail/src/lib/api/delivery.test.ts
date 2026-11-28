import { describe, it, expect, vi } from 'vitest';
import { messageTrace } from './delivery';

describe('messageTrace', () => {
	it('GETs the trace endpoint and returns parsed JSON', async () => {
		const trace = { direction: 'inbound', hopCount: 1, hops: [{ index: 0, parseOk: true }] };
		const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => trace });
		vi.stubGlobal('fetch', fetchMock);
		const out = await messageTrace('42');
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/messages/42/trace',
			expect.objectContaining({ method: 'GET' })
		);
		expect(out.hops![0].index).toBe(0);
	});

	it('percent-encodes the id into the request path (path-shaping boundary)', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ direction: 'inbound', hopCount: 0, hops: [] })
		});
		vi.stubGlobal('fetch', fetchMock);
		await messageTrace('a/b?c');
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/messages/a%2Fb%3Fc/trace',
			expect.objectContaining({ method: 'GET' })
		);
	});
});
