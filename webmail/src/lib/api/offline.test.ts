import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getOfflineSizeEstimate, getOfflineWindow, saveOfflineWindow } from './offline';

function mockFetchOnce(body: unknown, ok = true) {
	(globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
		ok,
		status: ok ? 200 : 500,
		json: async () => body,
		text: async () => JSON.stringify(body),
		headers: new Headers({ 'content-type': 'application/json' })
	});
}

describe('offline api', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
	});

	it('parses the size estimate', async () => {
		mockFetchOnce({ buckets: [{ window: '30d', messageCount: 5, bodyBytes: 1234 }] });
		const est = await getOfflineSizeEstimate();
		expect(est.buckets[0].bodyBytes).toBe(1234);
	});

	it('reads the offline window from view prefs, defaulting to 30d', async () => {
		mockFetchOnce({ defaultView: 'conversation' }); // no offlineWindow
		expect(await getOfflineWindow()).toBe('30d');
		expect(globalThis.fetch).toHaveBeenLastCalledWith('/api/settings/view', expect.any(Object));
		mockFetchOnce({ offlineWindow: '90d' });
		expect(await getOfflineWindow()).toBe('90d');
		expect(globalThis.fetch).toHaveBeenLastCalledWith('/api/settings/view', expect.any(Object));
	});

	it('defaults to 30d when offlineWindow is an invalid string', async () => {
		mockFetchOnce({ offlineWindow: 'bad_value' });
		expect(await getOfflineWindow()).toBe('30d');
	});

	it('saves the window by merging into existing view prefs', async () => {
		mockFetchOnce({ defaultView: 'flat', smartMute: true }); // GET (read)
		mockFetchOnce({ status: 'ok' }); // PUT (merge)
		await saveOfflineWindow('180d');
		expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe('/api/settings/view');
		const putCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[1];
		expect(putCall[0]).toBe('/api/settings/view');
		expect(putCall[1].method).toBe('PUT');
		const sent = JSON.parse(putCall[1].body as string);
		expect(sent.offlineWindow).toBe('180d');
		expect(sent.defaultView).toBe('flat'); // existing prefs preserved
		expect(sent.smartMute).toBe(true);
	});
});
