import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { adminTraceTimeline } from './client';

describe('adminTraceTimeline', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
		vi.stubGlobal('window', { location: { href: '' } });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('GETs /admin/trace/<url-encoded messageId> and returns parsed TraceTimeline', async () => {
		const payload = {
			messageId: 'msg+test@example.com',
			events: [
				{
					event: 'received',
					rcptAddr: 'bob@example.com',
					fromAddr: 'alice@example.com',
					remoteHost: '10.0.0.1',
					details: null,
					occurredAt: '2026-06-21T12:00:00Z'
				}
			],
			queue: {
				status: 'queued',
				attemptCount: 1,
				nextAttemptAt: '2026-06-21T12:05:00Z',
				lastError: null,
				rcptAddrs: ['bob@example.com'],
				queuedAt: '2026-06-21T12:00:00Z'
			},
			multiRecipient: false
		};

		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => payload
		});
		vi.stubGlobal('fetch', mockFetch);

		const result = await adminTraceTimeline('msg+test@example.com');

		// Verify correct URL with URL encoding
		const calledUrl = mockFetch.mock.calls[0][0] as string;
		expect(calledUrl).toBe('/api/admin/trace/msg%2Btest%40example.com');

		// Verify method is GET (default, not POST/PUT/DELETE)
		const calledOpts = mockFetch.mock.calls[0][1] as RequestInit;
		expect(calledOpts.method).toBeUndefined(); // GET is the default (no explicit method)

		// Verify parsed response shape
		expect(result.messageId).toBe('msg+test@example.com');
		expect(result.events).toHaveLength(1);
		expect(result.events[0].event).toBe('received');
		expect(result.events[0].rcptAddr).toBe('bob@example.com');
		expect(result.queue).not.toBeNull();
		expect(result.queue!.status).toBe('queued');
		expect(result.queue!.attemptCount).toBe(1);
		expect(result.multiRecipient).toBe(false);
	});

	it('returns null queue when no outbound queue row exists', async () => {
		const payload = {
			messageId: 'inbound@example.com',
			events: [],
			queue: null,
			multiRecipient: false
		};

		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => payload
		});
		vi.stubGlobal('fetch', mockFetch);

		const result = await adminTraceTimeline('inbound@example.com');
		expect(result.queue).toBeNull();
		expect(result.events).toHaveLength(0);
	});

	it('encodes special characters in messageId', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ messageId: 'a/b@c.com', events: [], queue: null, multiRecipient: false })
		});
		vi.stubGlobal('fetch', mockFetch);

		await adminTraceTimeline('a/b@c.com');
		const calledUrl = mockFetch.mock.calls[0][0] as string;
		expect(calledUrl).toBe('/api/admin/trace/a%2Fb%40c.com');
	});
});
