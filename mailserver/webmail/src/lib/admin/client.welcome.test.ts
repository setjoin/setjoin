import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { adminGetWelcomeEmail, adminPutWelcomeEmail, adminTestSendWelcomeEmail } from './client';

// Matches the established admin-client test seam (see client.timeline.test.ts):
// adminFetch routes through $lib/http → global fetch, so we stub global fetch.
function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' }
	});
}

describe('welcome-email admin client', () => {
	let mockFetch: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		mockFetch = vi.fn();
		vi.stubGlobal('fetch', mockFetch);
		vi.stubGlobal('window', { location: { href: '' } });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('GET hits /admin/system/welcome-email and parses the config', async () => {
		mockFetch.mockResolvedValue(jsonResponse({ enabled: true, default_locale: 'en', locales: {} }));
		const cfg = await adminGetWelcomeEmail();
		expect(cfg.default_locale).toBe('en');
		expect(cfg.enabled).toBe(true);
		expect(mockFetch.mock.calls[0][0]).toContain('/admin/system/welcome-email');
		// GET is the default — no explicit method.
		expect((mockFetch.mock.calls[0][1] as RequestInit).method).toBeUndefined();
	});

	it('PUT sends the config as JSON', async () => {
		mockFetch.mockResolvedValue(new Response(null, { status: 204 }));
		await adminPutWelcomeEmail({ enabled: false, default_locale: 'en', locales: {} });
		const [url, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(url).toContain('/admin/system/welcome-email');
		expect(opts.method).toBe('PUT');
		expect(String(opts.body)).toContain('"enabled":false');
	});

	it('test-send POSTs to .../test with the request body', async () => {
		mockFetch.mockResolvedValue(new Response(null, { status: 202 }));
		await adminTestSendWelcomeEmail({ locale: 'en', subject: 's', body_text: 'b', body_html: '' });
		const [url, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(url).toContain('/admin/system/welcome-email/test');
		expect(opts.method).toBe('POST');
		expect(String(opts.body)).toContain('"locale":"en"');
		expect(String(opts.body)).toContain('"subject":"s"');
	});
});
