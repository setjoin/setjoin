import { describe, it, expect, beforeEach, vi } from 'vitest';
import { asRich, assistComplete, type AssistMessage } from './assist';
import en from '$lib/i18n/en';

describe('asRich', () => {
	it('wraps **bold** in <strong>', () => {
		expect(asRich('hello **world** today')).toBe('hello <strong>world</strong> today');
	});

	it('wraps `code` in inline code chip', () => {
		expect(asRich('use `someFunction()` now')).toBe(
			'use <code class="sj-code-chip">someFunction()</code> now',
		);
	});

	it('handles mixed bold and code', () => {
		expect(asRich('**bold** and `code` mixed')).toBe(
			'<strong>bold</strong> and <code class="sj-code-chip">code</code> mixed',
		);
	});

	it('handles multiple bold segments', () => {
		expect(asRich('**one** and **two**')).toBe(
			'<strong>one</strong> and <strong>two</strong>',
		);
	});

	it('handles multiple code segments', () => {
		expect(asRich('run `a` then `b`')).toBe(
			'run <code class="sj-code-chip">a</code> then <code class="sj-code-chip">b</code>',
		);
	});

	it('returns plain text unchanged when no markup', () => {
		expect(asRich('plain text with no markup')).toBe('plain text with no markup');
	});

	it('handles empty string', () => {
		expect(asRich('')).toBe('');
	});

	it('does not render markdown headings', () => {
		expect(asRich('## Heading')).toBe('## Heading');
	});

	it('does not render markdown lists', () => {
		expect(asRich('- bullet point')).toBe('- bullet point');
	});

	it('does not render markdown links', () => {
		expect(asRich('[link](https://example.com)')).toBe('[link](https://example.com)');
	});

	it('handles text with asterisks but not bold (single *)', () => {
		expect(asRich('a * b * c')).toBe('a * b * c');
	});

	it('handles bold at start of string', () => {
		expect(asRich('**hello** world')).toBe('<strong>hello</strong> world');
	});

	it('handles code at start of string', () => {
		expect(asRich('`cmd` output')).toBe('<code class="sj-code-chip">cmd</code> output');
	});

	it('entity-escapes raw markup in plain text (builder-level encoding boundary)', () => {
		expect(asRich('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
	});

	it('entity-escapes raw markup inside bold and code markers', () => {
		expect(asRich('**<b>** and `<i>`')).toBe(
			'<strong>&lt;b&gt;</strong> and <code class="sj-code-chip">&lt;i&gt;</code>',
		);
	});

	it('passes already-escaped input through unchanged (no double-escaping)', () => {
		expect(asRich('&lt;script&gt;alert(1)&lt;/script&gt;')).toBe(
			'&lt;script&gt;alert(1)&lt;/script&gt;',
		);
		expect(asRich('**a &amp; b**')).toBe('<strong>a &amp; b</strong>');
	});
});

describe('assistComplete', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	function mockFetch(status: number, body: unknown): void {
		vi.stubGlobal('fetch', async () => ({
			ok: status >= 200 && status < 300,
			status,
			json: async () => body,
			text: async () => JSON.stringify(body),
		}));
	}

	it('returns content on 200', async () => {
		mockFetch(200, { content: 'Hello from Assist' });
		const result = await assistComplete({ messages: [{ role: 'user', content: 'hi' }] });
		expect(result.content).toBe('Hello from Assist');
	});

	it('throws assist-specific calm copy on 403 (not generic adminFetch message)', async () => {
		mockFetch(403, { detail: 'Feature assist is disabled for your account.' });
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist is not available for your account.');
	});

	it('throws calm user copy on 403 without problem detail', async () => {
		mockFetch(403, {});
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist is not available for your account.');
	});

	it('throws calm user copy on 502 with problem detail', async () => {
		mockFetch(502, { title: 'Service Unavailable', detail: 'The assist backend is down.' });
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist backend is not reachable. Try again soon.');
	});

	it('throws calm user copy on 502 without problem detail', async () => {
		mockFetch(502, {});
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist backend is not reachable. Try again soon.');
	});

	it('throws calm user copy on 503 with problem detail', async () => {
		mockFetch(503, { title: 'Service Unavailable', detail: 'Overloaded' });
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist is temporarily unavailable.');
	});

	it('throws calm user copy on 503 without problem detail', async () => {
		mockFetch(503, {});
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist is temporarily unavailable.');
	});

	it('throws problem detail on 422', async () => {
		mockFetch(422, { detail: 'Locale zh-TW is not supported.' });
		await expect(
			assistComplete({
				messages: [{ role: 'user', content: 'hi' }],
				locale: 'zh-TW',
			}),
		).rejects.toThrow('Locale zh-TW is not supported.');
	});

	it('throws fallback on 422 without detail', async () => {
		mockFetch(422, {});
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist request could not be processed.');
	});

	it('throws fallback on other non-ok status', async () => {
		mockFetch(500, {});
		await expect(
			assistComplete({ messages: [{ role: 'user', content: 'hi' }] }),
		).rejects.toThrow('Assist request failed. Try again.');
	});

	it('sends correct POST body with credentials', async () => {
		let actualUrl = '';
		let actualInit: RequestInit = {};
		vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
			actualUrl = url;
			actualInit = init;
			return {
				ok: true,
				json: async () => ({ content: 'ok' }),
			} as Response;
		});
		await assistComplete({
			messages: [
				{ role: 'user', content: 'test' },
				{ role: 'assistant', content: 'ok' },
			],
			context: 'admin/assist',
		});
		expect(actualUrl).toBe('/api/assist/complete');
		expect(actualInit.method).toBe('POST');
		expect(actualInit.credentials).toBe('include');
		const body = JSON.parse((actualInit.body as string) || '{}');
		expect(body.messages).toHaveLength(2);
		expect(body.context).toBe('admin/assist');
	});
});

describe('AssistDrawer i18n keys', () => {
	const requiredKeys = [
		'common.ask',
		'admin.assist.title',
		'admin.assist.intro',
		'admin.assist.placeholder',
		'admin.assist.q_alerts',
		'admin.assist.q_queue',
		'admin.assist.q_threats',
		'admin.assist.error_generic',
	];

	for (const key of requiredKeys) {
		it(`has i18n key "${key}" in en bundle`, () => {
			expect(en[key]).toBeDefined();
			expect(typeof en[key]).toBe('string');
		});
	}
});
