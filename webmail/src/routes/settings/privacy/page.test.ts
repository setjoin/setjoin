import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import PrivacyPage from './+page.svelte';
import { clearToasts } from '$lib/components/ui';
import { imageTrust } from '$lib/stores/imageTrust.svelte';
import { jmapSession } from '$lib/stores/session';

function jsonResponse(body: unknown, ok = true) {
	return {
		ok,
		status: ok ? 200 : 500,
		json: async () => body,
		text: async () => JSON.stringify(body),
	};
}

function stubPrivacyFetch(userEnabled: boolean, putOK = true) {
	const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = input instanceof Request ? input.url : String(input);
		const method = init?.method ?? (input instanceof Request ? input.method : 'GET');

		if (url.includes('/api/user/notification-preferences')) {
			return jsonResponse({ preferences: [] });
		}
		if (url.includes('/api/settings/external-sender') && method === 'PUT') {
			return jsonResponse(putOK ? { status: 'ok' } : { error: 'save failed' }, putOK);
		}
		if (url.includes('/api/settings/external-sender')) {
			return jsonResponse({ userEnabled, globalEnabled: true });
		}
		if (url.includes('/.well-known/jmap')) {
			return jsonResponse({
				effectiveCapabilities: {
					apps: {},
					features: { assist: false, bundles: false, external_labels: false },
				},
			});
		}
		throw new Error(`Unstubbed fetch: ${method} ${url}`);
	});
	vi.stubGlobal('fetch', fetchMock);
	return fetchMock;
}

beforeEach(() => {
	imageTrust.loaded = true;
	imageTrust.senders = [];
	jmapSession.set(null);
});

afterEach(() => {
	vi.unstubAllGlobals();
	jmapSession.set(null);
});

describe('Privacy external identity labels', () => {
	it('loads the existing per-user preference defaulted on', async () => {
		stubPrivacyFetch(true);
		render(PrivacyPage);

		const toggle = await screen.findByRole('switch', {
			name: 'Show External labels and warnings',
		});
		expect(toggle).toBeChecked();
		expect(toggle).toBeEnabled();
	});

	it('saves a toggle change and refreshes the effective session capability', async () => {
		const fetchMock = stubPrivacyFetch(true);
		render(PrivacyPage);

		const toggle = await screen.findByRole('switch', {
			name: 'Show External labels and warnings',
		});
		await fireEvent.click(toggle);

		await waitFor(() => {
			const put = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT');
			expect(put).toBeTruthy();
			expect(JSON.parse(String(put?.[1]?.body))).toEqual({ enabled: false });
		});
		expect(toggle).not.toBeChecked();
	});

	it('rolls back the switch when saving fails', async () => {
		stubPrivacyFetch(true, false);
		render(PrivacyPage);

		const toggle = await screen.findByRole('switch', {
			name: 'Show External labels and warnings',
		});
		await fireEvent.click(toggle);

		await waitFor(() => expect(toggle).toBeChecked());
		expect(screen.getByRole('alert')).toHaveTextContent(
			'Could not save your External label preference.',
		);
	});
});

// ── WP5: both settings loads/saves run through the composable + $lib/http seam ──

describe('Privacy load failures through the seam (WP5)', () => {
	beforeEach(() => {
		imageTrust.loaded = true;
		imageTrust.senders = [];
		jmapSession.set(null);
	});

	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
		jmapSession.set(null);
	});

	function failingPrivacyFetch(): void {
		vi.stubGlobal(
			'fetch',
			vi.fn(async (input: RequestInfo | URL) => {
				const url = input instanceof Request ? input.url : String(input);
				// The authedBootstrap probe succeeds (any JSON body proves a fresh
				// session document); the two protected reads fail.
				if (url.includes('/.well-known/jmap')) {
					return jsonResponse({ capabilities: {} });
				}
				if (url.includes('/api/user/notification-preferences')) {
					return jsonResponse({}, false); // 500
				}
				if (url.includes('/api/settings/external-sender')) {
					return jsonResponse({}, false); // 500
				}
				throw new Error(`Unstubbed fetch: ${url}`);
			})
		);
	}

	it('surfaces the notification-preferences typed failure display-safely', async () => {
		failingPrivacyFetch();
		render(PrivacyPage);
		// The seam's display-safe message, not a raw server body.
		await screen.findByText('Request failed (500)');
	});

	it('surfaces the authored External-label load failure', async () => {
		failingPrivacyFetch();
		render(PrivacyPage);
		await screen.findByText('Could not load your External label preference. Refresh to try again.');
	});
});

// ── WP5 follow-up: the read-receipt policy save (savePolicy) through the seam ──

describe('Privacy read-receipt policy save (WP5)', () => {
	const globalPrefsRow = {
		push_enabled: false,
		push_sound: 'custom',
		stop_push_when_desktop_online: true,
		dnd_start: '22:00',
		dnd_end: '07:00',
		dnd_days: 31,
		mail_notifications: 'mentions',
		calendar_reminders: false,
		task_reminders: false,
		read_receipt_policy: 'ask',
	};

	interface CapturedCall {
		method: string;
		url: string;
		body: unknown;
	}

	/**
	 * Stub the two GETs the page fires on mount plus the notification-preferences
	 * PUT that savePolicy issues. `withGlobalRow: false` loads with no global row
	 * so savePolicy falls back to its authored defaults object.
	 */
	function stubPolicyFetch(
		put: { status: number; body: unknown },
		withGlobalRow = true,
	): CapturedCall[] {
		const calls: CapturedCall[] = [];
		vi.stubGlobal(
			'fetch',
			vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = input instanceof Request ? input.url : String(input);
				const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
				calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : null });
				if (url.includes('/api/user/notification-preferences')) {
					if (method === 'PUT') {
						return jsonResponse(put.body, put.status >= 200 && put.status < 300);
					}
					return jsonResponse({ preferences: withGlobalRow ? [globalPrefsRow] : [] });
				}
				if (url.includes('/api/settings/external-sender')) {
					return jsonResponse({ userEnabled: true, globalEnabled: true });
				}
				// The authedBootstrap probe (WP5 completion).
				if (url.includes('/.well-known/jmap')) {
					return jsonResponse({ capabilities: {} });
				}
				throw new Error(`Unstubbed fetch: ${method} ${url}`);
			})
		);
		return calls;
	}

	async function changePolicy(value: string): Promise<HTMLSelectElement> {
		const select = (await screen.findByLabelText('Read receipts')) as HTMLSelectElement;
		await fireEvent.change(select, { target: { value } });
		return select;
	}

	function putCall(calls: CapturedCall[]): CapturedCall {
		const put = calls.find((call) => call.method === 'PUT');
		expect(put).toBeTruthy();
		return put as CapturedCall;
	}

	beforeEach(() => {
		// The toast store is module-global with a 6s real-time dismissal timer;
		// drops from earlier tests in this file would otherwise match our queries.
		clearToasts();
		imageTrust.loaded = true;
		imageTrust.senders = [];
		jmapSession.set(null);
	});

	afterEach(() => {
		cleanup();
		clearToasts();
		vi.unstubAllGlobals();
		jmapSession.set(null);
	});

	it('saves the policy with the existing global prefs sent back unchanged', async () => {
		const calls = stubPolicyFetch({ status: 200, body: { status: 'ok' } });
		render(PrivacyPage);

		const select = await changePolicy('always');

		await waitFor(() => expect(calls.some((call) => call.method === 'PUT')).toBe(true));
		expect(putCall(calls).url).toContain('/api/user/notification-preferences');
		expect(putCall(calls).body).toEqual({
			preferences: {
				push_enabled: false,
				push_sound: 'custom',
				stop_push_when_desktop_online: true,
				dnd_start: '22:00',
				dnd_end: '07:00',
				dnd_days: 31,
				mail_notifications: 'mentions',
				calendar_reminders: false,
				task_reminders: false,
				read_receipt_policy: 'always',
			},
		});
		expect(select).toHaveValue('always');
		await screen.findByText('Saved');
	});

	it('rolls back the policy and surfaces the authored error when the save fails', async () => {
		const calls = stubPolicyFetch({ status: 500, body: { error: 'quota exceeded' } });
		render(PrivacyPage);

		const select = await changePolicy('never');

		await screen.findByText('quota exceeded');
		expect(select).toHaveValue('ask');
		expect(screen.queryByText('Saved')).toBeNull();
	});

	it('uses the display-safe fallback message when the failure body has no authored error', async () => {
		const calls = stubPolicyFetch({ status: 500, body: {} }, false);
		render(PrivacyPage);

		const select = await changePolicy('always');

		await screen.findByText('Could not save your privacy preference. Try again.');
		expect(select).toHaveValue('ask');
		expect(putCall(calls).body).toMatchObject({
			preferences: expect.objectContaining({ read_receipt_policy: 'always' }),
		});
	});
});
