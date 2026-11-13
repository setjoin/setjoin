/**
 * COV-2 — /admin/system/welcome-email route wrapper.
 *
 * This route is a thin alias that mounts the shared `(system)/welcome-email`
 * editor page (whose behaviour is covered by that page's own suite, plus
 * `welcomeForm.svelte.test.ts`). Rendering the alias with the same client and
 * navigation mocks proves the alias resolves and forwards to the live editor.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), send: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	adminGetWelcomeEmail: api.get,
	adminPutWelcomeEmail: api.put,
	adminTestSendWelcomeEmail: api.send
}));
vi.mock('$app/navigation', () => ({ goto: vi.fn(), invalidateAll: vi.fn(), beforeNavigate: vi.fn() }));

import AliasPage from './+page.svelte';

const config = {
	enabled: true,
	default_locale: 'en',
	locales: {
		en: { subject: 'Welcome {{DisplayName}}', body_text: 'Open {{WebmailURL}}', body_html: '<p>Welcome</p>' },
		zh: { subject: '', body_text: '', body_html: '' },
		de: { subject: 'Willkommen', body_text: 'Hallo', body_html: '' }
	}
};

function grantSystemConsole() {
	jmapSession.set({
		accounts: {},
		primaryAccounts: {},
		branding: { name: 'Setjoin Test' },
		capabilities: {
			'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['system.config'] } }
		}
	} as never);
}

describe('admin system welcome-email alias page', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.get.mockResolvedValue(structuredClone(config));
		api.put.mockResolvedValue(undefined);
		api.send.mockResolvedValue(undefined);
	});
	afterEach(() => resetStores());

	it('mounts the shared welcome-email editor', async () => {
		await renderAsUser(AliasPage, {}, { userId: 1, email: 'admin@example.test', isAdmin: true });
		grantSystemConsole();

		await waitFor(() => expect(api.get).toHaveBeenCalledWith());
		expect(await screen.findByLabelText('Subject')).toBeInTheDocument();
	});
});
