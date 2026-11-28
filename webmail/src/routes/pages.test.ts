import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad, mockTaskLoad, mockDeletedEmailLoad } from '$lib/test-utils';

import LoginPage from './+page.svelte';
import Layout from './+layout.svelte';
import InboxPage from './inbox/+page.svelte';
import SettingsPage from './settings/+page.svelte';
import QuarantinePage from './quarantine/+page.svelte';
import RecoverPage from './recover/+page.svelte';
import TasksPage from './tasks/+page.svelte';

import * as auth from '$lib/stores/auth';

describe('Login Page', () => {
	beforeEach(() => resetStores());

	it('renders email input', () => {
		render(LoginPage);
		expect(screen.getByLabelText('Email')).toBeTruthy();
	});

	it('shows Sign In heading', () => {
		render(LoginPage);
		expect(screen.getByRole('heading', { name: /sign in/i })).toBeTruthy();
	});
});

describe('App Layout', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});

	it('shows loading state when auth initializing', () => {
		auth.authInitializing.set(true);
		auth.authenticated.set(false);
		render(Layout);
		// New shell: loading is shown via role="status" with aria-label="loading"
		// (Spinner is async-imported so no text node; check the status role)
		expect(screen.getByRole('status')).toBeTruthy();
	});

	it('renders nav items when authenticated', async () => {
		const { container } = await renderAsUser(Layout);
		// New rail: icon-only buttons with aria-label (no visible text)
		expect(container.querySelector('[aria-label="Mail"]')).toBeTruthy();
		expect(container.querySelector('[aria-label="Calendar"]')).toBeTruthy();
		expect(container.querySelector('[aria-label="Settings"]')).toBeTruthy();
	});

	it('shows admin link when user is admin', async () => {
		const { container } = await renderAsUser(Layout, {}, { isAdmin: true });
		// New rail: admin console button with aria-label="Mail admin"
		expect(container.querySelector('[aria-label="Mail admin"]')).toBeTruthy();
	});

	it('hides admin link for non-admin users', async () => {
		const { container } = await renderAsUser(Layout);
		expect(container.querySelector('[aria-label="Mail admin"]')).toBeFalsy();
	});
});

describe('Inbox Page', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});

	it('mounts inbox page without crashing', async () => {
		const { container } = await renderAsUser(InboxPage);
		expect(container).toBeTruthy();
	});
});

describe('Settings Page', () => {
	beforeEach(() => {
		resetStores();
	});

	it('mounts settings page without crashing', async () => {
		const { container } = await renderAsUser(SettingsPage);
		expect(container).toBeTruthy();
	});
});

describe('Settings Page Error States', () => {
	beforeEach(() => {
		resetStores();
	});

	it('renders without crash even when passkey fetch fails', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();
			// Fail the passkey credentials endpoint
			if (url.includes('/auth/webauthn/credentials')) {
				return { ok: false, status: 500, json: async () => ({}), text: async () => '' };
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));

		const { container } = await renderAsUser(SettingsPage);
		expect(container.querySelector('.sj-settings-page')).toBeTruthy();
	});

	it('mounts with four card layout', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => {
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));

		const { container } = await renderAsUser(SettingsPage);
		// Verify all four card sections are present
		expect(container.textContent).toContain('Profile');
		expect(container.textContent).toContain('Appearance');
		expect(container.textContent).toContain('Mail');
		expect(container.textContent).toContain('Security');
	});
});

describe('Quarantine Page', () => {
	it('mounts without crashing', async () => {
		const { container } = await render(QuarantinePage);
		expect(container).toBeTruthy();
	});
});

describe('Recover Page', () => {
	beforeEach(() => {
		resetStores();
		mockDeletedEmailLoad();
	});

	it('mounts without crashing', async () => {
		const { container } = await renderAsUser(RecoverPage);
		expect(container).toBeTruthy();
	});

	it('surfaces an error instead of an unhandled rejection when the session fails to load', async () => {
		// onMount calls loadSession() → fetch('/.well-known/jmap'). Make it fail.
		// The page must catch it and show the error banner, not reject the async
		// onMount (an unguarded throw here floats an unhandled rejection that, under
		// the full suite, lands on a later test — see the loadSession guarding that
		// every other page already has).
		vi.stubGlobal(
			'fetch',
			vi.fn(async (input: RequestInfo | URL) => {
				const url = typeof input === 'string' ? input : input.toString();
				if (url.includes('/.well-known/jmap')) {
					return { ok: false, status: 500, json: async () => ({}), text: async () => '' };
				}
				return { ok: true, status: 200, json: async () => ({ methodResponses: [] }), text: async () => '' };
			}),
		);
		const { container } = await renderAsUser(RecoverPage);
		await waitFor(() => {
			// The exact message varies (loadSession now falls back to a cached
			// session on refresh failure, so the surfaced error may come from the
			// downstream load instead) — the contract is: an error banner renders,
			// nothing floats as an unhandled rejection.
			expect(container.querySelector('.alert')?.textContent?.trim()).toBeTruthy();
		});
	});
});

describe('Tasks Page', () => {
	beforeEach(() => {
		resetStores();
		mockTaskLoad();
	});

	it('mounts without crashing', async () => {
		const { container } = await renderAsUser(TasksPage);
		expect(container).toBeTruthy();
	});
});
