/**
 * page.test.ts — Task 16b: security-event logout screen (remote-wipe landing)
 *
 * Verifies:
 * 1. h1 + "safe on the server" reassurance + Sign-in recovery action present.
 * 2. No role=alert — this is an expected, calm flow, not a fault.
 * 3. Body <p> is a polite live region (role=status, aria-live=polite) so screen
 *    readers announce the reassurance without assertive interruption.
 * 4. Generic fallback copy renders for absent/unknown reason.
 * 5. All security_event.* keys exist in zh/de (locale-completeness guard).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { page } from '$app/state';
import Page from './+page.svelte';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';

// Tap into the vitest.setup.ts mock — it exposes a mutable object.
const mockPage = page as { url: { pathname: string; searchParams: URLSearchParams; hash: string } };

const SECURITY_KEYS = [
	'security_event.remote_wipe.title',
	'security_event.remote_wipe.body',
	'security_event.generic.title',
	'security_event.generic.body',
	'security_event.sign_in',
];

describe('security-event screen', () => {
	beforeEach(() => {
		mockPage.url.searchParams = new URLSearchParams('reason=remote-wipe');
	});
	afterEach(() => {
		mockPage.url.searchParams = new URLSearchParams();
	});

	it('explains the remote-wipe security event and reassures (not a blank login)', () => {
		const { getByRole, getByText } = render(Page);
		expect(getByRole('heading', { level: 1 })).toBeTruthy();
		expect(getByText(/safe on the server/i)).toBeTruthy(); // reassurance
		expect(getByRole('button', { name: /sign in again/i })).toBeTruthy(); // recovery path
	});

	it('does NOT use an alarming error role (expected flow, not a fault)', () => {
		const { queryByRole } = render(Page);
		expect(queryByRole('alert')).toBeNull();
	});

	it('announces the reassurance via a polite live region (not assertive)', () => {
		const { getByText } = render(Page);
		const body = getByText(/safe on the server/i);
		expect(body.getAttribute('role')).toBe('status');
		expect(body.getAttribute('aria-live')).toBe('polite');
	});
});

describe('security-event screen — fallback for unknown/absent reason', () => {
	// searchParams default is empty (no reason param) from vitest.setup.ts mock.
	it('falls back to generic copy — h1 + recovery button always present', () => {
		const { getByRole, getByText } = render(Page);
		expect(getByRole('heading', { level: 1 })).toBeTruthy();
		// Generic body also reassures "safe on the server" (same trust arc).
		expect(getByText(/safe on the server/i)).toBeTruthy();
		expect(getByRole('button', { name: /sign in again/i })).toBeTruthy();
	});
});

describe('security-event i18n locale completeness', () => {
	it('every security_event.* key in en.ts exists in zh.ts and de.ts', () => {
		for (const k of SECURITY_KEYS) {
			expect(en[k], `en missing ${k}`).toBeTruthy();
			expect(zh[k], `zh missing ${k}`).toBeTruthy();
			expect(de[k], `de missing ${k}`).toBeTruthy();
		}
	});
});
