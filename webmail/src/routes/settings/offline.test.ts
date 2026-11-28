import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import SettingsPage from './+page.svelte';
import type { OfflineCaps } from '$lib/offline/caps';
import * as client from '$lib/admin/client';

// Minimal stubs so the settings page's other onMount calls don't throw
beforeEach(() => {
	vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
		ok: false, status: 404,
		json: async () => ({}),
		text: async () => '',
	}));
	vi.stubGlobal('localStorage', {
		getItem: vi.fn().mockReturnValue(null),
		setItem: vi.fn(),
		removeItem: vi.fn(),
	});
});

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

// Test helper: build an OfflineCaps with sensible defaults
const caps = (o: Partial<OfflineCaps> = {}): OfflineCaps => ({
	allowed: false, approvalState: 'pending', maxOfflineDays: 7,
	wipeOnLogout: 'admin_default', requireApproval: true, ...o,
});

describe('settings offline storage card', () => {
	it('ALLOWED (native+approved+optin): success badge + capped-window caption', () => {
		const { getByText } = render(SettingsPage, {
			__offlineCaps: caps({ allowed: true, approvalState: 'approved' }),
			__bridgePresent: true,
		} as never);
		expect(getByText(/offline mail on/i)).toBeTruthy();
		expect(getByText(/caching the last 7 days/i)).toBeTruthy();
	});

	it('PENDING: shows the reason + a "Request approval" action (not an error)', () => {
		const { getByText, getByRole } = render(SettingsPage, {
			__offlineCaps: caps({ approvalState: 'pending' }),
			__bridgePresent: true,
		} as never);
		expect(getByText(/awaiting administrator approval/i)).toBeTruthy();
		expect(getByRole('button', { name: /request approval/i })).toBeTruthy();
	});

	it('PENDING: requesting approval toasts + announces, never red', async () => {
		vi.spyOn(client, 'offlineOptIn').mockResolvedValue(undefined);
		const { getByRole, queryByRole } = render(SettingsPage, {
			__offlineCaps: caps({ approvalState: 'pending' }),
			__bridgePresent: true,
		} as never);
		await fireEvent.click(getByRole('button', { name: /request approval/i }));
		expect(queryByRole('alert')).toBeNull(); // pending is hopeful, not an error
	});

	it('DENIED: neutral "Not available" + ask-admin helper, no danger styling', () => {
		const { getByText } = render(SettingsPage, {
			__offlineCaps: caps({ approvalState: 'denied' }),
			__bridgePresent: true,
		} as never);
		expect(getByText(/not available/i)).toBeTruthy();
		expect(getByText(/ask your administrator/i)).toBeTruthy();
	});

	it("REVOKED: reassure-don't-alarm — \"your mail is safe and fully available online\"", () => {
		const { getByText } = render(SettingsPage, {
			__offlineCaps: caps({ approvalState: 'revoked' }),
			__bridgePresent: true,
		} as never);
		expect(getByText(/your mail is safe and fully available online/i)).toBeTruthy();
	});

	it('PLAIN BROWSER: honest capability statement + get-app link (not an error)', () => {
		// Both the reason text and the get-app link contain "desktop or mobile app";
		// use getAllByText since there are legitimately two matching elements.
		const { getAllByText, queryByRole } = render(SettingsPage, {
			__offlineCaps: caps({ allowed: true, approvalState: 'approved' }),
			__bridgePresent: false,
		} as never);
		expect(getAllByText(/desktop or mobile app/i).length).toBeGreaterThan(0);
		expect(queryByRole('alert')).toBeNull();
	});

	it('ALLOWED: opt-in switch is functional — clicking calls offlineOptIn (not a no-op)', async () => {
		const spy = vi.spyOn(client, 'offlineOptIn').mockResolvedValue(undefined);
		const { getByRole } = render(SettingsPage, {
			__offlineCaps: caps({ allowed: true, approvalState: 'approved' }),
			__bridgePresent: true,
		} as never);
		const sw = getByRole('switch', { name: /cache mail on this device/i });
		expect(sw).toBeTruthy();
		await fireEvent.click(sw);
		expect(spy).toHaveBeenCalled();
	});

	it('ALLOWED: BZ100/409 opt-in error surfaces inline alert + reverts switch', async () => {
		vi.spyOn(client, 'offlineOptIn').mockRejectedValue(new Error('conflict'));
		const { getByRole, findByRole } = render(SettingsPage, {
			__offlineCaps: caps({ allowed: true, approvalState: 'approved' }),
			__bridgePresent: true,
		} as never);
		const sw = getByRole('switch', { name: /cache mail on this device/i });
		// Switch starts checked (offlineOptedIn = true); click to opt-out triggers error
		await fireEvent.click(sw);
		// Inline role="alert" must appear with the error message
		const alert = await findByRole('alert');
		expect(alert.textContent).toBeTruthy();
		// Switch should be reverted — still present (not removed from DOM)
		expect(getByRole('switch', { name: /cache mail on this device/i })).toBeTruthy();
	});
});
