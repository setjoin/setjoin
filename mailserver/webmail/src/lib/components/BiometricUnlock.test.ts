import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import { readFileSync } from 'node:fs';

// --- Mocks ---
vi.mock('$lib/offline/store', () => ({
	isOfflineAvailable: vi.fn().mockReturnValue(true),
	getStore: vi.fn().mockReturnValue(null),
	MAIL_APP_KEY: 'mail',
}));
vi.mock('$lib/offline/sync', () => ({ requestSync: vi.fn() }));
vi.mock('$lib/offline/reconcile', () => ({
	listSyncIssues: vi.fn().mockResolvedValue([]),
	resolveId: vi.fn(),
}));
vi.mock('$lib/offline/leader', () => ({ withSyncOwnership: vi.fn() }));
vi.mock('$lib/jmap/client', () => ({ emailQuery: vi.fn(), emailGet: vi.fn() }));
vi.mock('$lib/db/offline', () => ({ getPendingActions: vi.fn().mockResolvedValue([]) }));

// Mock biometric module — tests control what it resolves to.
vi.mock('$lib/offline/biometric', () => ({
	isBiometricEnrolled: vi.fn().mockResolvedValue(true),
	unlockMail: vi.fn().mockResolvedValue('ok'),
	unlockWithPassphrase: vi.fn().mockResolvedValue('ok'),
	lockMail: vi.fn(),
	installIdleRelock: vi.fn().mockReturnValue(() => {}),
}));

import BiometricUnlock from './BiometricUnlock.svelte';
import { offline } from '$lib/offline/state.svelte';
import * as bio from '$lib/offline/biometric';

beforeEach(() => {
	vi.restoreAllMocks();
	// re-apply the module-level mocks after restoreAllMocks clears spies
	vi.mocked(bio.isBiometricEnrolled).mockResolvedValue(true);
	vi.mocked(bio.unlockMail).mockResolvedValue('ok');
	vi.mocked(bio.unlockWithPassphrase).mockResolvedValue('ok');
	// Reset offline state
	offline.featureEnabled = true;
	offline.capsAllowed = true;
	offline.workOffline = true;
	offline.setLockState('locked');
	offline.enrolled = true;
	offline.liveMessage = '';
});

// Helper: activate + set a specific lock state, then render
function renderWith(lockState: 'locked' | 'unlocking' | 'failed' | 'cancelled', opts: { enrolled?: boolean } = {}) {
	if (opts.enrolled !== undefined) offline.enrolled = opts.enrolled;
	offline.setLockState(lockState);
	return render(BiometricUnlock);
}

describe('BiometricUnlock — overlay presence', () => {
	it('renders the locked-inbox overlay as role=dialog aria-modal=true', () => {
		const { getByRole } = renderWith('locked');
		const dialog = getByRole('dialog');
		expect(dialog).toBeTruthy();
		expect(dialog.getAttribute('aria-modal')).toBe('true');
	});

	it('labels the dialog via aria-labelledby pointing to the headline', () => {
		const { getByRole } = renderWith('locked');
		const dialog = getByRole('dialog');
		const labelId = dialog.getAttribute('aria-labelledby');
		expect(labelId).toBeTruthy();
		const headline = document.getElementById(labelId!);
		expect(headline).toBeTruthy();
	});

	it('shows the primary Unlock button as initial focus target', () => {
		const { getByTestId } = renderWith('locked');
		expect(getByTestId('bio-unlock-btn')).toBeTruthy();
	});

	it('shows the locked-inbox headline + hint copy', () => {
		const { getByTestId } = renderWith('locked');
		expect(getByTestId('bio-headline')).toBeTruthy();
		expect(getByTestId('bio-hint')).toBeTruthy();
	});
});

describe('BiometricUnlock — unlock arc states', () => {
	it('unlocking: primary button is disabled and shows a Spinner', () => {
		const { getByTestId } = renderWith('unlocking');
		const btn = getByTestId('bio-unlock-btn') as HTMLButtonElement;
		expect(btn.disabled).toBe(true);
		expect(getByTestId('bio-spinner')).toBeTruthy();
	});

	it('failed: shows role=alert with the failed copy', () => {
		const { getByRole, getByTestId } = renderWith('failed');
		expect(getByRole('alert')).toBeTruthy();
		expect(getByTestId('bio-failed-msg')).toBeTruthy();
	});

	it('failed: shows the retry button', () => {
		const { getByTestId } = renderWith('failed');
		expect(getByTestId('bio-retry-btn')).toBeTruthy();
	});

	it('cancelled: no role=alert (not an error), shows quiet cancelled copy', () => {
		const { queryByRole, getByTestId } = renderWith('cancelled');
		expect(queryByRole('alert')).toBeNull();
		expect(getByTestId('bio-cancelled-msg')).toBeTruthy();
	});

	it('cancelled is distinct copy from failed', () => {
		// Two separate test bodies can each do a single render (cleanup runs between
		// tests). Within one test body only mount once — compare data-testid by
		// checking the cancelled state shows a different element than role=alert.
		offline.setLockState('cancelled');
		const { queryByRole, getByTestId } = render(BiometricUnlock);
		// cancelled: no alert role, but cancelled msg present
		expect(queryByRole('alert')).toBeNull();
		const cancelledEl = getByTestId('bio-cancelled-msg');
		expect(cancelledEl.textContent?.trim().length).toBeGreaterThan(0);
		// and it does NOT contain the same text as the failed key (spot-check word)
		expect(cancelledEl.textContent).not.toMatch(/couldn.t verify|couldn.t unlock/i);
	});
});

describe('BiometricUnlock — assertive live region (AT announcements)', () => {
	it('failed: role=alert carries the assertive announcement', () => {
		const { getByRole } = renderWith('failed');
		expect(getByRole('alert')).toBeTruthy();
	});

	it('relocked note shows when lockState is locked (idle-triggered)', async () => {
		offline.setLockState('locked');
		offline.liveMessage = 'offline.live.relocked';
		const { getByTestId } = render(BiometricUnlock);
		await tick();
		// Component reads liveMessage to show the relocked note
		expect(getByTestId('bio-relocked-note')).toBeTruthy();
	});

	it('dedicated assertive live region is present', () => {
		const { getByTestId } = renderWith('locked');
		const region = getByTestId('bio-assertive-live');
		expect(region.getAttribute('aria-live')).toBe('assertive');
	});
});

describe('BiometricUnlock — passphrase fallback', () => {
	it('passphrase toggle link is visible in locked state', () => {
		const { getByTestId } = renderWith('locked');
		expect(getByTestId('bio-passphrase-toggle')).toBeTruthy();
	});

	it('wrong passphrase: shows the reassuring wrong-passphrase copy', async () => {
		vi.mocked(bio.unlockWithPassphrase).mockResolvedValue('wrong');
		const { getByTestId } = renderWith('locked');
		// Click the toggle to open passphrase form
		getByTestId('bio-passphrase-toggle').click();
		await tick();
		const input = getByTestId('bio-passphrase-input') as HTMLInputElement;
		// Simulate entering a passphrase
		input.value = 'wrongpass';
		input.dispatchEvent(new Event('input'));
		await tick();
		// Submit the form directly
		const form = input.closest('form')!;
		form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
		// Wait for the async handler + DOM update
		await new Promise((r) => setTimeout(r, 0));
		await tick();
		expect(getByTestId('bio-passphrase-wrong')).toBeTruthy();
	});

	it('falls back to passphrase form when no biometric enrolled', async () => {
		vi.mocked(bio.isBiometricEnrolled).mockResolvedValue(false);
		offline.enrolled = true; // offline on, but device has no biometric
		const { getByTestId } = render(BiometricUnlock);
		await tick();
		// Should show passphrase input as primary path
		expect(getByTestId('bio-passphrase-input')).toBeTruthy();
	});
});

describe('BiometricUnlock — enrollment card (first-time)', () => {
	it('shows the enrollment card when !enrolled', () => {
		offline.enrolled = false;
		offline.setLockState('locked');
		const { getByTestId } = render(BiometricUnlock);
		expect(getByTestId('bio-enroll-card')).toBeTruthy();
	});

	it('shows Enable + Not Now buttons on the enrollment card', () => {
		offline.enrolled = false;
		offline.setLockState('locked');
		const { getByTestId } = render(BiometricUnlock);
		expect(getByTestId('bio-enroll-enable')).toBeTruthy();
		expect(getByTestId('bio-enroll-not-now')).toBeTruthy();
	});
});

// ── Style invariants ────────────────────────────────────────────────────────

const src = readFileSync('src/lib/components/BiometricUnlock.svelte', 'utf8');

describe('BiometricUnlock style invariants', () => {
	it('removes the glyph pulse under reduced-motion + is token-only', () => {
		const style = src.slice(src.indexOf('<style>'));
		expect(src).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/);
		expect(style).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
	});
});
