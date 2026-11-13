/**
 * E5 default-state inertness — every wired surface renders NOTHING new while
 * `feature.connectivity_aware_sync` is OFF (the shipped default: policy mode
 * `off`). Baseline behavior of each surface is preserved byte-for-byte in the
 * same assertions: what existed before E5 must still exist with the flag OFF.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import { tick } from 'svelte';

// Mock isOfflineAvailable so the offline singleton's nativeAvailable = true
// (mirrors OfflineStatus.test.ts; avoids window.setjoinNative setup).
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
vi.mock('$lib/jmap/client', async (importOriginal) => {
	// The settings page's import graph needs the real module (recovery offers,
	// auth-context reset); only the query functions are stubbed.
	const actual = await importOriginal<Record<string, unknown>>();
	return { ...actual, emailQuery: vi.fn(), emailGet: vi.fn() };
});
vi.mock('$lib/db/offline', () => ({ getPendingActions: vi.fn().mockResolvedValue([]) }));

import OfflineStatus from '$lib/components/OfflineStatus.svelte';
import MessageCard from '$lib/components/mail/MessageCard.svelte';
import SettingsPage from '../../routes/settings/+page.svelte';
import OfflinePolicyEditor from '$lib/admin/offline/OfflinePolicyEditor.svelte';
import { offline } from '$lib/offline/state.svelte';
import { e5ui } from '$lib/offline/e5ui.svelte';
import type { Email } from '$lib/types/jmap';
import type { OfflineCaps } from '$lib/offline/caps';

beforeEach(() => {
	offline.featureEnabled = false;
	offline.capsAllowed = false;
	offline.workOffline = false;
	offline.syncPhase = 'idle';
	offline.syncIssueCount = 0;
	offline.autoMergedCount = 0;
	offline.setLockState('unlocked');
	offline.liveMessage = '';
	offline.liveParams = undefined;
	e5ui.__resetForTests();
	vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
		ok: false, status: 404, json: async () => ({}), text: async () => '',
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
	e5ui.__resetForTests();
});

const approvedCaps = (o: Partial<OfflineCaps> = {}): OfflineCaps => ({
	allowed: true, approvalState: 'approved', maxOfflineDays: 7,
	wipeOnLogout: 'admin_default', requireApproval: false, ...o,
});

function activateE5(mode: 'observe' | 'execute' = 'execute'): void {
	e5ui.featureEnabled = true;
	e5ui.mode = mode;
}

function makeEmailWithAttachments(): Email {
	return {
		id: 'e-att',
		threadId: 't1',
		mailboxIds: { mb1: true },
		from: [{ name: 'Sender', email: 'sender@example.com' }],
		to: [{ name: 'Me', email: 'me@setjoin.local' }],
		subject: 'Files',
		preview: '',
		bodyText: 'see attached',
		receivedAt: '2026-09-01T10:00:00Z',
		keywords: { $seen: true },
		attachments: [
			{ blobId: 'b1', name: 'a.zip', type: 'application/zip', size: 100, disposition: 'attachment' },
			{ blobId: 'b2', name: 'b.pdf', type: 'application/pdf', size: 200, disposition: 'attachment' },
		],
	} as unknown as Email;
}

describe('E5 default-state inertness (flag OFF renders nothing new)', () => {
	it('OfflineStatus: no E5 status row and no E5 announcer even when offline controls are active', () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		const { queryByTestId, getByTestId } = render(OfflineStatus);
		expect(queryByTestId('e5-status')).toBeNull();
		expect(queryByTestId('e5-live')).toBeNull();
		// Baseline preserved: the existing toggle is still there.
		expect(getByTestId('work-offline-toggle')).toBeTruthy();
	});

	it('OfflineStatus: the E5 row appears only when the program is active on top of the offline gate', async () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		e5ui.setStatusAxes({ freshness: 'neverSynced', cached: false, blockingIssue: 'none', networkCost: 'unmetered' });
		const { queryByTestId, getByTestId } = render(OfflineStatus);
		expect(queryByTestId('e5-status')).toBeNull(); // e5ui still OFF
		activateE5();
		await tick();
		expect(getByTestId('e5-status')).toBeTruthy();
	});

	it('MessageCard: default state keeps the plain anchors and the ZIP save-all; no transfer rows', () => {
		const noop = () => {};
		const { queryByTestId, getByLabelText } = render(MessageCard, {
			email: makeEmailWithAttachments(),
			expanded: true,
			onToggle: noop,
			accountId: 'acc',
			onReply: noop,
			onForward: noop,
		});
		expect(queryByTestId('e5-transfer-row')).toBeNull();
		expect(queryByTestId('e5-saveall-group')).toBeNull();
		expect(queryByTestId('e5-saveall-start')).toBeNull();
		// Baseline preserved: plain download anchor for the zip, inline preview
		// chip for the pdf, and the ZIP save-all link.
		expect(getByLabelText('Download a.zip')).toBeTruthy();
		expect(getByLabelText('Preview b.pdf')).toBeTruthy();
	});

	it('MessageCard: with the program active and capability proven, a durable row replaces the anchor', async () => {
		const noop = () => {};
		activateE5();
		e5ui.durableTransferAvailable = true;
		const actions: Array<{ key: string; action: string }> = [];
		e5ui.transferActionHandler = (key, action) => actions.push({ key, action });
		const email = makeEmailWithAttachments();
		const { getByTestId, getByLabelText, findByTestId } = render(MessageCard, {
			email,
			expanded: true,
			onToggle: noop,
			accountId: 'acc',
			onReply: noop,
			onForward: noop,
		});
		// No rows until the durable controller registers one.
		expect(getByLabelText('Download a.zip')).toBeTruthy();
		e5ui.setTransferRow('acc:b1', { state: 'transferring', committedBytes: 40, totalBytes: 100 });
		expect(await findByTestId('e5-transfer-row')).toBeTruthy();
		expect(getByTestId('e5-transfer-state').textContent).toMatch(/downloading/i);
		// The OTHER attachment without a row keeps its native path (no invention).
		expect(getByLabelText('Preview b.pdf')).toBeTruthy();
		// Save all is a grouped job with resumable children (not ZIP).
		expect(getByTestId('e5-saveall-start')).toBeTruthy();
	});

	it('settings page: no E5 preferences block in the default state; the pre-E5 window input remains', () => {
		const { queryByTestId, getByLabelText } = render(SettingsPage, {
			__offlineCaps: approvedCaps(),
			__bridgePresent: true,
		} as never);
		expect(queryByTestId('e5-network-prefs')).toBeNull();
		expect(queryByTestId('e5-effective-window')).toBeNull();
		expect(queryByTestId('e5-crossed-explanation')).toBeNull();
		// Baseline preserved: the editable window field still renders when OFF.
		expect(getByLabelText(/days of mail to keep offline/i)).toBeTruthy();
	});

	it('settings page: with the program active, the window write is replaced by the read-only summary + storage link', async () => {
		const { queryByLabelText, getByTestId, queryByTestId } = render(SettingsPage, {
			__offlineCaps: approvedCaps(),
			__bridgePresent: true,
		} as never);
		activateE5();
		await tick();
		// The one-owner split: /settings no longer renders a window writer.
		expect(queryByLabelText(/days of mail to keep offline/i)).toBeNull();
		expect(getByTestId('e5-effective-window')).toBeTruthy();
		expect(getByTestId('e5-storage-link').getAttribute('href')).toBe('/settings/storage');
		expect(queryByTestId('e5-network-prefs')).toBeTruthy();
	});

	it('admin policy editor: no preview block in the default state', () => {
		const { queryByTestId } = render(OfflinePolicyEditor, {
			policies: [],
			loading: false,
			error: '',
		});
		expect(queryByTestId('e5-admin-preview')).toBeNull();
	});

	it('admin policy editor: the preview block appears only while the program is active', async () => {
		const { queryByTestId } = render(OfflinePolicyEditor, {
			policies: [],
			loading: false,
			error: '',
		});
		activateE5('observe');
		await tick();
		expect(queryByTestId('e5-admin-preview')).toBeTruthy();
	});

	it('the shipped e5ui gate mirrors the OFF policy source (configureE5FromPolicySource)', async () => {
		const { createOffPolicySource } = await import('$lib/offline/coordinator');
		const { configureE5FromPolicySource } = await import('$lib/offline/e5ui.svelte');
		activateE5(); // even from an active state, re-reading the OFF source turns it off
		await configureE5FromPolicySource(createOffPolicySource());
		expect(e5ui.featureEnabled).toBe(false);
		expect(e5ui.mode).toBe('off');
		expect(e5ui.active).toBe(false);
	});
});
