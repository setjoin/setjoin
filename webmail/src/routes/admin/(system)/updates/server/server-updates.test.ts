import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { setLocale } from '$lib/i18n';

const mocks = vi.hoisted(() => ({
	console: vi.fn(), preview: vi.fn(), challenge: vi.fn(), complete: vi.fn(),
	request: vi.fn(), intent: vi.fn(), cancel: vi.fn(),
}));
vi.mock('$lib/admin/client', () => ({
	adminUpgradeConsole: mocks.console,
	adminUpgradePreview: mocks.preview,
	adminUpgradeChallenge: mocks.challenge,
	adminUpgradeCompleteChallenge: mocks.complete,
	adminUpgradeRequest: mocks.request,
	adminUpgradeIntent: mocks.intent,
	adminUpgradeCancel: mocks.cancel,
}));
import Page from './+page.svelte';

const intent = {
	intentId: '42', releaseId: 'release-179', manifestDigest: 'a'.repeat(64),
	recoverySetId: '11111111-1111-4111-8111-111111111111', recoverySetDigest: 'b'.repeat(64),
	state: 'migrations', stateGeneration: '7', reason: 'Apply a verified Setjoin release',
	scheduleAt: null, expiresAt: '2026-08-02T00:00:00Z', result: null,
	events: [
		{ generation: '2', from: 'approved', to: 'claimed', occurredAt: '2026-08-01T10:00:00Z' },
		{ generation: '7', from: 'maintenance', to: 'migrations', occurredAt: '2026-08-01T10:02:00Z' },
	],
};

function consoleModel(execution: boolean, active: typeof intent | null = null) {
	return {
		schemaVersion: 1, flags: { catalog: true, execution },
		releases: [{
			releaseId: 'release-179', version: '2.2.0', channel: 'community',
			manifestDigest: 'a'.repeat(64), metadataExpiresAt: '2026-08-03T00:00:00Z',
			entitlementGraceUntil: null, status: 'available',
			readiness: { status: 'ready', generation: '1', checks: { disk: true }, blockerCount: 0, expiresAt: '2026-08-02T00:00:00Z' },
		}],
		recoverySet: {
			recoverySetId: '11111111-1111-4111-8111-111111111111', manifestDigest: 'b'.repeat(64),
			status: 'verified', createdAt: '2026-08-01T09:00:00Z', expiresAt: '2026-08-02T09:00:00Z', fresh: true,
			restoreProof: { proofId: '22222222-2222-4222-8222-222222222222', targetId: 'isolated-1', provedAt: '2026-08-01T09:30:00Z', staleWarning: false },
		},
		intent: active,
	};
}

describe('transactional server updates', () => {
	beforeEach(() => {
		vi.clearAllMocks(); resetStores(); setLocale('en'); mockSessionLoad();
		vi.stubGlobal('crypto', { randomUUID: vi.fn(() => '33333333-3333-4333-8333-333333333333') });
		mocks.intent.mockResolvedValue(intent);
	});
	afterEach(() => { setLocale('en'); vi.unstubAllGlobals(); });

	it('fails visibly closed while execution is off but preserves signed evidence', async () => {
		mocks.console.mockResolvedValue(consoleModel(false));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText('Transactional execution is off.')).toBeInTheDocument());
		expect(screen.getByText('2.2.0')).toBeInTheDocument();
		expect(screen.getByText('Restore rehearsal: proven')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeDisabled();
	});

	it('renders explicit empty evidence when the catalog and recovery set are absent', async () => {
		mocks.console.mockResolvedValue({ ...consoleModel(true), releases: [], recoverySet: null });
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText('No verified signed release is available.')).toBeInTheDocument());
		expect(screen.getByText('No complete DB + blob + protected-config recovery set is recorded.')).toBeInTheDocument();
		expect(screen.getByText('Select a release to inspect.')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeDisabled();
	});

	it('labels a withdrawn Enterprise release and shows its bounded access grace', async () => {
		mocks.console.mockResolvedValue({
			...consoleModel(true),
			releases: [{
				...consoleModel(true).releases[0],
				channel: 'enterprise',
				status: 'withdrawn',
				entitlementGraceUntil: '2026-08-04T00:00:00Z',
			}],
		});
		await renderAsUser(Page, {}, { isAdmin: true });
		const releaseButton = (await screen.findByText('release-179')).closest('button');
		expect(releaseButton).not.toBeNull();
		await fireEvent.click(releaseButton!);
		await waitFor(() => expect(screen.getAllByText('withdrawn')).toHaveLength(2));
		expect(screen.getByText(/Enterprise artifact access grace ends/)).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeDisabled();
	});

	it('rejects a past local schedule before previewing', async () => {
		mocks.console.mockResolvedValue(consoleModel(true));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeEnabled());
		await fireEvent.input(screen.getByLabelText('Schedule (optional, local time)'), { target: { value: '2020-01-02T03:04' } });
		expect(screen.getByRole('alert')).toHaveTextContent('Choose a future local time.');
		expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeDisabled();
		expect(mocks.preview).not.toHaveBeenCalled();
	});

	it('shows structured server remediation after a failed action', async () => {
		mocks.console.mockResolvedValue(consoleModel(true));
		mocks.preview.mockRejectedValue(new Error(JSON.stringify({
			detail: 'The recovery proof expired.', remediation: 'Run an isolated restore rehearsal.',
		})));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeEnabled());
		await fireEvent.click(screen.getByRole('button', { name: 'Review upgrade' }));
		const alert = await screen.findByRole('alert');
		expect(alert).toHaveTextContent('Action failed.');
		expect(alert).toHaveTextContent('The recovery proof expired. Run an isolated restore rehearsal.');
	});

	it('renders durable progress and exposes cancellation only at safe states', async () => {
		mocks.console.mockResolvedValue(consoleModel(true, intent));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getAllByText('migrations')).toHaveLength(2));
		expect(screen.getByRole('progressbar', { name: 'Upgrade transaction progress' })).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Review upgrade' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Cancel safely' })).not.toBeInTheDocument();
	});

	it('offers generation-bound cancellation only before maintenance', async () => {
		const preflight = { ...intent, state: 'preflight', stateGeneration: '4' } as typeof intent;
		mocks.console.mockResolvedValue(consoleModel(true, preflight));
		mocks.cancel.mockResolvedValue({ intentId: '42', state: 'cancel_requested', stateGeneration: '5' });
		mocks.intent.mockResolvedValue({ ...preflight, state: 'cancel_requested', stateGeneration: '5' });
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('button', { name: 'Cancel safely' })).toBeEnabled());
		await fireEvent.click(screen.getByRole('button', { name: 'Cancel safely' }));
		await waitFor(() => expect(mocks.cancel).toHaveBeenCalledWith(preflight, 'Cancel this upgrade at the next safe boundary'));
	});

	it('renders recovery-required as an assertive no-shell terminal', async () => {
		const recoveryRequired = { ...intent, state: 'recovery_required', stateGeneration: '9' } as typeof intent;
		mocks.console.mockResolvedValue(consoleModel(true, recoveryRequired));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText('Manual recovery is required.')).toBeInTheDocument());
		expect(screen.getByText('Manual recovery is required.').closest('[aria-live="assertive"]')).not.toBeNull();
		expect(screen.queryByRole('button', { name: 'Cancel safely' })).not.toBeInTheDocument();
		expect(document.body.textContent).not.toContain('journalctl');
		expect(document.body.textContent).not.toContain('/opt/setjoin');
	});

	it('renders the dangerous-state labels in Chinese without exposing host controls', async () => {
		setLocale('zh');
		const recoveryRequired = { ...intent, state: 'recovery_required', stateGeneration: '9' } as typeof intent;
		mocks.console.mockResolvedValue(consoleModel(true, recoveryRequired));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('heading', { name: '服务器更新' })).toBeInTheDocument());
		expect(screen.getByText('需要手动恢复。')).toBeInTheDocument();
		expect(screen.getByRole('progressbar', { name: '升级事务进度' })).toBeInTheDocument();
		expect(document.body.textContent).not.toContain('journalctl');
		expect(document.body.textContent).not.toContain('/opt/setjoin');
	});

	it('treats reconnect state as a silent baseline and announces a later transition without moving focus', async () => {
		const readiness = { ...intent, state: 'readiness', stateGeneration: '8' } as typeof intent;
		mocks.console.mockResolvedValueOnce(consoleModel(true, intent)).mockResolvedValueOnce(consoleModel(true, readiness));
		await renderAsUser(Page, {}, { isAdmin: true });
		const refresh = await screen.findByRole('button', { name: 'Refresh' });
		expect(document.querySelector('.sr-only')?.textContent).toBe('');
		refresh.focus();
		await fireEvent.click(refresh);
		await waitFor(() => expect(document.querySelector('.sr-only')?.textContent).toBe('Upgrade state changed to readiness.'));
		expect(refresh).toHaveFocus();
	});

	it('uses preview, fresh step-up, and one-use elevation without accepting a path', async () => {
		mocks.console.mockResolvedValue(consoleModel(true));
		mocks.preview.mockResolvedValue({
			preview: { releaseId: 'release-179', targetVersion: '2.2.0', channel: 'community', manifestDigest: 'a'.repeat(64), recoverySetId: '11111111-1111-4111-8111-111111111111', recoverySetDigest: 'b'.repeat(64), recoverySetExpiresAt: '2026-08-02T09:00:00Z', approvalRequired: false },
			previewDigest: 'c'.repeat(64), expiresAt: '2026-08-01T10:05:00Z',
		});
		mocks.challenge.mockResolvedValue({ challengeId: '44444444-4444-4444-8444-444444444444' });
		mocks.complete.mockResolvedValue({ elevationId: '55555555-5555-4555-8555-555555555555' });
		mocks.request.mockResolvedValue({ intentId: '42', state: 'approved' });
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('button', { name: 'Review upgrade' })).toBeEnabled());
		await fireEvent.input(screen.getByLabelText('Schedule (optional, local time)'), { target: { value: '2099-01-02T03:04' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Review upgrade' }));
		expect(mocks.preview).toHaveBeenCalledWith('release-179', 'Apply a verified Setjoin release', new Date(2099, 0, 2, 3, 4).toISOString());
		await waitFor(() => expect(screen.getByRole('button', { name: 'Authorize & start' })).toBeEnabled());
		await fireEvent.click(screen.getByRole('button', { name: 'Authorize & start' }));
		await waitFor(() => expect(mocks.request).toHaveBeenCalled());
		expect(mocks.request.mock.calls[0]?.[2]).toBe(new Date(2099, 0, 2, 3, 4).toISOString());
		expect(JSON.stringify(mocks.request.mock.calls)).not.toContain('/tmp/');
		expect(JSON.stringify(mocks.request.mock.calls)).not.toContain('binary_path');
		expect(screen.getByRole('link', { name: 'Back to client versions' })).toHaveAttribute('href', '/admin/updates');
		expect(screen.queryByLabelText('Gateway binary (.tar.gz)')).not.toBeInTheDocument();
	});
});
