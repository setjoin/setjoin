import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	list: vi.fn(),
	set: vi.fn(),
	getSodMode: vi.fn(),
	setSodMode: vi.fn(),
	deleteUnknown: vi.fn(),
	setMode: vi.fn()
}));

vi.mock('$lib/admin/client', () => ({
	adminFeatureList: api.list,
	adminFeatureSet: api.set,
	adminFeatureDeleteUnknown: api.deleteUnknown,
	adminFeatureRegistryModeSet: api.setMode
}));

vi.mock('$lib/admin/roles', () => ({
	adminGetSodMode: api.getSodMode,
	adminSetSodMode: api.setSodMode
}));

import Page from './+page.svelte';

type TestToggle = {
	key: string;
	enabled: boolean;
	storedEnabled: boolean | null;
	defaultEnabled: boolean;
	classification: 'known' | 'unknown';
	registryMode: 'observe' | 'enforce';
	gatewayEffective: boolean;
	gatewaySource: 'environment' | 'database' | 'default';
	authserverEffective: null;
	authserverSource: 'not_reported';
	changeMode: 'live' | 'disconnect-live-clients' | '';
	disableBehavior: 'immediate' | 'stop-admission-drain-existing' | '';
	dependencies: string[];
	confirmationRequired: boolean;
	description: string;
};

function toggle(overrides: Partial<TestToggle> & Pick<TestToggle, 'key'>): TestToggle {
	const { key, ...rest } = overrides;
	return {
		key,
		enabled: false,
		storedEnabled: false,
		defaultEnabled: false,
		classification: 'known',
		registryMode: 'observe',
		gatewayEffective: false,
		gatewaySource: 'database',
		authserverEffective: null,
		authserverSource: 'not_reported',
		changeMode: '',
		disableBehavior: '',
		dependencies: [],
		confirmationRequired: false,
		description: '',
		...rest
	};
}

const baseRows: TestToggle[] = [
	toggle({
		key: 'feature.imap',
		enabled: true,
		storedEnabled: true,
		defaultEnabled: true,
		gatewayEffective: true,
		changeMode: 'disconnect-live-clients',
		disableBehavior: 'immediate',
		description: 'IMAP listener'
	}),
	toggle({
		key: 'feature.spf',
		defaultEnabled: true,
		description: 'Sender policy checks'
	})
];

const unknown = toggle({
	key: 'legacy.custom_flag',
	enabled: true,
	storedEnabled: true,
	defaultEnabled: true,
	classification: 'unknown',
	gatewayEffective: true,
	description: 'Out-of-band row'
});

let rows: TestToggle[];

function allowConfig() {
	jmapSession.set({
		accounts: { a1: { name: 'admin@test', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: { consoles: ['system'], permissions: ['system.config'] }
			}
		}
	} as never);
}

async function renderConfigured() {
	await renderAsUser(Page, {}, { isAdmin: true });
	allowConfig();
	await screen.findByText('IMAP listener');
}

async function fillAuditReason(value = 'approved test change') {
	await fireEvent.input(screen.getByLabelText('Audit reason'), { target: { value } });
}

async function openRemoval() {
	await fireEvent.click(screen.getByRole('button', { name: `Remove unknown setting ${unknown.key}` }));
	await waitFor(() => expect(screen.getByLabelText(`Type ${unknown.key} to confirm`)).toHaveFocus());
	await fireEvent.input(screen.getByLabelText(`Type ${unknown.key} to confirm`), {
		target: { value: unknown.key }
	});
	await fillAuditReason('remove stale test row');
}

describe('admin feature registry UI', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		resetStores();
		mockSessionLoad();
		rows = baseRows.map((row) => ({ ...row }));
		api.list.mockImplementation(async () => rows.map((row) => ({ ...row })));
		api.set.mockImplementation(async (key: string, enabled: boolean) => {
			rows = rows.map((row) =>
				row.key === key ? { ...row, enabled, storedEnabled: enabled, gatewayEffective: enabled } : row
			);
		});
		api.setSodMode.mockImplementation(async (enabled: boolean) => {
			rows = rows.map((row) =>
				row.key === 'dengbao.sod_mode'
					? { ...row, enabled, storedEnabled: enabled, gatewayEffective: enabled }
					: row
			);
			return { enabled };
		});
		api.getSodMode.mockResolvedValue({ enabled: false, violations: [] });
		api.deleteUnknown.mockImplementation(async (key: string) => {
			rows = rows.filter((row) => row.key !== key);
		});
		api.setMode.mockImplementation(async (mode: 'observe' | 'enforce') => {
			rows = rows.map((row) => ({ ...row, registryMode: mode }));
			return { mode, registryDigest: 'a'.repeat(64) };
		});
	});

	afterEach(() => vi.unstubAllGlobals());

	it('uses a reasoned dialog for listener shutdown and verifies reloaded state', async () => {
		await renderConfigured();
		await fireEvent.click(screen.getByRole('switch', { name: 'Disable imap (feature.imap)' }));

		const dialog = screen.getByRole('dialog', { name: 'Change feature setting?' });
		expect(within(dialog).getByText('Disabling this listener disconnects active clients.')).toBeInTheDocument();
		expect(api.set).not.toHaveBeenCalled();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }));
		expect(within(dialog).getByText('Enter an audit reason.')).toHaveAttribute('id');

		await fillAuditReason();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }));
		await waitFor(() => expect(api.set).toHaveBeenCalledWith('feature.imap', false, 'approved test change'));
		await waitFor(() => expect(screen.getByRole('switch', { name: 'Enable imap (feature.imap)' })).not.toBeChecked());
	});

	it('routes SoD changes through the dedicated conflict-checking endpoint', async () => {
		rows = [
			...baseRows.map((row) => ({ ...row })),
			toggle({ key: 'dengbao.sod_mode', description: 'Separation of duties' })
		];
		await renderConfigured();
		await fireEvent.click(screen.getByRole('switch', { name: 'Enable dengbao.sod mode (dengbao.sod_mode)' }));
		await fillAuditReason('validate SoD assignments');
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

		await waitFor(() => expect(api.setSodMode).toHaveBeenCalledWith(true, 'validate SoD assignments'));
		expect(api.set).not.toHaveBeenCalledWith('dengbao.sod_mode', true, expect.anything());
		await waitFor(() =>
			expect(screen.getByRole('switch', { name: 'Disable dengbao.sod mode (dengbao.sod_mode)' })).toBeChecked()
		);
	});

	it('keeps the SoD dialog open and surfaces assignment conflicts', async () => {
		rows = [
			...baseRows.map((row) => ({ ...row })),
			toggle({ key: 'dengbao.sod_mode', description: 'Separation of duties' })
		];
		api.getSodMode.mockResolvedValueOnce({
			enabled: false,
			violations: Array.from({ length: 9 }, (_, index) => ({
				violationType: 'role_conflict',
				subject: `role-${index}`,
				detail: 'conflicting permissions'
			}))
		});
		await renderConfigured();
		await fireEvent.click(screen.getByRole('switch', { name: 'Enable dengbao.sod mode (dengbao.sod_mode)' }));
		await fillAuditReason('validate SoD assignments');
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

		expect(await screen.findByRole('alert')).toHaveTextContent('Resolve 9 conflicts before enabling.');
		expect(api.setSodMode).not.toHaveBeenCalled();
		expect(screen.getByRole('dialog', { name: 'Change feature setting?' })).toBeInTheDocument();
		expect(screen.getByRole('switch', { name: 'Enable dengbao.sod mode (dengbao.sod_mode)' })).not.toBeChecked();
	});

	it('renders dependency, drain, and security warnings from API metadata', async () => {
		rows = [
			...baseRows.map((row) => ({ ...row })),
			toggle({
				key: 'feature.meet',
				description: 'Meet'
			}),
			toggle({
				key: 'feature.meet_recording',
				dependencies: ['feature.meet'],
				confirmationRequired: true,
				description: 'Meet recording'
			}),
			toggle({
				key: 'feature.webhook_publication_outbox',
				enabled: true,
				storedEnabled: true,
				defaultEnabled: true,
				disableBehavior: 'stop-admission-drain-existing',
				description: 'Durable webhook publication'
			})
		];
		await renderConfigured();

		await fireEvent.click(screen.getByRole('switch', { name: 'Enable meet recording (feature.meet_recording)' }));
		let dialog = screen.getByRole('dialog', { name: 'Change feature setting?' });
		expect(within(dialog).getByText('Enable required settings first: feature.meet.')).toBeInTheDocument();
		expect(within(dialog).getByText('This change affects the organization security posture and requires explicit confirmation.')).toBeInTheDocument();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

		await fireEvent.click(screen.getByRole('switch', { name: 'Disable webhook publication outbox (feature.webhook_publication_outbox)' }));
		dialog = screen.getByRole('dialog', { name: 'Change feature setting?' });
		expect(within(dialog).getByText('Disabling stops new admissions; already accepted work continues draining.')).toBeInTheDocument();
	});

	it('surfaces unknown rows first, blocks enforce, and removes by exact key plus reason', async () => {
		rows = [...baseRows.map((row) => ({ ...row })), { ...unknown }];
		await renderConfigured();

		expect(screen.getByText('1 unrecognized setting needs review before registry enforcement.')).toBeInTheDocument();
		expect(screen.getByText('Unregistered (report only)')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Enforce registered settings' })).toBeDisabled();
		const keys = screen.getAllByText(/^(legacy\.custom_flag|feature\.imap|feature\.spf)$/);
		expect(keys[0]).toHaveTextContent(unknown.key);

		await openRemoval();
		await fireEvent.click(screen.getByRole('button', { name: 'Remove setting' }));
		await waitFor(() => expect(api.deleteUnknown).toHaveBeenCalledWith(unknown.key, 'remove stale test row'));
		await waitFor(() => expect(screen.queryByText(unknown.key)).not.toBeInTheDocument());
	});

	it('renders an enforced unknown row as ignored without an ineffective switch', async () => {
		rows = [
			{ ...unknown, registryMode: 'enforce' },
			...baseRows.map((row) => ({ ...row, registryMode: 'enforce' as const }))
		];
		await renderConfigured();

		expect(screen.getByText('Ignored')).toBeInTheDocument();
		expect(screen.getByText('1 unrecognized setting is ignored and may be removed.')).toBeInTheDocument();
		expect(screen.queryByRole('switch', { name: /legacy\.custom_flag/ })).not.toBeInTheDocument();
		expect(screen.getByRole('button', { name: `Remove unknown setting ${unknown.key}` })).toBeEnabled();
	});

	it('preserves removal inputs when the row remains after a successful response', async () => {
		rows = [{ ...unknown }, ...baseRows.map((row) => ({ ...row }))];
		api.deleteUnknown.mockResolvedValue(undefined);
		await renderConfigured();
		await openRemoval();
		await fireEvent.click(screen.getByRole('button', { name: 'Remove setting' }));

		await screen.findByText('The setting is still present. Review the error and try again.');
		expect(screen.getByLabelText(`Type ${unknown.key} to confirm`)).toHaveValue(unknown.key);
		expect(screen.getByLabelText('Audit reason')).toHaveValue('remove stale test row');
		expect(screen.getByRole('button', { name: 'Remove setting' })).toBeEnabled();
	});

	it('offers retry verification after a reload failure and then accepts absence', async () => {
		rows = [{ ...unknown }, ...baseRows.map((row) => ({ ...row }))];
		api.deleteUnknown.mockResolvedValue(undefined);
		await renderConfigured();
		await openRemoval();
		api.list.mockRejectedValueOnce(new Error('network interrupted'));
		await fireEvent.click(screen.getByRole('button', { name: 'Remove setting' }));

		await screen.findByText(`Could not verify whether ${unknown.key} was removed.`);
		expect(screen.getByLabelText('Audit reason')).toHaveValue('remove stale test row');
		rows = baseRows.map((row) => ({ ...row }));
		api.list.mockImplementation(async () => rows.map((row) => ({ ...row })));
		await fireEvent.click(screen.getByRole('button', { name: 'Retry verification' }));
		await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Remove unrecognized setting?' })).not.toBeInTheDocument());
	});

	it('treats an ambiguous delete error as success when reconciliation proves absence', async () => {
		rows = [{ ...unknown }, ...baseRows.map((row) => ({ ...row }))];
		api.deleteUnknown.mockImplementation(async (key: string) => {
			rows = rows.filter((row) => row.key !== key);
			throw new Error('response lost');
		});
		await renderConfigured();
		await openRemoval();
		await fireEvent.click(screen.getByRole('button', { name: 'Remove setting' }));

		await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Remove unrecognized setting?' })).not.toBeInTheDocument());
		expect(screen.queryByText('response lost')).not.toBeInTheDocument();
	});

	it('never claims a registry mode before the reloaded server response matches', async () => {
		await renderConfigured();
		await fireEvent.click(screen.getByRole('button', { name: 'Enforce registered settings' }));
		await fillAuditReason();
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

		await waitFor(() => expect(api.setMode).toHaveBeenCalledWith('enforce', 'approved test change'));
		await waitFor(() => expect(screen.getByText('Return to observe mode')).toBeInTheDocument());

		api.setMode.mockResolvedValueOnce({ mode: 'enforce', registryDigest: 'a'.repeat(64) });
		rows = rows.map((row) => ({ ...row, registryMode: 'observe' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Return to observe mode' }));
		await fillAuditReason('rollback test');
		// Requesting observe when the authoritative state is already observe is a
		// no-op at the server, but the dialog still verifies the returned list.
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
		await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Registry mode' })).not.toBeInTheDocument());
	});

	it('keeps the mode dialog open when reload contradicts the requested mode', async () => {
		api.setMode.mockResolvedValue({ mode: 'enforce', registryDigest: 'a'.repeat(64) });
		await renderConfigured();
		await fireEvent.click(screen.getByRole('button', { name: 'Enforce registered settings' }));
		await fillAuditReason();
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

		await screen.findByText('The reloaded server state does not match the requested registry mode.');
		expect(screen.getByRole('dialog', { name: 'Registry mode' })).toBeInTheDocument();
		expect(screen.getByText('Observe')).toBeInTheDocument();
	});

	it('reports a partially applied preset and preserves the audit dialog', async () => {
		api.set.mockImplementation(async (key: string, enabled: boolean) => {
			if (key === 'feature.spf') throw new Error('spf rejected');
			rows = rows.map((row) => row.key === key ? { ...row, storedEnabled: enabled } : row);
		});
		await renderConfigured();
		await fireEvent.click(screen.getByRole('button', { name: 'Enterprise' }));
		await fillAuditReason();
		await fireEvent.click(screen.getByRole('button', { name: 'Apply preset' }));

		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/partially applied.*feature\.spf/));
		expect(screen.getByRole('dialog', { name: 'Apply Enterprise preset?' })).toBeInTheDocument();
	});

	it('shows load failures and keeps controls disabled without permission', async () => {
		api.list.mockRejectedValueOnce(new Error('feature backend unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('feature backend unavailable'));
		expect(screen.getByRole('button', { name: 'Minimal' })).toBeDisabled();
	});
});
