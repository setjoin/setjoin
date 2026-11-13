import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import SelectiveSyncSheet from './SelectiveSyncSheet.svelte';

const apiMocks = vi.hoisted(() => ({ listSpaces: vi.fn(), tree: vi.fn() }));
const bridge = vi.hoisted(() => ({
	status: {
		running: true,
		paused: false,
		perSpace: [{
			spaceId: 1,
			state: 'syncing',
			pendingUploads: 2,
			lastSyncMs: 0 as number | null,
			aclMode: undefined as 'legacy' | 'shadow' | 'acl' | undefined,
			unmanagedAclRiskAccepted: undefined as boolean | undefined,
		}],
		issues: [{ code: 'name-conflict', relPath: 'Design/plan.docx' }],
	},
	configure: vi.fn(),
	openRoot: vi.fn(),
	resync: vi.fn(),
	setPaused: vi.fn(),
}));

vi.mock('$lib/drive/api', () => apiMocks);
vi.mock('$lib/drive/mirrorBridge.svelte', () => ({ mirrorBridge: bridge }));

describe('SelectiveSyncSheet behavior', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		apiMocks.listSpaces.mockResolvedValue([{ id: 1, name: 'Team files' }, { id: 2, name: 'Archive' }]);
		apiMocks.tree.mockResolvedValue([{ name: 'Design', kind: 'folder' }, { name: 'readme.txt', kind: 'file' }]);
		bridge.configure.mockResolvedValue(undefined);
		bridge.openRoot.mockResolvedValue(undefined);
		bridge.resync.mockResolvedValue(undefined);
		bridge.setPaused.mockResolvedValue(undefined);
		bridge.status.paused = false;
	});

	it('loads configured spaces, exposes status/issues, and saves folder exclusions', async () => {
		render(SelectiveSyncSheet, { open: true, onClose: vi.fn() });
		expect(await screen.findByText('Team files')).toBeInTheDocument();
		expect(screen.getByText('2 waiting to upload')).toBeInTheDocument();
		expect(screen.getByText('Design/plan.docx')).toBeInTheDocument();
		const design = screen.getByRole('checkbox', { name: 'Design' });
		await fireEvent.click(design);
		await waitFor(() => expect(bridge.configure).toHaveBeenCalledWith([
			{ spaceId: 1, excludes: ['Design'] },
		]));

		await fireEvent.click(screen.getByRole('button', { name: 'Open folder' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Re-check all files' }));
		expect(bridge.openRoot).toHaveBeenCalledWith(1);
		expect(bridge.resync).toHaveBeenCalledWith(1);
	});

	it('includes a new space and pauses the mirror from the footer', async () => {
		render(SelectiveSyncSheet, { open: true, onClose: vi.fn() });
		const archive = await screen.findByRole('checkbox', { name: 'Archive' });
		await fireEvent.click(archive);
		await waitFor(() => expect(apiMocks.tree).toHaveBeenCalledWith(2, { parent: null }));
		expect(bridge.configure).toHaveBeenCalledWith(expect.arrayContaining([{ spaceId: 2, excludes: [] }]));
		await fireEvent.click(screen.getByRole('button', { name: 'Pause sync' }));
		expect(bridge.setPaused).toHaveBeenCalledWith(true);
	});

	it('requires explicit residual-copy acceptance before configuring an ACL-mode folder mirror', async () => {
		apiMocks.listSpaces.mockResolvedValue([{ id: 1, name: 'Restricted', aclMode: 'acl', aclEpoch: 3 }]);
		bridge.status.perSpace = [{
			spaceId: 1,
			state: 'policy-blocked',
			pendingUploads: 0,
			lastSyncMs: null,
			aclMode: 'acl',
			unmanagedAclRiskAccepted: false,
		}];
		render(SelectiveSyncSheet, { open: true, onClose: vi.fn() });

		expect(await screen.findByText('This folder mirror is an unmanaged export')).toBeInTheDocument();
		const acceptance = screen.getByRole('checkbox', {
			name: 'I accept that residual copies may remain on this computer',
		});
		await fireEvent.click(acceptance);
		await waitFor(() => expect(bridge.configure).toHaveBeenCalledWith([{
			spaceId: 1,
			excludes: [],
			acceptUnmanagedAclRisk: true,
		}]));
		expect(screen.queryByRole('button', { name: 'Open folder' })).not.toBeInTheDocument();
	});
});
