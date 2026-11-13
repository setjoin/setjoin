import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/svelte/svelte5';
import NodeAccessDrawer from './NodeAccessDrawer.svelte';
import { user } from '$lib/stores/auth';
import { DriveError, type DriveNodeAccess } from '$lib/drive/api';

const h = vi.hoisted(() => ({
	get: vi.fn(), search: vi.fn(), preview: vi.fn(), grant: vi.fn(), revoke: vi.fn(),
	previewInheritance: vi.fn(), setInheritance: vi.fn(), previewRequest: vi.fn(), createRequest: vi.fn(),
}));

vi.mock('$lib/drive/api', async () => ({
	...(await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api')),
	getNodeAccess: h.get, searchACLSubjects: h.search, previewNodeGrant: h.preview,
	grantNodeAccess: h.grant, revokeNodeGrant: h.revoke,
	previewNodeInheritance: h.previewInheritance, setNodeInheritance: h.setInheritance,
	previewDriveAccessRequest: h.previewRequest, createDriveAccessRequest: h.createRequest,
}));

const node = { id: 12, parentId: 11, kind: 'file' as const, name: 'Roadmap.docx', branchCount: 0, lock: null, capabilities: ['read_metadata' as const] };

function detail(overrides: Partial<DriveNodeAccess> = {}): DriveNodeAccess {
	return {
		nodeId: '12', spaceId: '7', nodeName: 'Roadmap.docx', nodeKind: 'file', aclMode: 'acl', epoch: '8',
		capabilities: ['traverse', 'read_metadata', 'manage_acl'], traverseOnly: false, canManage: true,
		writesEnabled: true, governanceEnabled: true, inheritanceBroken: false,
		presets: ['viewer', 'contributor', 'editor', 'folder_manager'],
		grants: [
			{ grantId: '31', anchorNodeId: '12', anchorName: 'Roadmap.docx', subjectKind: 'user', subjectId: '22', subjectLabel: 'Alice', subjectSecondary: 'alice@example.test', preset: 'viewer', capabilities: ['preview'], propagation: 'self', source: 'direct', relation: 'direct', usedCount: 0, createdAt: '2026-08-03T10:00:00Z' },
			{ grantId: '32', anchorNodeId: '11', anchorName: 'Plans', subjectKind: 'group', subjectId: '4', subjectLabel: 'Finance', preset: 'editor', capabilities: ['modify_content'], propagation: 'subtree', source: 'group', relation: 'inherited', usedCount: 0, createdAt: '2026-08-02T10:00:00Z' },
		],
		sources: [{ capability: 'read_metadata', sourceKind: 'space_role', sourceId: '7', anchorNodeId: null }],
		...overrides,
	};
}

describe('NodeAccessDrawer', () => {
	beforeEach(() => {
		user.set({ email: 'manager@example.test', userId: 1, isAdmin: false, hasMailbox: true });
		h.get.mockReset().mockResolvedValue(detail());
		h.search.mockReset().mockResolvedValue([{ kind: 'user', id: '23', label: 'Bob', secondary: 'bob@example.test' }]);
		h.preview.mockReset().mockResolvedValue({ requestable: true });
		h.grant.mockReset().mockResolvedValue({ grantId: '33', epoch: '9', replayed: false });
		h.revoke.mockReset().mockResolvedValue({ grantId: '31', epoch: '9', state: 'revoked' });
		h.previewInheritance.mockReset().mockResolvedValue({ nodeId: '12', spaceId: '7', epoch: '8', requestedBreak: true, currentBreak: false, changed: true, affectedNodeCount: 5, affectedPrincipalCount: 2, currentManagerSourceCount: 1, mayRemoveOfflineContent: true });
		h.setInheritance.mockReset().mockResolvedValue({ epoch: '9', changed: true });
		h.previewRequest.mockReset().mockResolvedValue({ requestable: true });
		h.createRequest.mockReset().mockResolvedValue({ requestId: '90', status: 'pending', replayed: false });
		vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-4000-8000-000000000001');
	});

	it('renders direct and inherited sources and exposes exactly four public presets', async () => {
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		expect(screen.getByText('Finance')).toBeTruthy();
		expect(screen.getByText('Inherited (1)')).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: 'Add people' }));
		for (const label of ['Viewer', 'Contributor', 'Editor', 'Folder manager']) {
			expect(screen.getByRole('radio', { name: new RegExp(label) })).toBeTruthy();
		}
		expect(screen.queryByRole('radio', { name: /Custom/ })).toBeNull();
	});

	it('previews then submits the exact preset grant and refreshes authority', async () => {
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Add people' }));
		await fireEvent.input(screen.getByLabelText('Person or group'), { target: { value: 'Bo' } });
		await vi.waitFor(() => expect(screen.getByRole('button', { name: /Bob/ })).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: /Bob/ }));
		await fireEvent.click(screen.getByRole('radio', { name: /Editor/ }));
		await fireEvent.click(screen.getByRole('radio', { name: /This item only/ }));
		await fireEvent.click(screen.getByRole('button', { name: 'Review grant' }));
		await vi.waitFor(() => expect(h.preview).toHaveBeenCalledWith(12, { subjectKind: 'user', subjectId: '23', preset: 'editor', scope: 'self' }));
		expect(screen.getByText(/Grant Bob Editor access/)).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: 'Grant access' }));
		await vi.waitFor(() => expect(h.grant).toHaveBeenCalledWith(12, expect.objectContaining({ expectedEpoch: '8', idempotencyKey: '00000000-0000-4000-8000-000000000001' })));
		expect(h.get).toHaveBeenCalledTimes(2);
	});

	it('fails closed when manage_acl is absent but still explains the caller effective source', async () => {
		h.get.mockResolvedValue(detail({ canManage: false, writesEnabled: false, grants: [] }));
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('No custom permissions. Space access applies.')).toBeTruthy());
		expect(screen.queryByRole('button', { name: 'Add people' })).toBeNull();
		await fireEvent.click(screen.getByRole('button', { name: 'Why this access?' }));
		expect(screen.getByText('Read properties')).toBeTruthy();
		expect(screen.getByText('Space role')).toBeTruthy();
	});

	it('retains the grant draft and forces review after a stale epoch conflict', async () => {
		h.grant.mockRejectedValueOnce(new DriveError({ status: 409, code: 'BZ254', detail: 'epoch conflict' }));
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Add people' }));
		await fireEvent.input(screen.getByLabelText('Person or group'), { target: { value: 'Bo' } });
		await vi.waitFor(() => screen.getByRole('button', { name: /Bob/ }));
		await fireEvent.click(screen.getByRole('button', { name: /Bob/ }));
		await fireEvent.click(screen.getByRole('button', { name: 'Review grant' }));
		await vi.waitFor(() => screen.getByRole('button', { name: 'Grant access' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Grant access' }));
		await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Permissions changed while you were editing'));
		expect(screen.getByText('Bob')).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Review grant' })).toBeTruthy();
	});

	it('fails closed on an access-load error and retries the authoritative read', async () => {
		h.get.mockRejectedValueOnce(new DriveError({ status: 503, code: 'BZ100', detail: 'temporarily unavailable' }));
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
		expect(screen.queryByRole('button', { name: 'Add people' })).toBeNull();
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		expect(h.get).toHaveBeenCalledTimes(2);
	});

	it('handles short and failed subject searches without retaining stale results', async () => {
		h.search.mockRejectedValueOnce(new Error('directory unavailable'));
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Add people' }));
		const search = screen.getByLabelText('Person or group');
		await fireEvent.input(search, { target: { value: 'B' } });
		expect(h.search).not.toHaveBeenCalled();
		await fireEvent.input(search, { target: { value: 'Bo' } });
		await vi.waitFor(() => expect(screen.getByText('Could not search for people. Try again.')).toBeTruthy());
		expect(screen.queryByRole('option')).toBeNull();
	});

	it('requires typed confirmation, revokes a direct grant, and refreshes access', async () => {
		const onChanged = vi.fn();
		render(NodeAccessDrawer, { node, onClose: vi.fn(), onChanged });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Remove access' }));
		const dialog = screen.getByRole('dialog', { name: 'Remove access' });
		await fireEvent.input(within(dialog).getByLabelText(/type Alice to confirm/i), { target: { value: 'Alice' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Remove access' }));
		await vi.waitFor(() => expect(h.revoke).toHaveBeenCalledWith('31', '8', expect.any(String)));
		expect(h.get).toHaveBeenCalledTimes(2);
		expect(onChanged).toHaveBeenCalledTimes(1);
		expect(screen.getByText('Access removed from Alice.')).toBeTruthy();
	});

	it('keeps the destructive confirmation open and authority unchanged when revoke fails', async () => {
		const onChanged = vi.fn();
		h.revoke.mockRejectedValueOnce(new DriveError({ status: 503, code: 'BZ100', detail: 'temporarily unavailable' }));
		render(NodeAccessDrawer, { node, onClose: vi.fn(), onChanged });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Remove access' }));
		const dialog = screen.getByRole('dialog', { name: 'Remove access' });
		await fireEvent.input(within(dialog).getByLabelText(/type Alice to confirm/i), { target: { value: 'Alice' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Remove access' }));
		await vi.waitFor(() => expect(h.revoke).toHaveBeenCalledOnce());
		expect(screen.getByRole('dialog', { name: 'Remove access' })).toBeTruthy();
		expect(h.get).toHaveBeenCalledOnce();
		expect(onChanged).not.toHaveBeenCalled();
	});

	it('refreshes authoritative access and keeps confirmation explicit after a revoke conflict', async () => {
		h.revoke.mockRejectedValueOnce(new DriveError({ status: 409, code: 'BZ254', detail: 'epoch conflict' }));
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Remove access' }));
		const dialog = screen.getByRole('dialog', { name: 'Remove access' });
		await fireEvent.input(within(dialog).getByLabelText(/type Alice to confirm/i), { target: { value: 'Alice' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Remove access' }));
		await vi.waitFor(() => expect(within(dialog).getByRole('alert').textContent).toContain('Permissions changed while you were editing'));
		expect(h.get).toHaveBeenCalledTimes(2);
	});

	it('previews and confirms an inheritance break with the current epoch', async () => {
		const onChanged = vi.fn();
		render(NodeAccessDrawer, { node, onClose: vi.fn(), onChanged });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Stop inheriting' }));
		await vi.waitFor(() => expect(h.previewInheritance).toHaveBeenCalledWith(12, true));
		const dialog = screen.getByRole('dialog', { name: 'Stop inheriting' });
		expect(within(dialog).getByText(/5/)).toBeTruthy();
		await fireEvent.input(within(dialog).getByLabelText(/type Roadmap\.docx to confirm/i), { target: { value: 'Roadmap.docx' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Stop inheriting' }));
		await vi.waitFor(() => expect(h.setInheritance).toHaveBeenCalledWith(12, true, '8'));
		expect(onChanged).toHaveBeenCalledTimes(1);
		expect(screen.getByText('Inherited access stopped.')).toBeTruthy();
	});

	it('resumes inheritance using the preview epoch and the narrower no-offline-impact copy', async () => {
		const onChanged = vi.fn();
		h.get.mockResolvedValue(detail({ inheritanceBroken: true }));
		h.previewInheritance.mockResolvedValue({ nodeId: '12', spaceId: '7', epoch: '12', requestedBreak: false, currentBreak: true, changed: true, affectedNodeCount: 3, affectedPrincipalCount: 1, currentManagerSourceCount: 1, mayRemoveOfflineContent: false });
		render(NodeAccessDrawer, { node, onClose: vi.fn(), onChanged });
		await vi.waitFor(() => expect(screen.getByRole('button', { name: 'Resume inheriting' })).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Resume inheriting' }));
		const dialog = await screen.findByRole('dialog', { name: 'Resume inheriting' });
		await fireEvent.input(within(dialog).getByLabelText(/type Roadmap\.docx to confirm/i), { target: { value: 'Roadmap.docx' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Resume inheriting' }));
		await vi.waitFor(() => expect(h.setInheritance).toHaveBeenCalledWith(12, false, '12'));
		expect(onChanged).toHaveBeenCalledOnce();
		expect(screen.getByText('Current parent access now applies.')).toBeTruthy();
	});

	it('refreshes access and re-previews inheritance impact after an epoch conflict', async () => {
		h.setInheritance.mockRejectedValueOnce(new DriveError({ status: 409, code: 'BZ254', detail: 'epoch conflict' }));
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Stop inheriting' }));
		const dialog = await screen.findByRole('dialog', { name: 'Stop inheriting' });
		await fireEvent.input(within(dialog).getByLabelText(/type Roadmap\.docx to confirm/i), { target: { value: 'Roadmap.docx' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Stop inheriting' }));
		await vi.waitFor(() => expect(within(dialog).getByRole('alert').textContent).toContain('Permissions changed while you were editing'));
		expect(h.get).toHaveBeenCalledTimes(2);
		expect(h.previewInheritance).toHaveBeenCalledTimes(2);
	});

	it('previews and submits a bounded self download request', async () => {
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Request access' }));
		await fireEvent.input(screen.getByLabelText('Business reason'), { target: { value: 'Need this for quarterly review' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Submit request' }));
		const expected = {
			subjectKind: 'user', subjectId: '1', capabilities: ['download'],
			propagation: 'self', durationMinutes: 60, reason: 'Need this for quarterly review',
		};
		await vi.waitFor(() => expect(h.previewRequest).toHaveBeenCalledWith(12, expect.objectContaining(expected)));
		expect(h.createRequest).toHaveBeenCalledWith(12, expect.objectContaining({
			...expected,
			idempotencyKey: '00000000-0000-4000-8000-000000000001',
		}));
		expect(screen.getByText('Access request submitted.')).toBeTruthy();
	});

	it('does not create a request when the authoritative preview says it is not requestable', async () => {
		h.previewRequest.mockResolvedValueOnce({ requestable: false });
		render(NodeAccessDrawer, { node, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Alice')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Request access' }));
		await fireEvent.input(screen.getByLabelText('Business reason'), { target: { value: 'Need this for quarterly review' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Submit request' }));
		await vi.waitFor(() => expect(h.previewRequest).toHaveBeenCalledOnce());
		expect(h.createRequest).not.toHaveBeenCalled();
		expect(screen.getByRole('alert')).toBeTruthy();
	});
});
