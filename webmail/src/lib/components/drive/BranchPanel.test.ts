import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import BranchPanel from './BranchPanel.svelte';
import type { DriveBranch } from '$lib/drive/api';
import { DriveError } from '$lib/drive/api';

const listBranches = vi.fn();
const createBranch = vi.fn();
const renameBranch = vi.fn();
const setBranchStatus = vi.fn();
const resolveBranch = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		listBranches: (...a: unknown[]) => listBranches(...a),
		createBranch: (...a: unknown[]) => createBranch(...a),
		renameBranch: (...a: unknown[]) => renameBranch(...a),
		setBranchStatus: (...a: unknown[]) => setBranchStatus(...a),
		resolveBranch: (...a: unknown[]) => resolveBranch(...a),
	};
});

function branch(overrides: Partial<DriveBranch> = {}): DriveBranch {
	return {
		id: 1,
		name: 'budget-redo',
		status: 'open',
		autoCreated: false,
		headVersionId: 10,
		forkedFromVersionId: 9,
		createdBy: 42,
		createdAt: '2026-07-01T00:00:00Z',
		resolvedBy: null,
		resolvedAt: null,
		ffEligible: true,
		...overrides,
	};
}

describe('BranchPanel', () => {
	beforeEach(() => {
		listBranches.mockReset();
		createBranch.mockReset();
		renameBranch.mockReset();
		setBranchStatus.mockReset();
		resolveBranch.mockReset();
	});

	it('renders the branch list: name, status chip, age; merged/discarded hidden by default', async () => {
		listBranches.mockResolvedValue([branch()]);
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx' });
		await vi.waitFor(() => expect(screen.getByText('budget-redo')).toBeTruthy());
		expect(screen.getByText('Open')).toBeTruthy();
		expect(listBranches).toHaveBeenCalledWith(5, { all: false });
	});

	it('"show closed" toggle re-fetches with all:true', async () => {
		listBranches.mockResolvedValue([]);
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx' });
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalledWith(5, { all: false }));
		const toggle = screen.getByLabelText('Show closed branches');
		await fireEvent.click(toggle);
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalledWith(5, { all: true }));
	});

	it('"New branch from this version" calls createBranch with the current version id', async () => {
		listBranches.mockResolvedValue([]);
		createBranch.mockResolvedValue({ branchId: 99 });
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx' });
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		const input = screen.getByLabelText('Branch name');
		await fireEvent.input(input, { target: { value: 'new-idea' } });
		await fireEvent.click(screen.getByRole('button', { name: 'New branch from this version' }));
		await vi.waitFor(() => expect(createBranch).toHaveBeenCalledWith(5, 'new-idea', 10));
	});

	it('rename inline calls renameBranch', async () => {
		listBranches.mockResolvedValue([branch()]);
		renameBranch.mockResolvedValue(undefined);
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx' });
		await vi.waitFor(() => expect(screen.getByText('budget-redo')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Rename branch' }));
		const input = screen.getByDisplayValue('budget-redo');
		await fireEvent.input(input, { target: { value: 'budget-redo-2' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await vi.waitFor(() => expect(renameBranch).toHaveBeenCalledWith(1, 'budget-redo-2'));
	});

	it('"Ready for review" calls setBranchStatus(id, review)', async () => {
		listBranches.mockResolvedValue([branch()]);
		setBranchStatus.mockResolvedValue(undefined);
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx' });
		await vi.waitFor(() => expect(screen.getByText('budget-redo')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Ready for review' }));
		await vi.waitFor(() => expect(setBranchStatus).toHaveBeenCalledWith(1, 'review'));
	});

	it('BZ150 duplicate-name error surfaces the localized message', async () => {
		listBranches.mockResolvedValue([]);
		createBranch.mockRejectedValue(new DriveError({ status: 409, code: 'BZ150', detail: 'branch is no longer open' }));
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx' });
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		const input = screen.getByLabelText('Branch name');
		await fireEvent.input(input, { target: { value: 'dup' } });
		await fireEvent.click(screen.getByRole('button', { name: 'New branch from this version' }));
		await vi.waitFor(() =>
			expect(screen.getByText('That branch name is taken or the branch can no longer be changed.')).toBeTruthy(),
		);
	});

	it('"Resolve" opens ResolveDialog for that branch and calling ff routes through resolveBranch', async () => {
		listBranches.mockResolvedValue([branch()]);
		resolveBranch.mockResolvedValue({ verb: 'ff', headVersionId: 10, newNodeId: null });
		const onChanged = vi.fn();
		render(BranchPanel, { nodeId: 5, fromVersionId: 10, canWrite: true, fileName: 'report.xlsx', onChanged });
		await vi.waitFor(() => expect(screen.getByText('budget-redo')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Resolve' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Make this the main document' }));
		await vi.waitFor(() => expect(resolveBranch).toHaveBeenCalledWith(1, 'ff', undefined));
		await vi.waitFor(() => expect(onChanged).toHaveBeenCalled());
	});
});
