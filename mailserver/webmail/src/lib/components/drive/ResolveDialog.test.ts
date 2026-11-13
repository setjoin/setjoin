import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import ResolveDialog from './ResolveDialog.svelte';
import type { DriveBranch } from '$lib/drive/api';
import { DriveError } from '$lib/drive/api';

const resolveBranch = vi.fn();
const listBranches = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		resolveBranch: (...a: unknown[]) => resolveBranch(...a),
		listBranches: (...a: unknown[]) => listBranches(...a),
	};
});

function branch(overrides: Partial<DriveBranch> = {}): DriveBranch {
	return {
		id: 3,
		name: 'budget-redo',
		status: 'open',
		autoCreated: false,
		headVersionId: 21,
		forkedFromVersionId: 19,
		createdBy: 1,
		createdAt: '2026-07-09T00:00:00Z',
		resolvedBy: null,
		resolvedAt: null,
		ffEligible: true,
		...overrides,
	};
}

describe('ResolveDialog', () => {
	beforeEach(() => {
		resolveBranch.mockReset();
		listBranches.mockReset();
	});

	it('offers fast-forward only when ffEligible, and it is the first verb', async () => {
		resolveBranch.mockResolvedValue({ verb: 'ff', headVersionId: 21, newNodeId: null });
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: true }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		const verbButtons = screen
			.getAllByRole('button')
			.map((b) => b.textContent?.trim())
			.filter((text) => text && text !== 'Close');
		expect(verbButtons[0]).toBe('Make this the main document');
		await fireEvent.click(screen.getByRole('button', { name: 'Make this the main document' }));
		expect(resolveBranch).toHaveBeenCalledWith(3, 'ff', undefined);
	});

	it('hides fast-forward when not ffEligible', () => {
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: false }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		expect(screen.queryByRole('button', { name: 'Make this the main document' })).toBeNull();
	});

	it('adopt calls resolveBranch with verb adopt', async () => {
		resolveBranch.mockResolvedValue({ verb: 'adopt', headVersionId: 22, newNodeId: null });
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: false }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		await fireEvent.click(screen.getByRole('button', { name: 'Take this branch as a new main version' }));
		expect(resolveBranch).toHaveBeenCalledWith(3, 'adopt', undefined);
	});

	it('keep-both reveals a prefilled name input, then submits with it', async () => {
		resolveBranch.mockResolvedValue({ verb: 'keep_both', headVersionId: null, newNodeId: 88 });
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: false }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		await fireEvent.click(screen.getByRole('button', { name: 'Keep both as separate files' }));
		const input = await screen.findByDisplayValue('Report — budget-redo.xlsx');
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
		expect(resolveBranch).toHaveBeenCalledWith(3, 'keep_both', 'Report — budget-redo.xlsx');
	});

	it('discard requires a confirm step before calling resolveBranch', async () => {
		resolveBranch.mockResolvedValue({ verb: 'discard', headVersionId: null, newNodeId: null });
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: false }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		await fireEvent.click(screen.getByRole('button', { name: 'Close without merging' }));
		expect(resolveBranch).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
		expect(resolveBranch).toHaveBeenCalledWith(3, 'discard', undefined);
	});

	it('BZ150 re-fetches branches and re-renders without the ff option', async () => {
		resolveBranch.mockRejectedValue(new DriveError({ status: 409, code: 'BZ150', detail: 'branch is no longer open' }));
		listBranches.mockResolvedValue([branch({ ffEligible: false })]);
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: true }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		await fireEvent.click(screen.getByRole('button', { name: 'Make this the main document' }));
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalledWith(5, { all: true }));
		await vi.waitFor(() => expect(screen.queryByRole('button', { name: 'Make this the main document' })).toBeNull());
		expect(screen.getByText('That branch name is taken or the branch can no longer be changed.')).toBeTruthy();
	});

	it('BZ148 surfaces the quota error on adopt', async () => {
		resolveBranch.mockRejectedValue(new DriveError({ status: 413, code: 'BZ148', detail: 'space quota exceeded' }));
		render(ResolveDialog, { open: true, branch: branch({ ffEligible: false }), nodeId: 5, fileName: 'Report.xlsx', onClose: vi.fn() });
		await fireEvent.click(screen.getByRole('button', { name: 'Take this branch as a new main version' }));
		await vi.waitFor(() =>
			expect(screen.getByText("This space's storage quota or upload limit was exceeded.")).toBeTruthy(),
		);
	});
});
