import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import type { QuickStep } from '$lib/types/jmap';

const listQuickSteps = vi.fn();
const saveQuickStep = vi.fn();
const deleteQuickStep = vi.fn();

vi.mock('$lib/jmap/quicksteps', () => ({
	listQuickSteps: (...a: unknown[]) => listQuickSteps(...a),
	saveQuickStep: (...a: unknown[]) => saveQuickStep(...a),
	deleteQuickStep: (...a: unknown[]) => deleteQuickStep(...a),
}));

import QuickStepsPage from './+page.svelte';

const STEPS: QuickStep[] = [
	{ id: '1', name: 'File receipt', icon: 'FileText', position: 0,
	  actions: [{ type: 'mark_read' }, { type: 'categorize', params: { category: 'Receipts' } }] },
	{ id: '2', name: 'To team', icon: 'Forward', position: 1,
	  actions: [{ type: 'forward_to', params: { address: 'team@corp.test' } }] },
];

describe('Quick Steps settings page (A2)', () => {
	beforeEach(() => {
		listQuickSteps.mockResolvedValue(STEPS.map((s) => ({ ...s })));
		saveQuickStep.mockResolvedValue('99');
		deleteQuickStep.mockResolvedValue(undefined);
	});
	afterEach(() => vi.clearAllMocks());

	it('lists existing quick steps by name', async () => {
		render(QuickStepsPage);
		await waitFor(() => expect(screen.getByText('File receipt')).toBeInTheDocument());
		expect(screen.getByText('To team')).toBeInTheDocument();
	});

	it('saves a new quick step with an added action', async () => {
		render(QuickStepsPage);
		await waitFor(() => screen.getByTestId('qs-new-btn'));
		await fireEvent.click(screen.getByTestId('qs-new-btn'));
		await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'Archive it' } });
		await fireEvent.click(screen.getByTestId('qs-add-action'));
		await fireEvent.click(screen.getByTestId('qs-save-btn'));
		await waitFor(() => {
			expect(saveQuickStep).toHaveBeenCalled();
			const arg = saveQuickStep.mock.calls[0][0];
			expect(arg.name).toBe('Archive it');
			expect(arg.actions.length).toBeGreaterThanOrEqual(1);
		});
	});

	it('blocks save when the name is empty', async () => {
		render(QuickStepsPage);
		await waitFor(() => screen.getByTestId('qs-new-btn'));
		await fireEvent.click(screen.getByTestId('qs-new-btn'));
		// New form starts with an empty name + one default action.
		await fireEvent.click(screen.getByTestId('qs-save-btn'));
		await waitFor(() => expect(screen.getByText('Give the quick step a name.')).toBeInTheDocument());
		expect(saveQuickStep).not.toHaveBeenCalled();
	});

	it('deletes a quick step', async () => {
		render(QuickStepsPage);
		await waitFor(() => screen.getByTestId('qs-delete-2'));
		await fireEvent.click(screen.getByTestId('qs-delete-2'));
		await waitFor(() => expect(deleteQuickStep).toHaveBeenCalledWith('2'));
	});
});
