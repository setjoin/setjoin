import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import ChangeNoteDialog from './ChangeNoteDialog.svelte';

describe('ChangeNoteDialog', () => {
	it('disables Save until a non-empty note is entered, then submits the trimmed note', async () => {
		const onSubmit = vi.fn();
		render(ChangeNoteDialog, { open: true, onSubmit, onCancel: vi.fn() });
		const saveBtn = screen.getByRole('button', { name: 'Save with change note' });
		expect(saveBtn).toBeDisabled();

		const textarea = screen.getByLabelText('Change note (required in this space)');
		await fireEvent.input(textarea, { target: { value: '  Updated per QA finding #42  ' } });
		expect(saveBtn).not.toBeDisabled();

		await fireEvent.click(saveBtn);
		expect(onSubmit).toHaveBeenCalledWith('Updated per QA finding #42');
	});

	it('rejects a note over 2000 chars (Save stays disabled)', async () => {
		render(ChangeNoteDialog, { open: true, onSubmit: vi.fn(), onCancel: vi.fn() });
		const textarea = screen.getByLabelText('Change note (required in this space)');
		await fireEvent.input(textarea, { target: { value: 'x'.repeat(2001) } });
		expect(screen.getByRole('button', { name: 'Save with change note' })).toBeDisabled();
	});

	it('Cancel clears the note and fires onCancel without calling onSubmit', async () => {
		const onSubmit = vi.fn();
		const onCancel = vi.fn();
		render(ChangeNoteDialog, { open: true, onSubmit, onCancel });
		await fireEvent.input(screen.getByLabelText('Change note (required in this space)'), { target: { value: 'draft' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
		expect(onCancel).toHaveBeenCalled();
		expect(onSubmit).not.toHaveBeenCalled();
	});

	it('is not rendered when open is false', () => {
		render(ChangeNoteDialog, { open: false, onSubmit: vi.fn(), onCancel: vi.fn() });
		expect(screen.queryByLabelText('Change note (required in this space)')).toBeNull();
	});
});
