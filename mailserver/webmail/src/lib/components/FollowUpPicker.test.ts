import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import FollowUpPicker from './FollowUpPicker.svelte';
import type { FollowUpSelection } from './FollowUpPicker.svelte';

describe('FollowUpPicker (A2)', () => {
	it('emits a Tomorrow-dated due instant', async () => {
		const onSelect = vi.fn<(s: FollowUpSelection) => void>();
		const { getByText } = render(FollowUpPicker, { props: { onSelect, onClose: () => {} } });
		await fireEvent.click(getByText('Tomorrow'));
		expect(onSelect).toHaveBeenCalledTimes(1);
		const arg = onSelect.mock.calls[0][0];
		const tomorrow = new Date();
		tomorrow.setDate(tomorrow.getDate() + 1);
		expect(arg.dueAt.getDate()).toBe(tomorrow.getDate());
	});

	it('emits a Today-dated due instant', async () => {
		const onSelect = vi.fn<(s: FollowUpSelection) => void>();
		const { getByText } = render(FollowUpPicker, { props: { onSelect } });
		await fireEvent.click(getByText('Today'));
		const arg = onSelect.mock.calls[0][0];
		expect(arg.dueAt.getDate()).toBe(new Date().getDate());
	});

	it('includes a reminder instant when the reminder toggle is on (default)', async () => {
		const onSelect = vi.fn<(s: FollowUpSelection) => void>();
		const { getByText } = render(FollowUpPicker, { props: { onSelect } });
		await fireEvent.click(getByText('Today'));
		const arg = onSelect.mock.calls[0][0];
		expect(arg.reminderAt).not.toBeNull();
		expect(arg.reminderAt?.getTime()).toBe(arg.dueAt.getTime());
	});

	it('drops the reminder when the toggle is turned off', async () => {
		const onSelect = vi.fn<(s: FollowUpSelection) => void>();
		const { getByText, getByRole } = render(FollowUpPicker, { props: { onSelect } });
		// Turn the reminder switch off.
		const toggle = getByRole('switch');
		await fireEvent.click(toggle);
		await fireEvent.click(getByText('Today'));
		const arg = onSelect.mock.calls[0][0];
		expect(arg.reminderAt).toBeNull();
	});
});
