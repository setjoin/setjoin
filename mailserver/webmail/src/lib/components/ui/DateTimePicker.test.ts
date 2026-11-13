import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import DateTimePicker from './DateTimePicker.svelte';

describe('DateTimePicker', () => {
	it('renders a labelled date input and 48 half-hour time slots', () => {
		render(DateTimePicker, { onConfirm: vi.fn() });
		const date = screen.getByLabelText('Date') as HTMLInputElement;
		expect(date.type).toBe('date');
		const time = screen.getByLabelText('Time') as HTMLSelectElement;
		expect(time.options.length).toBe(48);
		expect(time.options[0].value).toBe('00:00');
		expect(time.options[47].value).toBe('23:30');
	});

	it('rejects past datetimes with inline danger text and does not confirm', async () => {
		const onConfirm = vi.fn();
		render(DateTimePicker, { onConfirm });
		await fireEvent.input(screen.getByLabelText('Date'), { target: { value: '2001-01-01' } });
		await fireEvent.change(screen.getByLabelText('Time'), { target: { value: '08:00' } });
		await fireEvent.click(screen.getByText('Confirm'));
		expect(onConfirm).not.toHaveBeenCalled();
		expect(screen.getByRole('alert').textContent).toBe('Pick a time in the future.');
	});

	it('emits a single Date for a future selection and clears the error', async () => {
		const onConfirm = vi.fn();
		render(DateTimePicker, { onConfirm });
		await fireEvent.input(screen.getByLabelText('Date'), { target: { value: '2001-01-01' } });
		await fireEvent.click(screen.getByText('Confirm'));
		expect(screen.queryByRole('alert')).toBeTruthy();

		await fireEvent.input(screen.getByLabelText('Date'), { target: { value: '2099-01-15' } });
		await fireEvent.change(screen.getByLabelText('Time'), { target: { value: '08:30' } });
		await fireEvent.click(screen.getByText('Confirm'));
		expect(onConfirm).toHaveBeenCalledTimes(1);
		const d = onConfirm.mock.calls[0][0] as Date;
		expect(d.getFullYear()).toBe(2099);
		expect(d.getMonth()).toBe(0);
		expect(d.getDate()).toBe(15);
		expect(d.getHours()).toBe(8);
		expect(d.getMinutes()).toBe(30);
		expect(screen.queryByRole('alert')).toBeNull();
	});

	it('uses a custom confirm label when given', () => {
		render(DateTimePicker, { onConfirm: vi.fn(), confirmLabel: 'Schedule' });
		expect(screen.getByText('Schedule')).toBeTruthy();
	});
});
