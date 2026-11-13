import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import SnoozePicker from './SnoozePicker.svelte';

describe('SnoozePicker', () => {
	beforeEach(() => {
		// Pin the clock to Saturday June 13, 2026 9:00 AM so
		// snoozePresets() is deterministic. Fake only Date.
		vi.useFakeTimers({ toFake: ['Date'] });
		vi.setSystemTime(new Date(2026, 5, 13, 9, 0, 0)); // Saturday
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('renders a "Snooze until" header', async () => {
		render(SnoozePicker, { onSelect: vi.fn() });
		expect(screen.getByText('Snooze until')).toBeTruthy();
	});

	it('renders the four kit §7 preset buttons from snoozePresets()', async () => {
		render(SnoozePicker, { onSelect: vi.fn() });
		// At 9 AM Saturday (18:00 still future), snoozePresets() returns the four
		// kit presets in order; "This evening" is NOT a kit preset.
		expect(screen.getByText('Later today, 18:00')).toBeTruthy();
		expect(screen.getByText('Tomorrow, 8:00')).toBeTruthy();
		expect(screen.getByText('This weekend, Sat 9:00')).toBeTruthy();
		expect(screen.getByText('Next week, Mon 8:00')).toBeTruthy();
		expect(screen.queryByText('This evening (6 PM)')).toBeNull();
		expect(screen.getByText('Custom')).toBeTruthy();
	});

	it('calls onSelect with 18:00 today when "Later today" is clicked', async () => {
		const onSelect = vi.fn();
		render(SnoozePicker, { onSelect });

		await fireEvent.click(screen.getByText('Later today, 18:00'));

		expect(onSelect).toHaveBeenCalledTimes(1);
		const selectedDate = onSelect.mock.calls[0][0] as Date;
		expect(selectedDate.getTime()).toBeGreaterThan(Date.now());
		expect(selectedDate.getHours()).toBe(18);
	});

	it('calls onSelect with tomorrow 8 AM when "Tomorrow" is clicked', async () => {
		const onSelect = vi.fn();
		render(SnoozePicker, { onSelect });

		await fireEvent.click(screen.getByText('Tomorrow, 8:00'));

		expect(onSelect).toHaveBeenCalledTimes(1);
		const selectedDate = onSelect.mock.calls[0][0] as Date;
		// Sunday June 14
		expect(selectedDate.getDate()).toBe(14);
		expect(selectedDate.getHours()).toBe(8);
	});

	it('shows DateTimePicker when Custom is clicked', async () => {
		render(SnoozePicker, { onSelect: vi.fn() });

		await fireEvent.click(screen.getByText('Custom'));

		// M1 DateTimePicker renders labelled Date and Time fields
		expect(screen.getByLabelText('Date')).toBeTruthy();
		expect(screen.getByLabelText('Time')).toBeTruthy();
		expect(screen.getByText('Snooze')).toBeTruthy(); // confirmLabel
	});

	it('calls onSelect when DateTimePicker confirms a future custom date', async () => {
		const onSelect = vi.fn();
		render(SnoozePicker, { onSelect });

		await fireEvent.click(screen.getByText('Custom'));

		// Pick a far-future date so isFuture() passes
		await fireEvent.input(screen.getByLabelText('Date'), { target: { value: '2099-06-15' } });
		await fireEvent.change(screen.getByLabelText('Time'), { target: { value: '14:30' } });
		await fireEvent.click(screen.getByText('Snooze'));

		expect(onSelect).toHaveBeenCalledTimes(1);
		const selectedDate = onSelect.mock.calls[0][0] as Date;
		expect(selectedDate.getFullYear()).toBe(2099);
		expect(selectedDate.getMonth()).toBe(5);
		expect(selectedDate.getDate()).toBe(15);
		expect(selectedDate.getHours()).toBe(14);
		expect(selectedDate.getMinutes()).toBe(30);
	});

	it('calls onSelect with next Saturday 8 AM when "This weekend" is clicked', async () => {
		const onSelect = vi.fn();
		render(SnoozePicker, { onSelect });

		await fireEvent.click(screen.getByText('This weekend, Sat 9:00'));

		expect(onSelect).toHaveBeenCalledTimes(1);
		const selectedDate = onSelect.mock.calls[0][0] as Date;
		expect(selectedDate.getDay()).toBe(6); // Saturday
		expect(selectedDate.getHours()).toBe(9);
		// Date is in the future (next Saturday, June 20)
		expect(selectedDate.getDate()).toBe(20);
	});

	it('calls onSelect with next Monday 8 AM when "Next week" is clicked', async () => {
		const onSelect = vi.fn();
		render(SnoozePicker, { onSelect });

		await fireEvent.click(screen.getByText('Next week, Mon 8:00'));

		expect(onSelect).toHaveBeenCalledTimes(1);
		const selectedDate = onSelect.mock.calls[0][0] as Date;
		expect(selectedDate.getDay()).toBe(1); // Monday
		expect(selectedDate.getHours()).toBe(8);
		// Next Monday from Saturday June 13 is Monday June 15
		expect(selectedDate.getDate()).toBe(15);
	});

	it('calls onClose when Escape is pressed', async () => {
		const onClose = vi.fn();
		render(SnoozePicker, { onSelect: vi.fn(), onClose });
		const group = document.querySelector('.sj-snooze') as HTMLElement;
		expect(group).toBeTruthy();
		await fireEvent.keyDown(group, { key: 'Escape' });
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('does not throw on Escape when no onClose is provided', async () => {
		render(SnoozePicker, { onSelect: vi.fn() });
		const group = document.querySelector('.sj-snooze') as HTMLElement;
		await fireEvent.keyDown(group, { key: 'Escape' });
		expect(group).toBeTruthy();
	});
});
