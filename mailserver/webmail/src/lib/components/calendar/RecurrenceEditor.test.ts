import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import RecurrenceEditor from './RecurrenceEditor.svelte';
import { buildRrule } from '$lib/calendar/rrule';
import type { RecurrenceParts } from '$lib/calendar/rrule';

describe('RecurrenceEditor', () => {
	it('renders the frequency select with a "does not repeat" option for null value', () => {
		const onChange = vi.fn();
		render(RecurrenceEditor, { value: null, onChange });
		const select = screen.getByLabelText('Repeat') as HTMLSelectElement;
		expect(select).toBeTruthy();
		// The empty/none option must be present.
		expect(Array.from(select.options).some((o) => o.value === 'none')).toBe(true);
	});

	it('composes FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE;UNTIL=… via onChange', async () => {
		let last: RecurrenceParts | null = null;
		const onChange = (p: RecurrenceParts | null) => {
			last = p;
		};
		render(RecurrenceEditor, { value: null, onChange });

		// Pick WEEKLY.
		const freq = screen.getByLabelText('Repeat') as HTMLSelectElement;
		await fireEvent.change(freq, { target: { value: 'WEEKLY' } });

		// Weekday toggles appear; click Mon + Wed.
		await fireEvent.click(screen.getByRole('button', { name: 'Mo' }));
		await fireEvent.click(screen.getByRole('button', { name: 'We' }));

		// Interval = 2.
		const interval = screen.getByLabelText('Every') as HTMLInputElement;
		await fireEvent.input(interval, { target: { value: '2' } });

		// End = until a date.
		const ends = screen.getByLabelText('Ends') as HTMLSelectElement;
		await fireEvent.change(ends, { target: { value: 'until' } });
		const untilInput = screen.getByLabelText('On date') as HTMLInputElement;
		await fireEvent.input(untilInput, { target: { value: '2026-12-31' } });

		expect(last).not.toBeNull();
		expect(buildRrule(last!)).toBe('FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE;UNTIL=20261231T000000Z');
	});

	it('emits null when the frequency is set back to "none"', async () => {
		const onChange = vi.fn();
		render(RecurrenceEditor, {
			value: { freq: 'DAILY', interval: 1, end: { type: 'never' } },
			onChange
		});
		const freq = screen.getByLabelText('Repeat') as HTMLSelectElement;
		await fireEvent.change(freq, { target: { value: 'none' } });
		expect(onChange).toHaveBeenLastCalledWith(null);
	});

	it("never emits an empty UNTIL — selecting 'ends on' without a date emits an explicit 'never'", async () => {
		const onChange = vi.fn();
		render(RecurrenceEditor, { value: null, onChange });

		await fireEvent.change(screen.getByLabelText('Repeat') as HTMLSelectElement, {
			target: { value: 'DAILY' }
		});
		// Select "ends on" but pick NO date yet.
		await fireEvent.change(screen.getByLabelText('Ends') as HTMLSelectElement, {
			target: { value: 'until' }
		});

		const lastCall = onChange.mock.calls.at(-1)?.[0] as RecurrenceParts;
		expect(lastCall.end).toEqual({ type: 'never' });
		// And clearing a picked date degrades to 'never', never {until: ''}.
		const untilInput = screen.getByLabelText('On date') as HTMLInputElement;
		await fireEvent.input(untilInput, { target: { value: '2026-12-31' } });
		await fireEvent.input(untilInput, { target: { value: '' } });
		const cleared = onChange.mock.calls.at(-1)?.[0] as RecurrenceParts;
		expect(cleared.end).toEqual({ type: 'never' });
	});
});
