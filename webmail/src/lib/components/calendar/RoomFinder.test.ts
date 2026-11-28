import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import RoomFinder from './RoomFinder.svelte';

vi.mock('$lib/stores/calendar', () => ({
	listResources: vi.fn(async () => [
		{ id: 'r1', name: 'Small Room', resourceType: 'room', capacity: 4, bookingPolicy: 'auto-accept' },
		{ id: 'r2', name: 'Large Room', resourceType: 'room', capacity: 12, bookingPolicy: 'decline-conflict' }
	])
}));

describe('RoomFinder', () => {
	beforeEach(() => vi.clearAllMocks());

	it('filters rooms below the required capacity and fires onPick with a resource attendee', async () => {
		const onPick = vi.fn();
		render(RoomFinder, { open: true, requiredCapacity: 8, onPick, onClose: () => {} });

		// Only the capacity-12 room should be selectable; the capacity-4 one is filtered out.
		await waitFor(() => {
			expect(screen.getByText('Large Room')).toBeTruthy();
		});
		expect(screen.queryByText('Small Room')).toBeNull();

		// Click the select button on the Large Room row.
		const pickBtn = screen.getByText('Select').closest('button')!;
		await fireEvent.click(pickBtn);

		expect(onPick).toHaveBeenCalledTimes(1);
		const attendee = onPick.mock.calls[0][0];
		expect(attendee.role).toBe('resource');
		expect(attendee.email).toBeTruthy();
		expect(attendee.name).toBe('Large Room');
	});
});
