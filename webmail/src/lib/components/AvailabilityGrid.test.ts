import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent } from '@testing-library/svelte/svelte5';
import AvailabilityGrid from './AvailabilityGrid.svelte';
import type { BusyInterval, MutualFreeSlot } from '$lib/types/scheduling';
import type { SelectedRoom } from '$lib/stores/scheduling.svelte';

// ── Test data ──

const date = '2026-06-01';
const rangeStart = `${date}T08:00:00Z`;
const rangeEnd = `${date}T17:00:00Z`;

function busy(d: string, s: string, e: string, st: BusyInterval['status'] = 'busy'): BusyInterval {
	return { start: `${d}T${s}:00Z`, end: `${d}T${e}:00Z`, status: st };
}

describe('AvailabilityGrid', () => {
	beforeEach(() => {
		resetStores();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('renders attendee rows', async () => {
		const { container } = await renderAsUser(AvailabilityGrid, {
			attendees: new Map([
				['alice@test.local', []],
				['bob@test.local', []]
			]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[]
		});

		expect(container).toBeTruthy();
		expect(screen.getByText('alice@test.local')).toBeTruthy();
		expect(screen.getByText('bob@test.local')).toBeTruthy();
	});

	it('shows empty state when no attendees', async () => {
		await renderAsUser(AvailabilityGrid, {
			attendees: new Map(),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[]
		});

		expect(screen.getByText('Add attendees to see availability')).toBeTruthy();
	});

	it('renders time column headers', async () => {
		await renderAsUser(AvailabilityGrid, {
			attendees: new Map([['alice@test.local', []]]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[]
		});

		// Should show hour labels (08:00, 09:00, etc.)
		expect(screen.getByText('8 AM')).toBeTruthy();
		expect(screen.getByText('12 PM')).toBeTruthy();
	});

	it('shows color-coded busy blocks for an attendee with intervals', async () => {
		const { container } = await renderAsUser(AvailabilityGrid, {
			attendees: new Map([
				['alice@test.local', [busy(date, '09:00', '10:30', 'busy')]]
			]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[]
		});

		// Free bucket for 08:00-08:30
		const freeCell = container.querySelector('[data-bucket="alice@test.local-08:00"]');
		expect(freeCell).toBeTruthy();
		expect(freeCell!.getAttribute('data-status')).toBe('free');

		// Busy bucket for 09:00-09:30
		const busyCell = container.querySelector('[data-bucket="alice@test.local-09:00"]');
		expect(busyCell).toBeTruthy();
		expect(busyCell!.getAttribute('data-status')).toBe('busy');

		// Busy bucket for 09:30-10:00
		const busyCell2 = container.querySelector('[data-bucket="alice@test.local-09:30"]');
		expect(busyCell2).toBeTruthy();
		expect(busyCell2!.getAttribute('data-status')).toBe('busy');

		// Free after 10:30
		const freeCell2 = container.querySelector('[data-bucket="alice@test.local-10:30"]');
		expect(freeCell2).toBeTruthy();
		expect(freeCell2!.getAttribute('data-status')).toBe('free');
	});

	it('renders room row when selectedRoom is provided', async () => {
		const room: SelectedRoom = {
			id: 'r1',
			name: 'Board Room',
			busyIntervals: [busy(date, '11:00', '12:00')]
		};
		await renderAsUser(AvailabilityGrid, {
			attendees: new Map([['alice@test.local', []]]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: room,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[]
		});

		expect(screen.getByText('Board Room')).toBeTruthy();
	});

	it('shows mutual free slots highlight bar at bottom', async () => {
		const slots: MutualFreeSlot[] = [
			{ start: `${date}T10:00:00Z`, end: `${date}T11:00:00Z`, durationMinutes: 60, attendeeFree: true, roomFree: true }
		];

		await renderAsUser(AvailabilityGrid, {
			attendees: new Map([['alice@test.local', [busy(date, '09:00', '10:00')]]]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: slots
		});

		// Should render the mutual free highlight bar
		expect(screen.getByText('Mutual free')).toBeTruthy();
	});

	it('calls onSlotSelect when a free slot is clicked', async () => {
		const onSlotSelect = vi.fn();

		// Create a contiguous free slot from 10:00-11:00
		const slots: MutualFreeSlot[] = [
			{ start: `${date}T10:00:00Z`, end: `${date}T11:00:00Z`, durationMinutes: 60, attendeeFree: true, roomFree: true }
		];

		const { container } = await renderAsUser(AvailabilityGrid, {
			attendees: new Map([['alice@test.local', [busy(date, '09:00', '10:00')]]]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: slots,
			onSlotSelect
		});

		// Click the mutual-free highlight for 10:00-10:30
		const slotButton = container.querySelector('[data-mutual-free="2026-06-01T10:00:00Z-2026-06-01T11:00:00Z"]');
		expect(slotButton).toBeTruthy();
		await fireEvent.click(slotButton!);

		expect(onSlotSelect).toHaveBeenCalledTimes(1);
		expect(onSlotSelect).toHaveBeenCalledWith(slots[0]);
	});

	it('renders tentative buckets with amber color', async () => {
		const { container } = await renderAsUser(AvailabilityGrid, {
			attendees: new Map([
				['alice@test.local', [busy(date, '09:00', '10:00', 'tentative')]]
			]),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[]
		});

		const tentativeCell = container.querySelector('[data-bucket="alice@test.local-09:00"]');
		expect(tentativeCell).toBeTruthy();
		expect(tentativeCell!.getAttribute('data-status')).toBe('tentative');
	});

	it('shows loading spinner when loading prop is true', async () => {
		await renderAsUser(AvailabilityGrid, {
			attendees: new Map(),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[],
			loading: true
		});

		expect(screen.getByText('Loading availability...')).toBeTruthy();
	});

	it('shows error message when error prop is set', async () => {
		await renderAsUser(AvailabilityGrid, {
			attendees: new Map(),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			mutualFreeSlots: [] as MutualFreeSlot[],
			error: 'Failed to load free/busy data'
		});

		expect(screen.getByText('Failed to load free/busy data')).toBeTruthy();
	});
});
