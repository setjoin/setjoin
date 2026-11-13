import { describe, it, expect } from 'vitest';
import {
	SchedulingStore,
	toBuckets,
	computeMutualFree,
	mergeIntervals,
	type SchedulingState
} from './scheduling.svelte';
import type { BusyInterval, MutualFreeSlot } from '$lib/types/scheduling';

// ── Helpers ──

/** Create a BusyInterval from HH:MM times on a given date. */
function busy(
	date: string,
	startHHMM: string,
	endHHMM: string,
	status: BusyInterval['status'] = 'busy'
): BusyInterval {
	return {
		start: `${date}T${startHHMM}:00Z`,
		end: `${date}T${endHHMM}:00Z`,
		status
	};
}

// ── mergeIntervals ──

describe('mergeIntervals', () => {
	it('returns empty array for empty input', () => {
		expect(mergeIntervals([])).toEqual([]);
	});

	it('returns single interval unchanged', () => {
		const intervals: BusyInterval[] = [busy('2026-06-01', '09:00', '10:00')];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(1);
		expect(merged[0].start).toBe('2026-06-01T09:00:00Z');
		expect(merged[0].end).toBe('2026-06-01T10:00:00Z');
	});

	it('merges overlapping intervals', () => {
		const intervals: BusyInterval[] = [
			busy('2026-06-01', '09:00', '10:00'),
			busy('2026-06-01', '09:30', '10:30')
		];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(1);
		expect(merged[0].start).toBe('2026-06-01T09:00:00Z');
		expect(merged[0].end).toBe('2026-06-01T10:30:00Z');
	});

	it('merges adjacent intervals (touching)', () => {
		const intervals: BusyInterval[] = [
			busy('2026-06-01', '09:00', '10:00'),
			busy('2026-06-01', '10:00', '11:00')
		];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(1);
		expect(merged[0].end).toBe('2026-06-01T11:00:00Z');
	});

	it('keeps non-overlapping intervals separate', () => {
		const intervals: BusyInterval[] = [
			busy('2026-06-01', '09:00', '10:00'),
			busy('2026-06-01', '11:00', '12:00')
		];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(2);
	});

	it('merges a chain of multiple overlapping intervals', () => {
		const intervals: BusyInterval[] = [
			busy('2026-06-01', '08:00', '09:30'),
			busy('2026-06-01', '09:00', '10:00'),
			busy('2026-06-01', '10:30', '11:00')
		];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(2);
		expect(merged[0].start).toBe('2026-06-01T08:00:00Z');
		expect(merged[0].end).toBe('2026-06-01T10:00:00Z');
		expect(merged[1].start).toBe('2026-06-01T10:30:00Z');
		expect(merged[1].end).toBe('2026-06-01T11:00:00Z');
	});

	it('handles unsorted input', () => {
		const intervals: BusyInterval[] = [
			busy('2026-06-01', '11:00', '12:00'),
			busy('2026-06-01', '09:00', '10:00')
		];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(2);
		expect(merged[0].start).toBe('2026-06-01T09:00:00Z');
	});

	it('merges tentative status as busy', () => {
		const intervals: BusyInterval[] = [
			busy('2026-06-01', '09:00', '10:00', 'tentative'),
			busy('2026-06-01', '09:30', '10:30', 'busy')
		];
		const merged = mergeIntervals(intervals);
		expect(merged).toHaveLength(1);
		expect(merged[0].end).toBe('2026-06-01T10:30:00Z');
	});
});

// ── toBuckets ──

describe('toBuckets', () => {
	const rangeStart = '2026-06-01T08:00:00Z';
	const rangeEnd = '2026-06-01T12:00:00Z';

	it('returns all free when no intervals', () => {
		const buckets = toBuckets([], rangeStart, rangeEnd, 30);
		expect(buckets.length).toBe(8); // 08:00-12:00 in 30-min buckets
		expect(buckets.every((b) => b.status === 'free')).toBe(true);
	});

	it('marks a single busy interval correctly', () => {
		const busyIntervals: BusyInterval[] = [busy('2026-06-01', '09:00', '10:00')];
		const buckets = toBuckets(busyIntervals, rangeStart, rangeEnd, 30);

		// 08:00-08:30 free, 08:30-09:00 free
		expect(buckets[0].status).toBe('free');   // 08:00-08:30
		expect(buckets[1].status).toBe('free');   // 08:30-09:00
		// 09:00-09:30 busy, 09:30-10:00 busy
		expect(buckets[2].status).toBe('busy');   // 09:00-09:30
		expect(buckets[3].status).toBe('busy');   // 09:30-10:00
		// 10:00-10:30 free
		expect(buckets[4].status).toBe('free');   // 10:00-10:30
	});

	it('marks tentative as tentative', () => {
		const intervals: BusyInterval[] = [busy('2026-06-01', '09:00', '10:00', 'tentative')];
		const buckets = toBuckets(intervals, rangeStart, rangeEnd, 30);
		expect(buckets[2].status).toBe('tentative');
		expect(buckets[3].status).toBe('tentative');
	});

	it('handles interval starting before range', () => {
		const intervals: BusyInterval[] = [busy('2026-06-01', '07:00', '09:00')];
		const buckets = toBuckets(intervals, rangeStart, rangeEnd, 30);
		// 08:00-08:30 and 08:30-09:00 should be busy
		expect(buckets[0].status).toBe('busy');
		expect(buckets[1].status).toBe('busy');
		// 09:00 onwards should be free
		expect(buckets[2].status).toBe('free');
	});

	it('handles interval ending after range', () => {
		const intervals: BusyInterval[] = [busy('2026-06-01', '11:00', '13:00')];
		const buckets = toBuckets(intervals, rangeStart, rangeEnd, 30);
		// Last two buckets (11:00-11:30, 11:30-12:00) should be busy
		expect(buckets[6].status).toBe('busy');
		expect(buckets[7].status).toBe('busy');
	});

	it('uses custom bucket size (15 min)', () => {
		const intervals: BusyInterval[] = [busy('2026-06-01', '08:00', '08:20')];
		const buckets = toBuckets(intervals, rangeStart, rangeEnd, 15);
		expect(buckets.length).toBe(16); // 4 hours * 4
		expect(buckets[0].status).toBe('busy'); // 08:00-08:15
		expect(buckets[1].status).toBe('busy'); // 08:15-08:30 (partial overlap)
	});
});

// ── computeMutualFree ──

describe('computeMutualFree', () => {
	const date = '2026-06-01';
	const rangeStart = `${date}T08:00:00Z`;
	const rangeEnd = `${date}T18:00:00Z`;

	// Helper to make a minimal SchedulingState
	function state(overrides: Partial<SchedulingState> = {}): SchedulingState {
		return {
			attendees: new Map(),
			timeRange: { start: rangeStart, end: rangeEnd },
			selectedRoom: null,
			durationMinutes: 30,
			roomFilters: {
				minCapacity: 0,
				maxCapacity: 1000,
				equipment: new Set(),
				location: ''
			},
			...overrides
		};
	}

	it('returns one big free slot when no attendees and no room', () => {
		const result = computeMutualFree(state());
		// 10 hours = one contiguous 600-min free block
		expect(result.length).toBe(1);
		expect(result[0].attendeeFree).toBe(true);
		expect(result[0].roomFree).toBe(true);
		expect(result[0].durationMinutes).toBe(600);
	});

	it('returns non-free slot when attendee is busy all day', () => {
		const s = state({
			attendees: new Map([
				['alice@test.local', [busy(date, '08:00', '18:00')]]
			])
		});
		const result = computeMutualFree(s);
		expect(result.every((s) => !s.attendeeFree)).toBe(true);
	});

	it('finds free slots between busy intervals for single attendee', () => {
		// Busy 09:00-10:00 and 11:00-12:00
		// Free: 08:00-09:00 (60 min), 10:00-11:00 (60 min), 12:00-18:00 (360 min)
		const s = state({
			attendees: new Map([
				['alice@test.local', [
					busy(date, '09:00', '10:00'),
					busy(date, '11:00', '12:00')
				]]
			])
		});
		const result = computeMutualFree(s);
		const freeSlots = result.filter((s) => s.attendeeFree);

		// Free slot 08:00-09:00
		const slot0800 = freeSlots.find((s) => s.start === `${date}T08:00:00Z`);
		expect(slot0800).toBeDefined();
		expect(slot0800!.durationMinutes).toBe(60);

		// Free slot 10:00-11:00
		const slot1000 = freeSlots.find((s) => s.start === `${date}T10:00:00Z`);
		expect(slot1000).toBeDefined();
		expect(slot1000!.durationMinutes).toBe(60);
	});

	it('computes mutual free for two attendees with overlapping busy', () => {
		// Alice busy 09:00-10:30, Bob busy 10:00-11:30
		// Merged busy: 09:00-11:30 (continuous)
		// Free: 08:00-09:00 (60 min), 11:30-18:00 (390 min)
		const s = state({
			attendees: new Map([
				['alice@test.local', [busy(date, '09:00', '10:30')]],
				['bob@test.local', [busy(date, '10:00', '11:30')]]
			])
		});
		const result = computeMutualFree(s);
		const freeSlots = result.filter((s) => s.attendeeFree);

		// Before 09:00: one contiguous 60-min slot
		const earlyFree = freeSlots.find((s) => s.start === `${date}T08:00:00Z`);
		expect(earlyFree).toBeDefined();
		expect(earlyFree!.durationMinutes).toBe(60);

		// After 11:30: one contiguous 390-min slot
		const lateFree = freeSlots.find((s) => s.start === `${date}T11:30:00Z`);
		expect(lateFree).toBeDefined();
		expect(lateFree!.durationMinutes).toBe(390);
	});

	it('marks slots blocked by room as roomFree=false', () => {
		// Alice free all day. Room busy 14:00-15:00.
		// Slots: 08:00-14:00 free (360), 14:00-15:00 room busy (60),
		//        15:00-18:00 free (180)
		const s = state({
			attendees: new Map([
				['alice@test.local', []]
			]),
			selectedRoom: {
				id: 'room-1',
				name: 'Board Room',
				busyIntervals: [busy(date, '14:00', '15:00')]
			}
		});
		const result = computeMutualFree(s);

		// Free before 14:00
		const before14 = result.find((s) => s.start === `${date}T08:00:00Z`);
		expect(before14).toBeDefined();
		expect(before14!.attendeeFree).toBe(true);
		expect(before14!.roomFree).toBe(true);
		expect(before14!.durationMinutes).toBe(360);

		// Room busy 14:00-15:00
		const at14 = result.find((s) => s.start === `${date}T14:00:00Z`);
		expect(at14).toBeDefined();
		expect(at14!.attendeeFree).toBe(true);
		expect(at14!.roomFree).toBe(false);

		// Free after 15:00
		const after15 = result.find((s) => s.start === `${date}T15:00:00Z`);
		expect(after15).toBeDefined();
		expect(after15!.attendeeFree).toBe(true);
		expect(after15!.roomFree).toBe(true);
		expect(after15!.durationMinutes).toBe(180);
	});

	it('handles half-hour gap correctly', () => {
		// Busy 09:00-10:00 and 10:30-11:00 — 30-min gap at 10:00-10:30
		const s = state({
			attendees: new Map([
				['alice@test.local', [
					busy(date, '09:00', '10:00'),
					busy(date, '10:30', '11:00')
				]]
			])
		});
		const result = computeMutualFree(s);
		const freeSlots = result.filter((s) => s.attendeeFree);

		// The 10:00-10:30 gap is one 30-min contiguous free slot
		const slot10 = freeSlots.find((s) => s.start === `${date}T10:00:00Z`);
		expect(slot10).toBeDefined();
		expect(slot10!.durationMinutes).toBe(30);
	});

	it('handles DST spring-forward (missing hour)', () => {
		const dstStart = '2026-03-08T00:00:00Z';
		const dstEnd = '2026-03-08T23:59:59Z';
		const result = computeMutualFree(state({ timeRange: { start: dstStart, end: dstEnd } }));
		expect(result.length).toBeGreaterThan(0);
		expect(result.every((s) => s.attendeeFree)).toBe(true);
	});

	it('handles DST fall-back (extra hour)', () => {
		const dstStart = '2026-11-01T00:00:00Z';
		const dstEnd = '2026-11-01T23:59:59Z';
		const result = computeMutualFree(state({ timeRange: { start: dstStart, end: dstEnd } }));
		expect(result.length).toBeGreaterThan(0);
	});
});

// ── SchedulingStore (class-based $state rune container) ──

describe('SchedulingStore', () => {
	it('initializes with default values', () => {
		const store = new SchedulingStore();
		expect(store.attendees.size).toBe(0);
		expect(store.selectedRoom).toBeNull();
		expect(store.durationMinutes).toBe(30);
		expect(store.loading).toBe(false);
		expect(store.error).toBe('');
	});

	it('addAttendee adds email and empty busy intervals', () => {
		const store = new SchedulingStore();
		store.addAttendee('alice@test.local');
		expect(store.attendees.has('alice@test.local')).toBe(true);
		expect(store.attendees.get('alice@test.local')).toEqual([]);
	});

	it('addAttendee ignores duplicates', () => {
		const store = new SchedulingStore();
		store.addAttendee('alice@test.local');
		store.addAttendee('alice@test.local');
		expect(store.attendees.size).toBe(1);
	});

	it('removeAttendee removes email', () => {
		const store = new SchedulingStore();
		store.addAttendee('alice@test.local');
		store.addAttendee('bob@test.local');
		store.removeAttendee('alice@test.local');
		expect(store.attendees.has('alice@test.local')).toBe(false);
		expect(store.attendees.has('bob@test.local')).toBe(true);
	});

	it('setBusyIntervals updates intervals for an attendee', () => {
		const store = new SchedulingStore();
		store.addAttendee('alice@test.local');
		store.setBusyIntervals('alice@test.local', [busy('2026-06-01', '09:00', '10:00')]);
		const intervals = store.attendees.get('alice@test.local');
		expect(intervals).toHaveLength(1);
	});

	it('setBusyIntervals is a no-op for unknown email', () => {
		const store = new SchedulingStore();
		store.setBusyIntervals('unknown@test.local', [busy('2026-06-01', '09:00', '10:00')]);
		expect(store.attendees.has('unknown@test.local')).toBe(false);
	});

	it('setTimeRange updates time range', () => {
		const store = new SchedulingStore();
		store.setTimeRange('2026-06-01T08:00:00Z', '2026-06-01T18:00:00Z');
		expect(store.timeRange.start).toBe('2026-06-01T08:00:00Z');
		expect(store.timeRange.end).toBe('2026-06-01T18:00:00Z');
	});

	it('selectRoom sets selected room with busy intervals', () => {
		const store = new SchedulingStore();
		const roomIntervals = [busy('2026-06-01', '09:00', '10:00')];
		store.selectRoom('room-1', 'Board Room', roomIntervals);
		expect(store.selectedRoom).toEqual({
			id: 'room-1',
			name: 'Board Room',
			busyIntervals: roomIntervals
		});
	});

	it('clearRoom deselects room', () => {
		const store = new SchedulingStore();
		store.selectRoom('room-1', 'Board Room', []);
		store.clearRoom();
		expect(store.selectedRoom).toBeNull();
	});

	it('setRoomFilter updates filter and resets to default on invalid values', () => {
		const store = new SchedulingStore();

		store.setRoomFilter('minCapacity', 10);
		expect(store.roomFilters.minCapacity).toBe(10);

		store.setRoomFilter('maxCapacity', 50);
		expect(store.roomFilters.maxCapacity).toBe(50);

		store.setRoomFilter('location', 'Building A');
		expect(store.roomFilters.location).toBe('Building A');

		// Negative minCapacity resets to 0
		store.setRoomFilter('minCapacity', -1);
		expect(store.roomFilters.minCapacity).toBe(0);

		// Zero maxCapacity resets to 1000
		store.setRoomFilter('maxCapacity', 0);
		expect(store.roomFilters.maxCapacity).toBe(1000);
	});

	it('toggleEquipment adds/removes equipment filter', () => {
		const store = new SchedulingStore();

		store.toggleEquipment('projector');
		expect(store.roomFilters.equipment.has('projector')).toBe(true);

		store.toggleEquipment('vc');
		expect(store.roomFilters.equipment.has('vc')).toBe(true);

		// Toggle removes
		store.toggleEquipment('projector');
		expect(store.roomFilters.equipment.has('projector')).toBe(false);
	});

	it('reset restores all defaults', () => {
		const store = new SchedulingStore();
		store.addAttendee('alice@test.local');
		store.setTimeRange('2026-06-01T08:00:00Z', '2026-06-01T18:00:00Z');
		store.setRoomFilter('location', 'Building A');
		store.toggleEquipment('projector');
		store.loading = true;
		store.error = 'some error';

		store.reset();

		expect(store.attendees.size).toBe(0);
		expect(store.selectedRoom).toBeNull();
		expect(store.durationMinutes).toBe(30);
		expect(store.timeRange.start).not.toBe('2026-06-01T08:00:00Z');
		expect(store.roomFilters.location).toBe('');
		expect(store.roomFilters.equipment.size).toBe(0);
		expect(store.loading).toBe(false);
		expect(store.error).toBe('');
	});

	it('mutualFreeSlots derived when attendees change', () => {
		const store = new SchedulingStore();
		store.setTimeRange('2026-06-01T08:00:00Z', '2026-06-01T18:00:00Z');

		// Initial: no busy intervals, so one big contiguous free slot (600 min)
		const initial = store.mutualFreeSlots;
		expect(initial.length).toBe(1);
		expect(initial[0].attendeeFree).toBe(true);

		// Add a busy attendee filling the entire range
		store.addAttendee('alice@test.local');
		store.setBusyIntervals('alice@test.local', [busy('2026-06-01', '08:00', '18:00')]);

		const after = store.mutualFreeSlots;
		expect(after.every((s) => !s.attendeeFree)).toBe(true);
	});
});
