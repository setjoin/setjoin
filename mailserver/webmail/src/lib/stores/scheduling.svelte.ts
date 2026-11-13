// SchedulingStore — client-side scheduling assistant state (Roadmap 3.4)
// Uses Svelte 5 $state runes. All mutual free-slot computation is client-side.

import type {
	BusyInterval,
	MutualFreeSlot,
	RoomFilter
} from '$lib/types/scheduling';
import { MIN_SLOT_MINUTES, DEFAULT_DURATION_MINUTES, GRID_BUCKET_MINUTES } from '$lib/types/scheduling';

// ── Types ──

export interface TimeRange {
	start: string; // ISO 8601
	end: string;   // ISO 8601
}

export interface SelectedRoom {
	id: string;
	name: string;
	busyIntervals: BusyInterval[];
}

export interface SchedulingState {
	attendees: Map<string, BusyInterval[]>;
	timeRange: TimeRange;
	selectedRoom: SelectedRoom | null;
	durationMinutes: number;
	roomFilters: RoomFilter;
}

export interface BucketSlot {
	start: string;
	end: string;
	status: 'free' | 'busy' | 'tentative';
}

// ── Helpers ──

/** Format a Date as ISO 8601 without milliseconds (e.g. 2026-06-01T08:00:00Z). */
function isoNoMs(d: Date): string {
	const y = d.getUTCFullYear();
	const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
	const day = String(d.getUTCDate()).padStart(2, '0');
	const h = String(d.getUTCHours()).padStart(2, '0');
	const mi = String(d.getUTCMinutes()).padStart(2, '0');
	const s = String(d.getUTCSeconds()).padStart(2, '0');
	return `${y}-${mo}-${day}T${h}:${mi}:${s}Z`;
}

// ── Pure Algorithm Functions ──

/** Merge overlapping BusyInterval[] into a minimal sorted list.
 *  Treats tentative as busy for conflict purposes. */
export function mergeIntervals(intervals: BusyInterval[]): BusyInterval[] {
	if (intervals.length === 0) return [];

	const sorted = [...intervals].sort((a, b) => a.start.localeCompare(b.start));
	const merged: BusyInterval[] = [{ ...sorted[0] }];

	for (let i = 1; i < sorted.length; i++) {
		const last = merged[merged.length - 1];
		const cur = sorted[i];

		if (cur.start <= last.end) {
			// Overlapping or adjacent — extend
			if (cur.end > last.end) {
				last.end = cur.end;
			}
			// Busy status wins over tentative
			if (cur.status === 'busy' || last.status === 'busy') {
				last.status = 'busy';
			}
		} else {
			merged.push({ ...cur });
		}
	}

	return merged;
}

/**
 * Split a time range into fixed-size buckets and mark each bucket
 * as free, busy, or tentative based on the provided merged busy intervals.
 */
export function toBuckets(
	busyIntervals: BusyInterval[],
	rangeStart: string,
	rangeEnd: string,
	bucketMinutes: number = GRID_BUCKET_MINUTES
): BucketSlot[] {
	const merged = mergeIntervals(busyIntervals);
	const buckets: BucketSlot[] = [];
	const bucketMs = bucketMinutes * 60 * 1000;
	const startTime = new Date(rangeStart).getTime();
	const endTime = new Date(rangeEnd).getTime();

	for (let t = startTime; t < endTime; t += bucketMs) {
		const bucketStart = isoNoMs(new Date(t));
		const bucketEnd = isoNoMs(new Date(t + bucketMs));

		let status: BucketSlot['status'] = 'free';

		for (const interval of merged) {
			const ivStart = new Date(interval.start).getTime();
			const ivEnd = new Date(interval.end).getTime();

			// Bucket overlaps busy interval if bucket start < iv end AND bucket end > iv start
			if (t < ivEnd && t + bucketMs > ivStart) {
				status = interval.status === 'tentative' ? 'tentative' : 'busy';
				break;
			}
		}

		buckets.push({ start: bucketStart, end: bucketEnd, status });
	}

	return buckets;
}

/**
 * Compute mutual free slots across all attendees and the selected room.
 * Returns contiguous MutualFreeSlot entries (grouped by same free status).
 *
 * Algorithm:
 *  1. Union all busy intervals from all attendees into one merged set.
 *  2. Same for the selected room (if any).
 *  3. Walk 30-min buckets: a bucket is attendeeFree if no attendee busy overlap,
 *     roomFree if no room busy overlap (or no room selected).
 *  4. Group consecutive buckets of the same status into MutualFreeSlot entries.
 *  5. Discard slots shorter than 15 min.
 */
export function computeMutualFree(state: SchedulingState): MutualFreeSlot[] {
	const { attendees, timeRange, selectedRoom } = state;
	const bucketMinutes = GRID_BUCKET_MINUTES;

	// Union all attendee busy intervals
	const allAttendeeBusy: BusyInterval[] = [];
	for (const intervals of attendees.values()) {
		allAttendeeBusy.push(...intervals);
	}
	const mergedAttendeeBusy = mergeIntervals(allAttendeeBusy);

	// Room busy intervals
	const roomBusy = selectedRoom?.busyIntervals ?? [];
	const mergedRoomBusy = roomBusy.length > 0 ? mergeIntervals(roomBusy) : [];

	// Build continuum buckets
	const bucketMs = bucketMinutes * 60 * 1000;
	const startTime = new Date(timeRange.start).getTime();
	const endTime = new Date(timeRange.end).getTime();
	const totalBuckets = Math.floor((endTime - startTime) / bucketMs);

	if (totalBuckets <= 0) return [];

	// Precompute bucket-level flags
	const bucketFree: { attendeeFree: boolean; roomFree: boolean }[] = [];

	for (let i = 0; i < totalBuckets; i++) {
		const t = startTime + i * bucketMs;
		const bt = t + bucketMs;

		let attendeeFree = true;
		for (const iv of mergedAttendeeBusy) {
			const ivStart = new Date(iv.start).getTime();
			const ivEnd = new Date(iv.end).getTime();
			if (t < ivEnd && bt > ivStart) {
				attendeeFree = false;
				break;
			}
		}

		let roomFree = true;
		if (selectedRoom) {
			for (const iv of mergedRoomBusy) {
				const ivStart = new Date(iv.start).getTime();
				const ivEnd = new Date(iv.end).getTime();
				if (t < ivEnd && bt > ivStart) {
					roomFree = false;
					break;
				}
			}
		}

		bucketFree.push({ attendeeFree, roomFree });
	}

	// Group contiguous same-status buckets into MutualFreeSlot
	const slots: MutualFreeSlot[] = [];
	let runStart = -1;
	let prevAttendeeFree = false;
	let prevRoomFree = false;

	for (let i = 0; i <= bucketFree.length; i++) {
		const cur = i < bucketFree.length ? bucketFree[i] : null;

		if (runStart === -1) {
			// Start a potential run
			runStart = i;
			if (cur) {
				prevAttendeeFree = cur.attendeeFree;
				prevRoomFree = cur.roomFree;
			}
			continue;
		}

		// Check if current bucket has same free status as the previous
		const sameStatus =
			cur !== null &&
			cur.attendeeFree === prevAttendeeFree &&
			cur.roomFree === prevRoomFree;

		if (sameStatus) {
			continue; // extend the run
		}

		// End the run: [runStart, i)
		const runEnd = i;
		const durMinutes = (runEnd - runStart) * bucketMinutes;

		// Only emit if duration >= MIN_SLOT_MINUTES (15 min)
		if (durMinutes >= MIN_SLOT_MINUTES) {
			const slotStart = isoNoMs(new Date(startTime + runStart * bucketMs));
			const slotEnd = isoNoMs(new Date(startTime + runEnd * bucketMs));
			slots.push({
				start: slotStart,
				end: slotEnd,
				durationMinutes: durMinutes,
				attendeeFree: prevAttendeeFree,
				roomFree: prevRoomFree
			});
		}

		// Start a new run
		runStart = i;
		if (cur) {
			prevAttendeeFree = cur.attendeeFree;
			prevRoomFree = cur.roomFree;
		}
	}

	return slots;
}

/** Generate a default time range centered on today, 08:00–18:00 local. */
function defaultTimeRange(): TimeRange {
	const now = new Date();
	const start = new Date(now);
	start.setHours(8, 0, 0, 0);
	const end = new Date(now);
	end.setHours(18, 0, 0, 0);
	return { start: start.toISOString(), end: end.toISOString() };
}

export {
	MIN_SLOT_MINUTES,
	DEFAULT_DURATION_MINUTES,
	GRID_BUCKET_MINUTES
};

// ── SchedulingStore (Svelte 5 $state rune class) ──

export class SchedulingStore {
	// ── $state fields ──
	attendees: Map<string, BusyInterval[]> = $state(new Map());
	timeRange: TimeRange = $state(defaultTimeRange());
	selectedRoom: SelectedRoom | null = $state(null);
	durationMinutes: number = $state(DEFAULT_DURATION_MINUTES);
	roomFilters: RoomFilter = $state({
		minCapacity: 0,
		maxCapacity: 1000,
		equipment: new Set(),
		location: ''
	});
	loading: boolean = $state(false);
	error: string = $state('');

	// ── Derived ──
	get mutualFreeSlots(): MutualFreeSlot[] {
		return computeMutualFree(this as unknown as SchedulingState);
	}

	// ── Actions ──

	addAttendee(email: string): void {
		if (this.attendees.has(email)) return;
		this.attendees.set(email, []);
	}

	removeAttendee(email: string): void {
		this.attendees.delete(email);
	}

	setBusyIntervals(email: string, intervals: BusyInterval[]): void {
		if (!this.attendees.has(email)) return;
		this.attendees.set(email, intervals);
	}

	setTimeRange(start: string, end: string): void {
		this.timeRange = { start, end };
	}

	selectRoom(id: string, name: string, busyIntervals: BusyInterval[]): void {
		this.selectedRoom = { id, name, busyIntervals };
	}

	clearRoom(): void {
		this.selectedRoom = null;
	}

	setRoomFilter<K extends keyof RoomFilter>(key: K, value: RoomFilter[K]): void {
		if (key === 'minCapacity' && typeof value === 'number' && value < 0) {
			this.roomFilters.minCapacity = 0;
		} else if (key === 'maxCapacity' && typeof value === 'number' && value <= 0) {
			this.roomFilters.maxCapacity = 1000;
		} else {
			(this.roomFilters as unknown as Record<string, unknown>)[key] = value;
		}
	}

	toggleEquipment(equip: string): void {
		const eq = this.roomFilters.equipment;
		if (eq.has(equip)) {
			eq.delete(equip);
		} else {
			eq.add(equip);
		}
	}

	reset(): void {
		this.attendees = new Map();
		this.timeRange = defaultTimeRange();
		this.selectedRoom = null;
		this.durationMinutes = DEFAULT_DURATION_MINUTES;
		this.roomFilters = {
			minCapacity: 0,
			maxCapacity: 1000,
			equipment: new Set(),
			location: ''
		};
		this.loading = false;
		this.error = '';
	}
}
