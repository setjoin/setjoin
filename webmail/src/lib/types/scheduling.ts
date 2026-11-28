// Scheduling assistant types for Room Booking Calendar UI (Roadmap 3.4)

/** A busy or free interval on a user/room timeline. */
export interface BusyInterval {
	start: string; // ISO 8601 timestamp
	end: string;   // ISO 8601 timestamp
	status: 'busy' | 'tentative' | 'free';
}

/** Busy intervals keyed by attendee email. */
export interface AttendeeBusy {
	email: string;
	intervals: BusyInterval[];
}

/** Room resource — extends Calendar with room-specific fields. */
export interface Room {
	id: string;
	name: string;
	resourceType: 'room' | 'equipment';
	bookingPolicy: 'auto-accept' | 'manual' | 'decline-conflict';
	capacity?: number;
	location?: string;    // building/floor string
	equipment?: string[]; // e.g. ["projector", "vc", "whiteboard", "phone"]
	color?: string;
}

/** Filters for the RoomFinder component. */
export interface RoomFilter {
	minCapacity: number;
	maxCapacity: number;
	equipment: Set<string>;
	location: string; // building filter string; empty = all
}

/** A computed mutual free slot across all attendees + selected room. */
export interface MutualFreeSlot {
	start: string;    // ISO 8601 timestamp
	end: string;      // ISO 8601 timestamp
	durationMinutes: number;
	attendeeFree: boolean;  // all attendees free
	roomFree: boolean;      // selected room free (true if no room selected)
}

/** Known room equipment options. */
export const ROOM_EQUIPMENT_OPTIONS = ['projector', 'vc', 'whiteboard', 'phone'] as const;
export type RoomEquipment = (typeof ROOM_EQUIPMENT_OPTIONS)[number];

/** Minimum contiguous free slot duration to consider (minutes). */
export const MIN_SLOT_MINUTES = 15;
/** Default meeting duration (minutes). */
export const DEFAULT_DURATION_MINUTES = 30;
/** Default bucket size for the availability grid (minutes). */
export const GRID_BUCKET_MINUTES = 30;
