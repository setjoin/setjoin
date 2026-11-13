<svelte:options runes={true} />

<script lang="ts">
	import type { BusyInterval, MutualFreeSlot } from '$lib/types/scheduling';
	import type { SelectedRoom } from '$lib/stores/scheduling.svelte';
	import { toBuckets, type BucketSlot } from '$lib/stores/scheduling.svelte';
	import { GRID_BUCKET_MINUTES } from '$lib/types/scheduling';
	import Icon from './Icon.svelte';

	interface Props {
		attendees: Map<string, BusyInterval[]>;
		timeRange: { start: string; end: string };
		selectedRoom: SelectedRoom | null;
		durationMinutes: number;
		mutualFreeSlots: MutualFreeSlot[];
		loading?: boolean;
		error?: string;
		onSlotSelect?: (slot: MutualFreeSlot) => void;
		onRefresh?: () => void;
	}

	let {
		attendees = new Map(),
		timeRange = { start: '', end: '' },
		selectedRoom = null,
		durationMinutes = 30,
		mutualFreeSlots = [],
		loading = false,
		error = '',
		onSlotSelect = undefined,
		onRefresh = undefined
	}: Props = $props();

	// ── Derived data ──

	interface Row {
		type: 'attendee' | 'room' | 'mutual';
		label: string;
		email?: string;
		buckets: BucketSlot[];
	}

	function formatHour(hour: number): string {
		if (hour === 0) return '12 AM';
		if (hour === 12) return '12 PM';
		if (hour > 12) return `${hour - 12} PM`;
		return `${hour} AM`;
	}

	let rows = $derived.by(() => {
		const result: Row[] = [];

		// Attendee rows
		for (const [email, intervals] of attendees) {
			const buckets = toBuckets(intervals, timeRange.start, timeRange.end, GRID_BUCKET_MINUTES);
			result.push({ type: 'attendee' as const, label: email, email, buckets });
		}

		// Room row (if selected)
		if (selectedRoom) {
			const buckets = toBuckets(
				selectedRoom.busyIntervals,
				timeRange.start,
				timeRange.end,
				GRID_BUCKET_MINUTES
			);
			result.push({ type: 'room' as const, label: selectedRoom.name, buckets });
		}

		return result;
	});

	let timeColumns = $derived.by(() => {
		const cols: { label: string; isoStart: string }[] = [];
		const bucketMs = GRID_BUCKET_MINUTES * 60 * 1000;
		const startMs = new Date(timeRange.start).getTime();
		const endMs = new Date(timeRange.end).getTime();

		for (let t = startMs; t < endMs; t += bucketMs) {
			const d = new Date(t);
			const iso = d.toISOString();
			const hour = d.getUTCHours();
			const label = formatHour(hour);
			cols.push({ label, isoStart: iso });
		}
		return cols;
	});

	/** Build the hour header labels. Show hour label at the first slot of each hour. */
	function hourLabel(colIdx: number): string | null {
		if (colIdx % (60 / GRID_BUCKET_MINUTES) !== 0) return null;
		return timeColumns[colIdx]?.label ?? null;
	}

	/** Build data-bucket attribute for a cell. */
	function bucketKey(rowLabel: string, colIdx: number): string {
		const col = timeColumns[colIdx];
		if (!col) return '';
		// Use HH:MM from ISO for stable keys
		const time = col.isoStart.slice(11, 16);
		return `${rowLabel}-${time}`;
	}

	/** Check if a mutual free slot covers a given column index. */
	function isSlotColumn(slot: MutualFreeSlot, colIdx: number): boolean {
		const col = timeColumns[colIdx];
		if (!col) return false;
		const colStart = new Date(col.isoStart).getTime();
		const colEnd = colStart + GRID_BUCKET_MINUTES * 60 * 1000;
		const slotStart = new Date(slot.start).getTime();
		const slotEnd = new Date(slot.end).getTime();
		return colStart < slotEnd && colEnd > slotStart;
	}

	let slotKey = (s: MutualFreeSlot) => `${s.start}-${s.end}`;

	function statusClass(status: BucketSlot['status']): string {
		switch (status) {
			case 'free': return 'grid-cell--free';
			case 'busy': return 'grid-cell--busy';
			case 'tentative': return 'grid-cell--tentative';
		}
	}

	function cellTitle(rowLabel: string, bucket: BucketSlot): string {
		return `${rowLabel}: ${bucket.status} (${bucket.start.slice(11, 16)} – ${bucket.end.slice(11, 16)})`;
	}
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="availability-grid" role="grid" aria-label="Attendee availability">
	{#if loading}
		<div class="grid-loading" role="status">Loading availability...</div>
	{:else if error}
		<div class="grid-error" role="alert">{error}</div>
	{:else if attendees.size === 0}
		<div class="grid-empty">Add attendees to see availability</div>
	{:else}
		<div class="grid-toolbar">
			<span class="grid-duration">Meeting: {durationMinutes} min</span>
			{#if onRefresh}
				<button class="grid-refresh-btn" onclick={onRefresh} type="button" aria-label="Refresh availability">
					<Icon name="RefreshCw" /> Refresh
				</button>
			{/if}
		</div>

		<div class="grid-scroll">
			<table class="grid-table">
				<thead>
					<tr>
						<th class="grid-label-col" scope="col"></th>
						{#each timeColumns as col, i}
							<th class="grid-time-col" scope="col">
								{hourLabel(i)}
							</th>
						{/each}
					</tr>
				</thead>
				<tbody>
					{#each rows as row (row.label)}
						<tr class="grid-row">
							<td class="grid-row-label">
								<div class="grid-label-text">
									{#if row.type === 'room'}
										<Icon name="DoorOpen" />
									{/if}
									{row.label}
								</div>
							</td>
							{#each row.buckets as bucket, i}
								<td
									class="grid-cell {statusClass(bucket.status)}"
									class:grid-cell--room={row.type === 'room'}
									data-bucket={bucketKey(row.label, i)}
									data-status={bucket.status}
									title={cellTitle(row.label, bucket)}
								></td>
							{/each}
						</tr>
					{/each}

					<!-- Mutual free highlight row -->
					{#if mutualFreeSlots.length > 0}
						<tr class="grid-row grid-row--mutual">
							<td class="grid-row-label">
								<div class="grid-label-text grid-label--mutual">Mutual free</div>
							</td>
							{#each timeColumns as col, i}
								{@const matching = mutualFreeSlots.filter((s) => isSlotColumn(s, i))}
								{@const isFree = matching.length > 0 && matching[0].attendeeFree && matching[0].roomFree}
								{@const clickable = isFree && onSlotSelect !== undefined}
								<td class="grid-cell grid-cell--mutual-free" class:grid-cell--clickable={clickable}>
									{#if isFree && matching[0].durationMinutes >= GRID_BUCKET_MINUTES}
										<button
											type="button"
											class="mutual-slot-btn"
											data-mutual-free={slotKey(matching[0])}
											onclick={() => onSlotSelect?.(matching[0])}
											aria-label="Select free slot {matching[0].start} to {matching[0].end}"
										></button>
									{/if}
								</td>
							{/each}
						</tr>
					{/if}
				</tbody>
			</table>
		</div>
	{/if}
</div>

<style>
	.availability-grid {
		background: var(--surface-card);
		border-radius: var(--radius-md);
		border: 1px solid var(--border-default);
		overflow: hidden;
	}

	.grid-loading, .grid-empty, .grid-error {
		padding: var(--space-6);
		text-align: center;
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}

	.grid-error {
		color: var(--danger-solid);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		margin: var(--space-2);
	}

	.grid-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-default);
		font-size: var(--text-xs);
	}

	.grid-duration {
		color: var(--text-secondary);
		font-weight: 500;
	}

	.grid-refresh-btn {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		padding: var(--space-1) var(--space-2);
		font-size: var(--text-xs);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		cursor: pointer;
		color: var(--text-primary);
	}
	.grid-refresh-btn:hover { background: var(--surface-hover); }
	.grid-refresh-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.grid-scroll {
		overflow: auto;
		max-height: 360px;
	}

	.grid-table {
		border-collapse: collapse;
		width: 100%;
		min-width: 600px;
		table-layout: fixed;
	}

	.grid-label-col {
		width: 140px;
		min-width: 140px;
		position: sticky;
		left: 0;
		background: inherit;
		z-index: 1;
		padding: 0;
	}

	.grid-time-col {
		width: 48px;
		min-width: 48px;
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		text-align: center;
		padding: var(--space-1) 0;
		border-bottom: 1px solid var(--border-default);
	}

	.grid-row-label {
		position: sticky;
		left: 0;
		background: var(--surface-card);
		padding: var(--space-1) var(--space-2);
		border-bottom: 1px solid var(--border-default);
		z-index: 1;
	}

	.grid-label-text {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-xs);
		font-weight: 500;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.grid-label--mutual {
		color: var(--success-solid);
		font-size: var(--text-2xs);
	}

	.grid-cell {
		width: 48px;
		min-width: 48px;
		height: 24px;
		border-right: 1px solid var(--border-subtle);
		border-bottom: 1px solid var(--border-subtle);
		transition: background 0.1s;
	}

	.grid-cell--free {
		background: var(--success-bg);
	}
	.grid-cell--busy {
		background: var(--danger-bg);
	}
	.grid-cell--tentative {
		background: var(--warning-bg);
	}
	.grid-cell--room.grid-cell--busy {
		background: repeating-linear-gradient(
			-45deg,
			var(--danger-bg),
			var(--danger-bg) 3px,
			var(--danger-fg) 3px,
			var(--danger-fg) 6px
		);
	}

	.grid-row--mutual {
		border-top: 2px solid var(--success-solid);
	}

	.grid-cell--mutual-free {
		background: transparent;
		padding: 0;
	}

	.grid-cell--clickable {
		cursor: pointer;
	}

	.mutual-slot-btn {
		display: block;
		width: 100%;
		height: 100%;
		border: none;
		background: var(--success-bg);
		cursor: pointer;
		padding: 0;
		transition: background 0.15s;
	}
	.mutual-slot-btn:hover {
		background: var(--success-solid);
	}
	.mutual-slot-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
