<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Input, Spinner, EmptyState } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { listResources } from '$lib/stores/calendar';
	import type { CalendarResource, EventAttendee } from '$lib/types/jmap';

	let {
		open = false,
		requiredCapacity = 0,
		onPick,
		onClose
	}: {
		open?: boolean;
		requiredCapacity?: number;
		onPick: (attendee: EventAttendee) => void;
		onClose: () => void;
	} = $props();

	let rooms = $state<CalendarResource[]>([]);
	let loading = $state(false);
	// Seed the capacity filter once from the prop (a plain function read = one-time snapshot).
	const initialCapacity = (() => requiredCapacity)();
	let capacityFilter = $state<number>(initialCapacity);

	$effect(() => {
		if (open) void load();
	});

	async function load() {
		loading = true;
		try {
			rooms = await listResources();
		} finally {
			loading = false;
		}
	}

	const visibleRooms = $derived(
		rooms.filter((r) => !capacityFilter || (r.capacity ?? 0) >= capacityFilter)
	);

	function pick(room: CalendarResource) {
		onPick({
			email: room.email || `calendar-${room.id}@resources`,
			name: room.name,
			role: 'resource'
		});
		onClose();
	}
</script>

<Dialog {open} title={t('calendar.rooms.title')} onClose={onClose}>
	<div class="room-finder">
		<Input
			label={t('calendar.rooms.capacity')}
			type="number"
			min={0}
			value={String(capacityFilter)}
			oninput={(e: Event) => (capacityFilter = Math.max(0, parseInt((e.currentTarget as HTMLInputElement).value, 10) || 0))}
		/>
		{#if loading}
			<div class="rf-loading"><Spinner size={16} label={t('calendar.rooms.title')} /></div>
		{:else if visibleRooms.length === 0}
			<EmptyState title={t('calendar.rooms.none')} />
		{:else}
			<ul class="rf-list">
				{#each visibleRooms as room (room.id)}
					<li class="rf-row">
						<div class="rf-meta">
							<span class="rf-name">{room.name}</span>
							{#if room.capacity != null}
								<span class="rf-cap">{t('calendar.rooms.capacity_label')}: {room.capacity}</span>
							{/if}
						</div>
						<Button variant="secondary" size="sm" onclick={() => pick(room)}>
							{t('calendar.rooms.pick')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	{#snippet footer()}
		<Button variant="secondary" size="md" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<style>
	.room-finder {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		min-width: 22rem;
	}
	.rf-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-4);
	}
	.rf-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.rf-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.rf-meta {
		display: flex;
		flex-direction: column;
	}
	.rf-name {
		font-weight: var(--font-weight-medium);
		color: var(--text-primary);
	}
	.rf-cap {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
</style>
