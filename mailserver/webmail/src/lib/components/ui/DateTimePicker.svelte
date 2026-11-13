<svelte:options runes={true} />

<script lang="ts">
	import { buildTimeSlots, combineDateTime, isFuture, toDateStr, toTimeSlot } from './datetime';

	let {
		value,
		confirmLabel = 'Confirm',
		onConfirm
	}: {
		value?: Date;
		confirmLabel?: string;
		onConfirm: (date: Date) => void;
	} = $props();

	const uid = $props.id();
	const slots = buildTimeSlots();

	// Capture the initial value once at construction time for controlled state.
	// dateStr/timeStr are user-editable state; `value` is the one-time seed.
	const { dateStr: initDate, timeStr: initTime } = (() => {
		const seed = value ?? new Date();
		return { dateStr: toDateStr(seed), timeStr: toTimeSlot(seed) };
	})();

	let dateStr = $state(initDate);
	let timeStr = $state(initTime);
	let error = $state('');

	function confirm() {
		const date = combineDateTime(dateStr, timeStr);
		if (date === null || !isFuture(date)) {
			error = 'Pick a time in the future.';
			return;
		}
		error = '';
		onConfirm(date);
	}
</script>

<div class="sj-dtp">
	<div class="sj-dtp__field">
		<label class="sj-dtp__label" for="{uid}-date">Date</label>
		<input id="{uid}-date" class="sj-dtp__input" type="date" bind:value={dateStr} />
	</div>
	<div class="sj-dtp__field">
		<label class="sj-dtp__label" for="{uid}-time">Time</label>
		<select id="{uid}-time" class="sj-dtp__select" bind:value={timeStr}>
			{#each slots as slot (slot.value)}
				<option value={slot.value}>{slot.label}</option>
			{/each}
		</select>
	</div>
	{#if error}
		<p class="sj-dtp__error" role="alert">{error}</p>
	{/if}
	<button type="button" class="sj-dtp__confirm" onclick={confirm}>{confirmLabel}</button>
</div>

<style>
	.sj-dtp {
		display: flex;
		flex-direction: column;
		gap: 8px;
		min-width: 220px;
		padding: 12px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		font-family: var(--font-sans);
	}
	.sj-dtp__field {
		display: flex;
		flex-direction: column;
		gap: 5px;
	}
	.sj-dtp__label {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.sj-dtp__input,
	.sj-dtp__select {
		height: var(--control-height);
		padding: 0 10px;
		width: 100%;
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		transition: border-color var(--duration-fast) var(--ease-out), box-shadow var(--duration-fast) var(--ease-out);
	}
	.sj-dtp__select {
		cursor: pointer;
	}
	.sj-dtp__input:hover:not(:disabled, :focus),
	.sj-dtp__select:hover:not(:disabled, :focus) {
		border-color: var(--border-strong);
	}
	.sj-dtp__input:focus-visible,
	.sj-dtp__select:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.sj-dtp__error {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--danger-fg);
	}
	.sj-dtp__confirm {
		align-self: flex-end;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		height: var(--control-height-sm);
		padding: 0 8px;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-inverse);
		background: var(--accent);
		border: 1px solid transparent;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: background var(--duration-fast) var(--ease-out);
	}
	.sj-dtp__confirm:hover {
		background: var(--accent-hover);
	}
	.sj-dtp__confirm:active {
		background: var(--accent-active);
	}
	.sj-dtp__confirm:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
