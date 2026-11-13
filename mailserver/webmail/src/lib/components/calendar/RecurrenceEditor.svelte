<svelte:options runes={true} />

<script lang="ts">
	import { Select, Input } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { WEEKDAYS, type RecurrenceParts, type Freq, type RecurrenceEnd } from '$lib/calendar/rrule';

	let {
		value = null,
		onChange
	}: {
		value?: RecurrenceParts | null;
		onChange: (parts: RecurrenceParts | null) => void;
	} = $props();

	// Local editor state, seeded ONCE from the incoming `value` (this is a controlled-then-
	// local editor: after mount the component owns the working state and emits via onChange).
	// The seed is captured inside a plain function so the prop read is an explicit one-time
	// snapshot (not a reactive dependency).
	function initialSeed(): RecurrenceParts | null {
		return value;
	}
	const seed = initialSeed();
	let freq = $state<Freq | 'none'>(seed ? seed.freq : 'none');
	let interval = $state<number>(seed?.interval ?? 1);
	let byDay = $state<string[]>(seed?.byDay ? [...seed.byDay] : []);
	let endType = $state<RecurrenceEnd['type']>(seed?.end.type ?? 'never');
	let count = $state<number>(seed?.end.type === 'count' ? seed.end.count : 10);
	let until = $state<string>(seed?.end.type === 'until' ? seed.end.until : '');

	function emit() {
		if (freq === 'none') {
			onChange(null);
			return;
		}
		let end: RecurrenceEnd;
		if (endType === 'count') end = { type: 'count', count: Math.max(1, count) };
		// Validate before emission: an "ends on" selection with no date yet (or a
		// cleared date input) must never emit {type:'until', until:''} — a
		// malformed UNTIL silently loses the bound in free/busy expansion. While
		// the date is missing, the honest bound is an explicit 'never'.
		else if (endType === 'until' && until !== '') end = { type: 'until', until };
		else end = { type: 'never' };

		const parts: RecurrenceParts = {
			freq,
			interval: Math.max(1, interval || 1),
			end
		};
		if (freq === 'WEEKLY' && byDay.length > 0) parts.byDay = [...byDay];
		onChange(parts);
	}

	function setFreq(v: string) {
		freq = v as Freq | 'none';
		if (freq !== 'WEEKLY') byDay = [];
		emit();
	}

	function toggleDay(token: string) {
		byDay = byDay.includes(token) ? byDay.filter((d) => d !== token) : [...byDay, token];
		emit();
	}

	const freqOptions = $derived([
		{ value: 'none', label: t('calendar.recurrence.none') },
		{ value: 'DAILY', label: t('calendar.recurrence.daily') },
		{ value: 'WEEKLY', label: t('calendar.recurrence.weekly') },
		{ value: 'MONTHLY', label: t('calendar.recurrence.monthly') },
		{ value: 'YEARLY', label: t('calendar.recurrence.yearly') }
	]);

	const endOptions = $derived([
		{ value: 'never', label: t('calendar.recurrence.ends_never') },
		{ value: 'count', label: t('calendar.recurrence.ends_after') },
		{ value: 'until', label: t('calendar.recurrence.ends_on') }
	]);
</script>

<div class="recurrence-editor">
	<Select label={t('calendar.recurrence.repeat')} value={freq} options={freqOptions}
		onchange={(e: Event) => setFreq((e.currentTarget as HTMLSelectElement).value)} />

	{#if freq !== 'none'}
		<div class="rec-row">
			<Input
				label={t('calendar.recurrence.interval_every')}
				type="number"
				min={1}
				value={String(interval)}
				oninput={(e: Event) => { interval = Math.max(1, parseInt((e.currentTarget as HTMLInputElement).value, 10) || 1); emit(); }}
			/>
		</div>

		{#if freq === 'WEEKLY'}
			<div class="rec-weekdays" role="group" aria-label={t('calendar.recurrence.repeat_on')}>
				<span class="rec-label">{t('calendar.recurrence.repeat_on')}</span>
				<div class="rec-day-buttons">
					{#each WEEKDAYS as day}
						<button
							type="button"
							class="rec-day"
							class:rec-day--on={byDay.includes(day.token)}
							aria-pressed={byDay.includes(day.token)}
							onclick={() => toggleDay(day.token)}
						>{t(day.labelKey)}</button>
					{/each}
				</div>
			</div>
		{/if}

		<div class="rec-row">
			<Select label={t('calendar.recurrence.ends')} value={endType} options={endOptions}
				onchange={(e: Event) => { endType = (e.currentTarget as HTMLSelectElement).value as RecurrenceEnd['type']; emit(); }} />
			{#if endType === 'count'}
				<Input label={t('calendar.recurrence.occurrences')} type="number" min={1}
					value={String(count)}
					oninput={(e: Event) => { count = Math.max(1, parseInt((e.currentTarget as HTMLInputElement).value, 10) || 1); emit(); }} />
			{:else if endType === 'until'}
				<Input label={t('calendar.recurrence.ends_on')} type="date"
					bind:value={until} oninput={emit} />
			{/if}
		</div>
	{/if}
</div>

<style>
	.recurrence-editor {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.rec-row {
		display: flex;
		gap: var(--space-3);
		align-items: flex-end;
	}
	.rec-weekdays {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.rec-label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.rec-day-buttons {
		display: flex;
		gap: var(--space-1);
		flex-wrap: wrap;
	}
	.rec-day {
		min-width: 2.25rem;
		height: 2.25rem;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-default);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.rec-day--on {
		background: var(--accent-default);
		color: var(--text-on-accent);
		border-color: var(--accent-default);
	}
	.rec-day:focus-visible {
		outline: 2px solid var(--accent-default);
		outline-offset: 1px;
	}
</style>
