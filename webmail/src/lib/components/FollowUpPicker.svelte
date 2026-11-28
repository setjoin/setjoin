<svelte:options runes={true} />

<script lang="ts" module>
	export interface FollowUpSelection {
		dueAt: Date;
		reminderAt: Date | null;
	}

	/** Today at 17:00 local. */
	function todayPreset(): Date {
		const d = new Date();
		d.setHours(17, 0, 0, 0);
		return d;
	}

	/** Tomorrow at 09:00 local. */
	function tomorrowPreset(): Date {
		const d = new Date();
		d.setDate(d.getDate() + 1);
		d.setHours(9, 0, 0, 0);
		return d;
	}

	/** This week = the coming Friday at 17:00 (or today if already Friday/later in week). */
	function thisWeekPreset(): Date {
		const d = new Date();
		const day = d.getDay(); // 0=Sun … 5=Fri
		const delta = (5 - day + 7) % 7; // days until next Friday (0 if today is Friday)
		d.setDate(d.getDate() + delta);
		d.setHours(17, 0, 0, 0);
		return d;
	}
</script>

<script lang="ts">
	import { DateTimePicker, Switch } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		onSelect,
		onClose,
	}: { onSelect: (sel: FollowUpSelection) => void; onClose?: () => void } = $props();

	/** Reminder toggle — when on, the reminder fires at the due instant (A6 fires it). */
	let remind = $state(true);
	let showCustom = $state(false);

	function emit(dueAt: Date) {
		onSelect({ dueAt, reminderAt: remind ? dueAt : null });
	}

	function handleCustomConfirm(date: Date) {
		emit(date);
		showCustom = false;
	}

	function handleClick(e: MouseEvent) {
		e.stopPropagation();
	}

	function handleKeydown(e: KeyboardEvent) {
		e.stopPropagation();
		if (e.key === 'Escape') {
			e.preventDefault();
			onClose?.();
		}
	}
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
	class="sj-followup"
	role="group"
	aria-label={t('triage.followup.title')}
	onclick={handleClick}
	onkeydown={handleKeydown}
>
	<div class="sj-followup__header">{t('triage.followup.title')}</div>

	<button class="sj-followup__item" onclick={() => emit(todayPreset())}>
		{t('triage.followup.today')}
	</button>
	<button class="sj-followup__item" onclick={() => emit(tomorrowPreset())}>
		{t('triage.followup.tomorrow')}
	</button>
	<button class="sj-followup__item" onclick={() => emit(thisWeekPreset())}>
		{t('triage.followup.this_week')}
	</button>

	<button
		class="sj-followup__item sj-followup__custom-toggle"
		onclick={() => (showCustom = !showCustom)}
	>
		{t('triage.followup.custom')}
	</button>

	{#if showCustom}
		<div class="sj-followup__custom">
			<DateTimePicker confirmLabel={t('triage.follow_up')} onConfirm={handleCustomConfirm} />
		</div>
	{/if}

	<div class="sj-followup__reminder">
		<Switch bind:checked={remind} label={t('triage.followup.reminder')} />
	</div>
</div>

<style>
	.sj-followup {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		padding: 4px;
		width: 220px;
	}

	.sj-followup__header {
		font-size: var(--text-2xs);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		font-weight: var(--weight-semibold);
		padding: 6px 8px 4px;
	}

	.sj-followup__item {
		display: block;
		width: 100%;
		text-align: left;
		border: none;
		background: none;
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		padding: 7px 8px;
		border-radius: var(--radius-sm);
	}

	.sj-followup__item:hover {
		background: var(--surface-hover);
	}

	.sj-followup__item:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-followup__custom-toggle {
		border-top: 1px solid var(--border-default);
		margin-top: 4px;
		padding-top: 9px;
		color: var(--text-secondary);
	}

	.sj-followup__custom {
		padding: 8px 0 0;
	}

	.sj-followup__reminder {
		border-top: 1px solid var(--border-default);
		margin-top: 4px;
		padding: 9px 8px 6px;
	}
</style>
