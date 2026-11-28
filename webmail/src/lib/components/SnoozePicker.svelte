<svelte:options runes={true} />

<script lang="ts">
	import { snoozePresets } from '$lib/stores/tagHelpers';
	import { DateTimePicker } from '$lib/components/ui';

	let { onSelect, onClose }: { onSelect: (date: Date) => void; onClose?: () => void } = $props();

	let showCustom = $state(false);

	const presets = $derived(snoozePresets());

	function handleCustomConfirm(date: Date) {
		onSelect(date);
		showCustom = false;
	}

	function handleClick(e: MouseEvent) {
		// Prevent clicks inside the menu from bubbling to the document-level
		// dismiss listener that the parent (toolbar) may install per kit §7.
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
	class="sj-snooze"
	role="group"
	aria-label="Snooze until"
	onclick={handleClick}
	onkeydown={handleKeydown}
>
	<div class="sj-snooze__header">Snooze until</div>

	{#each presets as preset (preset.label)}
		<button
			class="sj-snooze__item"
			onclick={() => onSelect(preset.date)}
		>
			{preset.label}
		</button>
	{/each}

	<button
		class="sj-snooze__item sj-snooze__custom-toggle"
		onclick={() => (showCustom = !showCustom)}
	>
		Custom
	</button>

	{#if showCustom}
		<div class="sj-snooze__custom">
			<DateTimePicker
				confirmLabel="Snooze"
				onConfirm={handleCustomConfirm}
			/>
		</div>
	{/if}
</div>

<style>
	/* In-flow inside .sj-reading-pane__snooze-dropdown, which positions it. Self-
	   positioning (absolute; right:0) against that zero-width wrapper shot the
	   picker 200px left, into the overflow-clipped message list — unclickable. */
	.sj-snooze {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		padding: 4px;
		width: 200px;
	}

	.sj-snooze__header {
		font-size: var(--text-2xs);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		font-weight: var(--weight-semibold);
		padding: 6px 8px 4px;
	}

	.sj-snooze__item {
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

	.sj-snooze__item:hover {
		background: var(--surface-hover);
	}

	.sj-snooze__item:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-snooze__custom-toggle {
		border-top: 1px solid var(--border-default);
		margin-top: 4px;
		padding-top: 9px;
		color: var(--text-secondary);
	}

	.sj-snooze__custom {
		padding: 8px 0 0;
	}
</style>
