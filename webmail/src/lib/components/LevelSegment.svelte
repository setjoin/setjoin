<svelte:options runes={true} />

<!--
	LevelSegment — the 无/闲忙/详细 sharing-granularity segmented control
	(spec 2026-06-27-sharing-delegation-design.md §6-A / §7). A WAI-ARIA
	radiogroup with roving tabindex + arrow-key nav; selecting follows focus
	(standard radio behavior). Shared by ShareCalendarDialog and the admin
	Sharing console.
-->

<script lang="ts">
	import { t } from '$lib/i18n';
	import type { SharingLevel } from '$lib/api/sharing';

	let {
		value,
		onChange,
		label,
		disabled = false
	}: {
		value: SharingLevel;
		onChange: (level: SharingLevel) => void;
		/** Accessible group label. */
		label: string;
		disabled?: boolean;
	} = $props();

	const LEVELS: SharingLevel[] = ['none', 'freebusy', 'read'];

	let buttons: (HTMLButtonElement | null)[] = $state([null, null, null]);

	function select(level: SharingLevel) {
		if (!disabled && level !== value) onChange(level);
	}

	function onKeydown(e: KeyboardEvent, idx: number) {
		let next = -1;
		if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (idx + 1) % LEVELS.length;
		else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (idx + LEVELS.length - 1) % LEVELS.length;
		else if (e.key === 'Home') next = 0;
		else if (e.key === 'End') next = LEVELS.length - 1;
		if (next === -1) return;
		e.preventDefault();
		buttons[next]?.focus();
		select(LEVELS[next]);
	}
</script>

<div class="sj-level-seg" role="radiogroup" aria-label={label}>
	{#each LEVELS as level, idx (level)}
		<button
			type="button"
			role="radio"
			class="sj-level-seg__opt"
			class:sj-level-seg__opt--on={value === level}
			aria-checked={value === level}
			tabindex={value === level ? 0 : -1}
			{disabled}
			bind:this={buttons[idx]}
			onclick={() => select(level)}
			onkeydown={(e) => onKeydown(e, idx)}
		>
			{t(`sharing.level.${level}`)}
		</button>
	{/each}
</div>

<style>
	.sj-level-seg {
		display: inline-flex;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		overflow: hidden;
		background: var(--surface-sunken);
	}
	.sj-level-seg__opt {
		min-height: 32px;
		padding: 0 var(--space-3);
		border: none;
		background: transparent;
		font-size: var(--text-sm);
		font-family: var(--font-sans);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.sj-level-seg__opt + .sj-level-seg__opt {
		border-left: 1px solid var(--border-default);
	}
	.sj-level-seg__opt:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		position: relative;
		z-index: 1;
	}
	.sj-level-seg__opt--on {
		background: var(--surface-card);
		color: var(--text-primary);
		font-weight: var(--weight-medium);
	}
	.sj-level-seg__opt:disabled {
		opacity: 0.5;
		cursor: default;
	}

	@media (pointer: coarse) {
		.sj-level-seg__opt {
			min-height: 44px;
		}
	}
</style>
