<!--
	Checkbox — 16px, radius-xs, indigo when checked; indeterminate dash
	for select-all rows. The native input is visually hidden but focusable;
	the visible box is a styled sibling span.
-->
<script lang="ts">
	interface Props {
		/** Checked state; bindable. */
		checked?: boolean;
		/** Dash state for partial selections (e.g. mail list select-all). */
		indeterminate?: boolean;
		disabled?: boolean;
		label?: string;
		/** Accessible label for the <input> when no visible label text is needed (screen-reader only). */
		ariaLabel?: string;
		id?: string;
		class?: string;
		onchange?: (e: Event & { currentTarget: EventTarget & HTMLInputElement }) => void;
	}

	let {
		checked = $bindable(false),
		indeterminate = false,
		disabled = false,
		label,
		ariaLabel,
		id,
		class: className = '',
		onchange
	}: Props = $props();

	let inputEl: HTMLInputElement | undefined = $state();

	// The reference design only draws the dash — the native property must be
	// set too so assistive tech and :indeterminate CSS see the mixed state.
	$effect(() => {
		if (inputEl) inputEl.indeterminate = indeterminate;
	});

	const uid = $props.id();
	const inputId = $derived(id ?? `sj-check-${uid}`);
	const on = $derived(checked || indeterminate);

	function handleChange(e: Event & { currentTarget: EventTarget & HTMLInputElement }) {
		checked = e.currentTarget.checked;
		onchange?.(e);
	}

	function handleClick(e: MouseEvent) {
		if (disabled) e.preventDefault();
	}
</script>

<label
	class="sj-check {className}"
	class:sj-check--on={on}
	class:sj-check--disabled={disabled}
	for={inputId}
>
	<input
		bind:this={inputEl}
		id={inputId}
		type="checkbox"
		{checked}
		{disabled}
		aria-label={ariaLabel}
		onclick={handleClick}
		onchange={disabled ? undefined : handleChange}
	/>
	<span class="sj-check__box" aria-hidden="true">
		{#if indeterminate}
			<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5"><path d="M5 12h14"></path></svg>
		{:else if checked}
			<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5"><path d="M20 6 9 17l-5-5"></path></svg>
		{/if}
	</span>
	{#if label}<span>{label}</span>{/if}
</label>

<style>
	.sj-check {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		user-select: none;
	}
	.sj-check--disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.sj-check__box {
		width: 16px;
		height: 16px;
		flex: none;
		border-radius: var(--radius-xs);
		border: 1.5px solid var(--border-strong);
		background: var(--surface-card);
		display: inline-flex;
		align-items: center;
		justify-content: center;
		color: var(--text-inverse);
		transition:
			background var(--duration-fast) var(--ease-out),
			border-color var(--duration-fast) var(--ease-out);
	}
	.sj-check input {
		position: absolute;
		opacity: 0;
		width: 0;
		height: 0;
	}
	.sj-check input:focus-visible + .sj-check__box {
		box-shadow: var(--focus-ring);
	}
	.sj-check--on .sj-check__box {
		background: var(--accent);
		border-color: var(--accent);
	}
	.sj-check:hover:not(.sj-check--disabled, .sj-check--on) .sj-check__box {
		border-color: var(--gray-500);
	}
</style>
