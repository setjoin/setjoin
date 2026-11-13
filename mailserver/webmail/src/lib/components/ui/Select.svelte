<!--
	Select — styled native dropdown. Same field metrics as Input
	(32px height, radius-sm, indigo focus). Custom caret, appearance: none.
	Pass `options` as strings or {value,label}, or <option> children.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLSelectAttributes } from 'svelte/elements';
	import { normalizeOptions, type SelectOption } from './types';

	interface Props extends Omit<HTMLSelectAttributes, 'value'> {
		/** Field label rendered above the select, associated via for/id. */
		label?: string;
		/** Options as strings or {value,label}; alternatively pass <option> children. */
		options?: Array<string | SelectOption>;
		/** Selected value; bindable. Pass an initial value that matches an option. */
		value?: string;
		/** Fallback <option> elements used when `options` is empty. */
		children?: Snippet;
	}

	let {
		label,
		options = [],
		value = $bindable(''),
		id,
		children,
		class: className = '',
		...rest
	}: Props = $props();

	const uid = $props.id();
	const selectId = $derived(id ?? `sj-select-${uid}`);
	const opts = $derived(normalizeOptions(options));
</script>

<div class="sj-select-wrap">
	{#if label}
		<label class="sj-select-wrap__label" for={selectId}>{label}</label>
	{/if}
	<select {...rest} id={selectId} class="sj-select {className}" bind:value>
		{#if opts.length > 0}
			{#each opts as o (o.value)}
				<option value={o.value}>{o.label}</option>
			{/each}
		{:else if children}
			{@render children()}
		{/if}
	</select>
	<svg
		class="sj-select-caret"
		width="14"
		height="14"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
		aria-hidden="true"><path d="m6 9 6 6 6-6"></path></svg
	>
</div>

<style>
	.sj-select-wrap {
		position: relative;
		display: flex;
		flex-direction: column;
		gap: 5px;
		font-family: var(--font-sans);
	}
	.sj-select-wrap__label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-select {
		appearance: none;
		height: var(--control-height);
		padding: 0 28px 0 10px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		width: 100%;
		cursor: pointer;
		transition:
			border-color var(--duration-fast) var(--ease-out),
			box-shadow var(--duration-fast) var(--ease-out);
	}
	.sj-select:hover:not(:disabled, :focus-visible) {
		border-color: var(--border-strong);
	}
	.sj-select:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.sj-select:disabled {
		background: var(--surface-sunken);
		color: var(--text-disabled);
		cursor: not-allowed;
	}
	.sj-select-caret {
		position: absolute;
		right: 9px;
		bottom: 9px;
		pointer-events: none;
		color: var(--text-tertiary);
	}
</style>
