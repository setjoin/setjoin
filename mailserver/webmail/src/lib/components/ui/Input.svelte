<!--
	Input — standard setjoin text field: quiet border, indigo focus ring,
	label / hint / error stack. `mono` for hostnames, IPs, ports, config
	values. `size="lg"` only on login and other hero forms.
-->
<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';
	import type { FieldSize } from './types';

	interface Props extends Omit<HTMLInputAttributes, 'size' | 'value'> {
		/** Field label rendered above the input, associated via for/id. */
		label?: string;
		/** Helper text below the field; replaced by error when set. */
		hint?: string;
		/** Error message; also switches the border to danger. */
		error?: string;
		/** md=32px (default), lg=40px for login/hero forms. */
		size?: FieldSize;
		/** Mono rendering for hosts, IPs, config values. */
		mono?: boolean;
		/** Current text; bindable. */
		value?: string;
	}

	let {
		label,
		hint,
		error,
		size = 'md',
		mono = false,
		value = $bindable(''),
		id,
		oninput,
		class: className = '',
		...rest
	}: Props = $props();

	const uid = $props.id();
	const inputId = $derived(id ?? `sj-input-${uid}`);
	const describedBy = $derived(
		error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined
	);

	// Explicit handler instead of bind:value so `type` can flow through
	// rest props (Svelte disallows bind:value with a dynamic type attribute).
	function handleInput(e: Event & { currentTarget: EventTarget & HTMLInputElement }) {
		value = e.currentTarget.value;
		oninput?.(e);
	}
</script>

<div class="sj-field">
	{#if label}
		<label class="sj-field__label" for={inputId}>{label}</label>
	{/if}
	<input
		{...rest}
		id={inputId}
		class="sj-input {className}"
		class:sj-input--lg={size === 'lg'}
		class:sj-input--error={!!error}
		class:sj-input--mono={mono}
		aria-invalid={error ? 'true' : undefined}
		aria-describedby={describedBy}
		{value}
		oninput={handleInput}
	/>
	{#if error}
		<span class="sj-field__error" id="{inputId}-error">{error}</span>
	{:else if hint}
		<span class="sj-field__hint" id="{inputId}-hint">{hint}</span>
	{/if}
</div>

<style>
	.sj-field {
		display: flex;
		flex-direction: column;
		gap: 5px;
		font-family: var(--font-sans);
	}
	.sj-field__label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		overflow-wrap: anywhere;
	}
	.sj-field__hint {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-field__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
	.sj-input {
		height: var(--control-height);
		padding: 0 10px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		width: 100%;
		transition:
			border-color var(--duration-fast) var(--ease-out),
			box-shadow var(--duration-fast) var(--ease-out);
	}
	.sj-input::placeholder {
		color: var(--text-disabled);
	}
	.sj-input:hover:not(:disabled, :focus) {
		border-color: var(--border-strong);
	}
	.sj-input:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.sj-input:disabled {
		background: var(--surface-sunken);
		color: var(--text-disabled);
		cursor: not-allowed;
	}
	.sj-input--error {
		border-color: var(--danger-solid);
	}
	.sj-input--error:focus-visible {
		border-color: var(--danger-solid);
		box-shadow: var(--focus-ring);
	}
	.sj-input--lg {
		height: var(--control-height-lg);
		font-size: var(--text-md);
		padding: 0 12px;
	}
	.sj-input--mono {
		font-family: var(--font-mono);
	}
</style>
