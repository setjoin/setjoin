<script lang="ts">
	interface Props {
		value?: string;
		label?: string;
		hint?: string;
		error?: string;
		placeholder?: string;
		rows?: number;
		disabled?: boolean;
		required?: boolean;
		maxlength?: number;
		oninput?: (e: Event & { currentTarget: EventTarget & HTMLTextAreaElement }) => void;
		onfocus?: (e: FocusEvent & { currentTarget: EventTarget & HTMLTextAreaElement }) => void;
	}

	let {
		value = $bindable(''),
		label = '',
		hint = '',
		error = '',
		placeholder = '',
		rows = 3,
		disabled = false,
		required = false,
		maxlength,
		oninput,
		onfocus
	}: Props = $props();

	const uid = $props.id();
	const textareaId = `sj-textarea-${uid}`;
	const describedBy = $derived(
		error ? `${textareaId}-error` : hint ? `${textareaId}-hint` : undefined
	);

	function handleInput(e: Event & { currentTarget: EventTarget & HTMLTextAreaElement }) {
		value = e.currentTarget.value;
		oninput?.(e);
	}
</script>

<div class="sj-field">
	{#if label}<label class="sj-field__label" for={textareaId}>{label}</label>{/if}
	<textarea
		id={textareaId}
		class="textarea"
		class:textarea--error={error !== ''}
		aria-invalid={error ? 'true' : undefined}
		aria-describedby={describedBy}
		{value}
		{placeholder}
		{rows}
		{disabled}
		{required}
		{maxlength}
		oninput={handleInput}
		{onfocus}
	></textarea>
	{#if error}
		<span class="sj-field__error" id="{textareaId}-error">{error}</span>
	{:else if hint}
		<span class="sj-field__hint" id="{textareaId}-hint">{hint}</span>
	{/if}
</div>

<style>
	.sj-field {
		display: flex;
		flex-direction: column;
		gap: 5px; /* canonical field-stack gap (deliberately off the 4px grid); matches Input */
		font-family: var(--font-sans);
	}
	.sj-field__label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-field__hint {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-field__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
	.textarea {
		min-height: 64px;
		padding: var(--space-2) var(--space-3);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		line-height: var(--leading-normal);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		width: 100%;
		resize: vertical;
		transition:
			border-color var(--duration-fast) var(--ease-out),
			box-shadow var(--duration-fast) var(--ease-out);
	}
	.textarea::placeholder {
		color: var(--text-disabled);
	}
	.textarea:hover:not(:disabled, :focus-visible) {
		border-color: var(--border-strong);
	}
	.textarea:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.textarea:disabled {
		background: var(--surface-sunken);
		color: var(--text-disabled);
		cursor: not-allowed;
		resize: none;
	}
	.textarea--error {
		border-color: var(--danger-solid);
	}
	.textarea--error:focus-visible {
		border-color: var(--danger-solid);
		box-shadow: var(--focus-ring);
	}
</style>
