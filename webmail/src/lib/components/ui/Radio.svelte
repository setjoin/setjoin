<script lang="ts">
	interface Props {
		checked?: boolean;
		disabled?: boolean;
		label?: string;
		name?: string;
		value?: string;
		onchange?: (value: string) => void;
	}

	let { checked = false, disabled = false, label = '', name = '', value = '', onchange }: Props = $props();

	const uid = $props.id();
</script>

<label class="radio" class:radio--disabled={disabled} for="radio-{uid}">
	<input
		id="radio-{uid}"
		type="radio"
		{name}
		{value}
		{checked}
		{disabled}
		onchange={disabled ? undefined : () => onchange?.(value)}
	/>
	<span class="radio__circle" class:radio__circle--on={checked}></span>
	{#if label}<span>{label}</span>{/if}
</label>

<style>
	.radio {
		position: relative;
		display: inline-flex;
		align-items: center;
		gap: 8px;
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		user-select: none;
	}
	.radio--disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.radio__circle {
		width: 16px;
		height: 16px;
		flex: none;
		border-radius: var(--radius-full);
		border: 1.5px solid var(--border-strong);
		background: var(--surface-card);
		display: inline-flex;
		align-items: center;
		justify-content: center;
		transition:
			background var(--duration-fast) var(--ease-out),
			border-color var(--duration-fast) var(--ease-out);
	}
	.radio input {
		position: absolute;
		opacity: 0;
		width: 0;
		height: 0;
	}
	.radio input:focus-visible + .radio__circle {
		box-shadow: var(--focus-ring);
	}
	.radio__circle--on {
		background: var(--accent);
		border-color: var(--accent);
	}
	.radio__circle--on::after {
		content: '';
		width: 6px;
		height: 6px;
		border-radius: var(--radius-full);
		background: var(--text-inverse);
	}
	.radio:hover:not(.radio--disabled) .radio__circle:not(.radio__circle--on) {
		border-color: var(--gray-500);
	}
</style>
