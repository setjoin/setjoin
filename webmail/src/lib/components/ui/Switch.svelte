<!--
	Switch — setjoin's hot-toggle control for feature flags and settings.
	Switches apply instantly; never pair with a Save button.
	32x18 track, 14px thumb, duration-base motion.
-->
<script lang="ts">
	interface Props {
		/** Checked state; bindable. */
		checked?: boolean;
		disabled?: boolean;
		label?: string;
		/** Secondary line under the label (e.g. resource impact). */
		description?: string;
		id?: string;
		class?: string;
		onchange?: (e: Event & { currentTarget: EventTarget & HTMLInputElement }) => void;
	}

	let {
		checked = $bindable(false),
		disabled = false,
		label,
		description,
		id,
		class: className = '',
		onchange
	}: Props = $props();

	const uid = $props.id();
	const inputId = $derived(id ?? `sj-switch-${uid}`);

	function handleChange(e: Event & { currentTarget: EventTarget & HTMLInputElement }) {
		checked = e.currentTarget.checked;
		onchange?.(e);
	}

	function handleClick(e: MouseEvent) {
		if (disabled) e.preventDefault();
	}
</script>

<label
	class="sj-switch {className}"
	class:sj-switch--on={checked}
	class:sj-switch--disabled={disabled}
	for={inputId}
>
	<input
		id={inputId}
		type="checkbox"
		role="switch"
		aria-checked={checked}
		{checked}
		{disabled}
		onclick={handleClick}
		onchange={disabled ? undefined : handleChange}
	/>
	<span class="sj-switch__track" aria-hidden="true"><span class="sj-switch__thumb"></span></span>
	{#if label}
		<span class="sj-switch__text">
			<span>{label}</span>
			{#if description}<span class="sj-switch__desc">{description}</span>{/if}
		</span>
	{/if}
</label>

<style>
	.sj-switch {
		display: inline-flex;
		align-items: center;
		min-width: 0;
		max-width: 100%;
		position: relative;
		gap: var(--space-2);
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		user-select: none;
	}
	.sj-switch--disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.sj-switch input {
		position: absolute;
		opacity: 0;
		width: var(--switch-track-width);
		height: var(--switch-track-height);
		margin: 0;
		cursor: inherit;
		z-index: 1;
	}
	.sj-switch__track {
		width: var(--switch-track-width);
		height: var(--switch-track-height);
		flex: none;
		border-radius: var(--radius-full);
		background: var(--gray-300);
		position: relative;
		transition: background var(--duration-base) var(--ease-out);
	}
	.sj-switch__thumb {
		position: absolute;
		top: var(--switch-thumb-inset);
		left: var(--switch-thumb-inset);
		width: var(--switch-thumb-size);
		height: var(--switch-thumb-size);
		border-radius: var(--radius-full);
		background: var(--gray-0);
		box-shadow: var(--shadow-xs);
		transition: transform var(--duration-base) var(--ease-out);
	}
	.sj-switch--on .sj-switch__track {
		background: var(--accent);
	}
	.sj-switch--on .sj-switch__thumb {
		transform: translateX(var(--switch-thumb-size));
	}
	.sj-switch input:focus-visible + .sj-switch__track {
		box-shadow: var(--focus-ring);
	}
	.sj-switch__text {
		display: inline-flex;
		flex-direction: column;
		min-width: 0;
		gap: 1px;
		overflow-wrap: anywhere;
	}
	.sj-switch__desc {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
	}
</style>
