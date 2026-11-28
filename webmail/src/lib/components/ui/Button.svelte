<!--
	Button — setjoin's action control. One primary per view. Labels are
	sentence case, verb-first ("Start migration", not "Migration").
	size: sm 26px / md 32px (default) / lg 40px — lg only on login & hero forms.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import type { ButtonVariant, ButtonSize } from './types';

	interface Props extends HTMLButtonAttributes {
		/** Visual style. Default "primary". One primary per view. */
		variant?: ButtonVariant;
		/** Control height: sm=26px, md=32px (default), lg=40px (hero forms only). */
		size?: ButtonSize;
		/** Optional leading icon (16px Lucide, stroke-width 1.75). */
		icon?: Snippet;
		children?: Snippet;
	}

	let {
		variant = 'primary',
		size = 'md',
		icon,
		children,
		type = 'button',
		disabled = false,
		onclick,
		class: className = '',
		...rest
	}: Props = $props();
</script>

<button
	{...rest}
	{type}
	{disabled}
	onclick={disabled ? undefined : onclick}
	class="sj-btn {className}"
	class:sj-btn--primary={variant === 'primary'}
	class:sj-btn--secondary={variant === 'secondary'}
	class:sj-btn--ghost={variant === 'ghost'}
	class:sj-btn--danger={variant === 'danger'}
	class:sj-btn--sm={size === 'sm'}
	class:sj-btn--md={size === 'md'}
	class:sj-btn--lg={size === 'lg'}
>
	{#if icon}<span class="sj-btn__icon">{@render icon()}</span>{/if}
	{#if children}{@render children()}{/if}
</button>

<style>
	.sj-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		font-family: var(--font-sans);
		font-weight: var(--weight-medium);
		white-space: nowrap;
		border-radius: var(--radius-sm);
		border: 1px solid transparent;
		cursor: pointer;
		transition:
			background var(--duration-fast) var(--ease-out),
			border-color var(--duration-fast) var(--ease-out),
			color var(--duration-fast) var(--ease-out),
			opacity var(--duration-base) var(--ease-out);
		text-decoration: none;
	}
	.sj-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.sj-btn--md {
		height: var(--control-height);
		padding: 0 12px;
		font-size: var(--text-sm);
	}
	.sj-btn--sm {
		height: var(--control-height-sm);
		padding: 0 8px;
		font-size: var(--text-xs);
	}
	.sj-btn--lg {
		height: var(--control-height-lg);
		padding: 0 16px;
		font-size: var(--text-md);
	}
	.sj-btn--primary {
		background: var(--accent);
		color: var(--text-inverse);
	}
	.sj-btn--primary:hover:not(:disabled) {
		background: var(--accent-hover);
	}
	.sj-btn--primary:active:not(:disabled) {
		background: var(--accent-active);
	}
	.sj-btn--secondary {
		background: var(--surface-card);
		color: var(--text-primary);
		border-color: var(--border-default);
		box-shadow: var(--shadow-xs);
	}
	.sj-btn--secondary:hover:not(:disabled) {
		background: var(--gray-50);
		border-color: var(--border-strong);
	}
	.sj-btn--secondary:active:not(:disabled) {
		background: var(--gray-100);
	}
	.sj-btn--ghost {
		background: transparent;
		color: var(--text-secondary);
	}
	.sj-btn--ghost:hover:not(:disabled) {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.sj-btn--ghost:active:not(:disabled) {
		background: var(--gray-200);
	}
	.sj-btn--danger {
		background: var(--danger-solid);
		color: var(--text-inverse);
	}
	.sj-btn--danger:hover:not(:disabled) {
		background: var(--danger-fg);
	}
	.sj-btn__icon {
		display: inline-flex;
		flex: none;
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-btn {
			transition: none;
		}
	}
</style>
