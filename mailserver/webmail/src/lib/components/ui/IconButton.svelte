<!--
	IconButton — square icon-only control for toolbars and row hover-actions.
	Always pass `label` (becomes aria-label + title tooltip).
	variant="outline" adds border + card background for standalone use.
	`active` shows the indigo selected tint (toggled tools, current filter).
-->
<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import type { IconButtonSize, IconButtonVariant } from './types';

	interface Props extends HTMLButtonAttributes {
		/** Required accessible name; also shown as tooltip via title. */
		label: string;
		/** Optional tooltip text when it should differ from the accessible name. */
		tooltip?: string;
		/** ghost (default) for toolbars; outline for standalone placement. */
		variant?: IconButtonVariant;
		/** sm=26px for dense list rows, md=32px (default). */
		size?: IconButtonSize;
		/** Pressed/toggled state — indigo tint. */
		active?: boolean;
		/** The icon itself: 16–18px Lucide, stroke-width 1.75. */
		children: Snippet;
	}

	let {
		label,
		tooltip,
		variant = 'ghost',
		size = 'md',
		active = false,
		children,
		type = 'button',
		disabled = false,
		onclick,
		class: className = '',
		...rest
	}: Props = $props();
</script>

<!--
  disabled + onclick are extracted (not left to ...rest) so the click
  handler is suppressed when disabled — jsdom's fireEvent.click fires
  synthetically on disabled elements, so the disabled-click test needs
  this explicit guard (same pattern as Button).
-->
<button
	{...rest}
	{type}
	{disabled}
	onclick={disabled ? undefined : onclick}
	aria-label={label}
	title={tooltip ?? label}
	class="sj-iconbtn {className}"
	class:sj-iconbtn--sm={size === 'sm'}
	class:sj-iconbtn--md={size === 'md'}
	class:sj-iconbtn--outline={variant === 'outline'}
	class:sj-iconbtn--active={active}
>
	{@render children()}
</button>

<style>
	.sj-iconbtn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex: none;
		border-radius: var(--radius-sm);
		border: 1px solid transparent;
		cursor: pointer;
		background: transparent;
		color: var(--text-secondary);
		transition:
			background var(--duration-fast) var(--ease-out),
			color var(--duration-fast) var(--ease-out);
	}
	.sj-iconbtn:hover:not(:disabled) {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.sj-iconbtn:active:not(:disabled) {
		background: var(--gray-200);
	}
	.sj-iconbtn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-iconbtn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.sj-iconbtn--md {
		width: var(--control-height);
		height: var(--control-height);
	}
	.sj-iconbtn--sm {
		width: var(--control-height-sm);
		height: var(--control-height-sm);
	}
	.sj-iconbtn--outline {
		background: var(--surface-card);
		border-color: var(--border-default);
		box-shadow: var(--shadow-xs);
	}
	.sj-iconbtn--outline:hover:not(:disabled) {
		background: var(--gray-50);
		border-color: var(--border-strong);
	}
	.sj-iconbtn--active {
		background: var(--surface-selected);
		color: var(--text-accent);
	}
	.sj-iconbtn--active:hover:not(:disabled) {
		background: var(--accent-subtle-hover);
		color: var(--text-accent);
	}
</style>
