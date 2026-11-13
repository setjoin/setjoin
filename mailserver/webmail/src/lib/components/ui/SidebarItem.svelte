<!-- mailserver/webmail/src/lib/components/ui/SidebarItem.svelte -->
<svelte:options runes={true} />

<script lang="ts" module>
	/** The 8 kit tag hues — must stay in sync with the --tag-*-dot tokens. */
	export type TagHue =
		| 'blue'
		| 'teal'
		| 'green'
		| 'amber'
		| 'orange'
		| 'rose'
		| 'purple'
		| 'gray';
</script>

<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		label: string;
		/** Leading 16px slot, option A: an icon snippet (typically a 16px lucide icon). */
		icon?: Snippet;
		/** Leading 16px slot, option B: an 8px tag-hue dot. Wins over `icon` when both are set. */
		dotColor?: TagHue;
		/** Right-aligned mono count. Hidden when 0 or null (unread-count semantics). */
		count?: number | null;
		active?: boolean;
		/** Nesting depth; left padding is 8 + depth * 16 px. */
		depth?: number;
		onclick?: (e: MouseEvent) => void;
	}

	let { label, icon, dotColor, count = null, active = false, depth = 0, onclick }: Props = $props();
</script>

<button
	type="button"
	class="sbitem"
	class:sbitem--active={active}
	aria-current={active ? 'true' : undefined}
	style:padding-left={`${8 + depth * 16}px`}
	{onclick}
>
	{#if dotColor}
		<span class="sbitem__icon">
			<span class="sbitem__dot" style:background={`var(--tag-${dotColor}-dot)`}></span>
		</span>
	{:else if icon}
		<span class="sbitem__icon">{@render icon()}</span>
	{/if}
	<span class="sbitem__label">{label}</span>
	{#if count != null && count !== 0}
		<span class="sbitem__count">{count}</span>
	{/if}
</button>

<style>
	.sbitem {
		display: flex;
		align-items: center;
		gap: 8px;
		width: 100%;
		height: 30px; /* fixed 30px row */
		padding: 0 8px;
		border: none;
		background: transparent;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		font-size: var(--text-sm); /* 13px */
		color: var(--text-secondary);
		border-radius: var(--radius-sm); /* 4px */
		transition:
			background var(--duration-fast) var(--ease-out),
			color var(--duration-fast) var(--ease-out); /* 120ms cubic-bezier(0.2, 0, 0, 1) */
	}
	.sbitem:hover {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.sbitem:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sbitem--active {
		background: var(--surface-selected);
		color: var(--accent-fg-on-subtle);
		font-weight: var(--weight-medium); /* 500 */
	}
	.sbitem--active:hover {
		background: var(--accent-subtle-hover);
		color: var(--accent-fg-on-subtle);
	}
	.sbitem__icon {
		display: inline-flex;
		flex: none;
		width: 16px;
		justify-content: center;
	}
	.sbitem__label {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.sbitem__count {
		font-family: var(--font-mono);
		font-size: var(--text-2xs); /* 11px */
		color: var(--text-caption);
	}
	.sbitem--active .sbitem__count {
		color: var(--accent-fg-on-subtle);
		font-weight: var(--weight-semibold); /* 600 */
	}
	.sbitem__dot {
		width: 8px;
		height: 8px;
		border-radius: var(--radius-full); /* 999px */
		flex: none;
	}
</style>
