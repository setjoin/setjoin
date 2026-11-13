<!-- mailserver/webmail/src/lib/components/ui/Menu.svelte -->
<svelte:options runes={true} />

<script lang="ts" module>
	export interface MenuItem {
		id: string;
		label: string;
		/** Destructive items render in --danger-fg (e.g. Delete). */
		destructive?: boolean;
	}
</script>

<script lang="ts">
	import { tick } from 'svelte';
	import type { Snippet } from 'svelte';

	interface Props {
		items: MenuItem[];
		onSelect?: (id: string) => void;
		/** Accessible name for the menu; also the trigger text when no children snippet is given. */
		label?: string;
		/** Popover horizontal alignment relative to the trigger. */
		align?: 'start' | 'end';
		/** Custom trigger content (rendered inside the trigger button). */
		children?: Snippet;
	}

	let { items, onSelect, label = 'Menu', align = 'start', children }: Props = $props();

	let open = $state(false);
	let activeIndex = $state(0);
	let root = $state<HTMLDivElement | null>(null);
	let triggerEl = $state<HTMLButtonElement | null>(null);
	let itemEls = $state<HTMLButtonElement[]>([]);

	function focusItem(i: number) {
		if (items.length === 0) return;
		activeIndex = (i + items.length) % items.length;
		itemEls[activeIndex]?.focus();
	}

	async function openMenu(idx: number) {
		open = true;
		await tick();
		focusItem(idx);
	}

	function close(refocusTrigger: boolean) {
		open = false;
		if (refocusTrigger) triggerEl?.focus();
	}

	function onTriggerClick() {
		if (open) close(true);
		else void openMenu(0);
	}

	function onTriggerKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			void openMenu(0);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			void openMenu(items.length - 1);
		}
	}

	function onItemKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			focusItem(activeIndex + 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			focusItem(activeIndex - 1);
		} else if (e.key === 'Home') {
			e.preventDefault();
			focusItem(0);
		} else if (e.key === 'End') {
			e.preventDefault();
			focusItem(items.length - 1);
		} else if (e.key === 'Escape') {
			e.preventDefault();
			close(true);
		} else if (e.key === 'Tab') {
			open = false; // let focus proceed naturally
		}
	}

	function onItemClick(id: string) {
		onSelect?.(id);
		close(true);
	}

	$effect(() => {
		if (!open) return;
		function onPointerDown(e: Event) {
			if (root && !root.contains(e.target as Node)) open = false;
		}
		document.addEventListener('pointerdown', onPointerDown);
		return () => document.removeEventListener('pointerdown', onPointerDown);
	});
</script>

<div class="menu-root" bind:this={root}>
	<button
		type="button"
		class="menu-trigger"
		bind:this={triggerEl}
		aria-haspopup="menu"
		aria-expanded={open}
		aria-label={children ? label : undefined}
		onclick={onTriggerClick}
		onkeydown={onTriggerKeydown}
	>
		{#if children}{@render children()}{:else}{label}{/if}
	</button>
	{#if open}
		<div class="menu" class:menu--end={align === 'end'} role="menu" aria-label={label}>
			{#each items as item, i (item.id)}
				<button
					type="button"
					role="menuitem"
					class="menu__item"
					class:menu__item--destructive={item.destructive}
					tabindex={i === activeIndex ? 0 : -1}
					bind:this={itemEls[i]}
					onclick={() => onItemClick(item.id)}
					onkeydown={onItemKeydown}
				>
					{item.label}
				</button>
			{/each}
		</div>
	{/if}
</div>

<style>
	.menu-root {
		position: relative;
		display: inline-flex;
	}
	.menu-trigger {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		height: 32px; /* kit default control height */
		padding: 0 10px;
		background: transparent;
		border: none;
		border-radius: var(--radius-sm); /* 4px */
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm); /* 13px */
		color: var(--text-primary);
		transition: background var(--duration-fast) var(--ease-out);
	}
	.menu-trigger:hover {
		background: var(--surface-hover);
	}
	.menu-trigger:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.menu {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		z-index: 50;
		min-width: 160px;
		display: flex;
		flex-direction: column;
		padding: 4px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md); /* 6px */
		box-shadow: var(--shadow-md);
	}
	.menu--end {
		left: auto;
		right: 0;
	}
	.menu__item {
		display: flex;
		align-items: center;
		gap: 8px;
		width: 100%;
		height: 30px; /* fixed 30px row */
		padding: 0 8px;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		font-size: var(--text-sm); /* 13px */
		color: var(--text-primary);
		border-radius: var(--radius-sm); /* 4px */
	}
	.menu__item:hover {
		background: var(--surface-hover);
	}
	.menu__item:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		background: var(--surface-hover);
	}
	.menu__item--destructive {
		color: var(--danger-fg);
	}
</style>
