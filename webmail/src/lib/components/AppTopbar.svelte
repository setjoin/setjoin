<svelte:options runes={true} />

<script lang="ts">
	import type { Snippet } from 'svelte';
	import { IconButton } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	interface Props {
		title: string;
		showBurger?: boolean;
		onBurger?: () => void;
		onSearch?: (q: string) => void;
		searchPlaceholder?: string;
		actions?: Snippet;
	}

	let {
		title,
		showBurger = false,
		onBurger,
		onSearch,
		searchPlaceholder = 'Search',
		actions,
	}: Props = $props();

	let isFocused = $state(false);
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;

	function handleInput(e: Event) {
		const value = (e.target as HTMLInputElement).value;
		if (debounceTimer !== undefined) {
			clearTimeout(debounceTimer);
		}
		debounceTimer = setTimeout(() => {
			onSearch?.(value);
		}, 300);
	}
</script>

<header class="sj-topbar">
	{#if showBurger}
		<IconButton label={t('shell.menu')} size="md" variant="ghost" class="sj-burger-lg" data-tour="apps" onclick={onBurger}>
			<Icon name="Menu" size={18} strokeWidth={1.75} />
		</IconButton>
	{/if}

	<span class="sj-topbar-title">{title}</span>

	{#if onSearch}
		<div class="sj-topbar-search">
			<div class="sj-topbar-search-icon" aria-hidden="true">
				<Icon name="Search" size={15} />
			</div>
			<input
				type="text"
				aria-label={searchPlaceholder}
				placeholder={searchPlaceholder}
				oninput={handleInput}
				onfocus={() => { isFocused = true; }}
				onblur={() => { isFocused = false; }}
				class="sj-topbar-search-input"
				class:sj-topbar-search-input--focused={isFocused}
			/>
		</div>
	{:else}
		<div class="sj-topbar-spacer"></div>
	{/if}

	{#if actions}
		{@render actions()}
	{/if}
</header>

<style>
	.sj-topbar {
		height: var(--topbar-height);
		flex: none;
		display: flex;
		align-items: center;
		gap: var(--space-2); /* 8px */
		padding: 0 10px;
		border-bottom: 1px solid var(--border-default);
		background: var(--surface-card);
	}

	.sj-topbar-spacer {
		flex: 1;
	}

	.sj-topbar-title {
		font-size: var(--text-md);
		font-weight: 600;
		padding: 0 2px;
		white-space: nowrap;
		color: var(--text-primary);
	}

	.sj-topbar-search {
		flex: 1 1 auto;
		min-width: 0;
		max-width: 560px;
		position: relative;
		margin-left: 4px;
	}

	.sj-topbar-search-icon {
		position: absolute;
		left: 9px;
		top: 8px;
		color: var(--text-tertiary);
		pointer-events: none;
		z-index: 1;
		display: flex;
		align-items: center;
	}

	.sj-topbar-search-input {
		width: 100%;
		/* 1px inset from default control height on each side to sit flush in the 52px topbar */
		height: calc(var(--control-height) - 2px);
		box-sizing: border-box;
		padding: 0 10px 0 30px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: var(--surface-sunken);
		color: var(--text-primary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		outline: none;
	}

	.sj-topbar-search-input--focused {
		background: var(--surface-card);
		border-color: var(--accent);
	}
</style>
