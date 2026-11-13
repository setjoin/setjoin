<!-- mailserver/webmail/src/lib/components/ui/Tabs.svelte -->
<svelte:options runes={true} />

<script lang="ts" module>
	export interface TabItem {
		id: string;
		label: string;
		/** Mono count pill. Rendered for any number, including 0; omitted when undefined/null. */
		count?: number | null;
	}
</script>

<script lang="ts">
	interface Props {
		items: TabItem[];
		/** id of the active tab. */
		active: string;
		onChange?: (id: string) => void;
	}

	let { items, active, onChange }: Props = $props();
</script>

<div class="tabs" role="tablist">
	{#each items as item (item.id)}
		<button
			type="button"
			role="tab"
			aria-selected={active === item.id}
			class="tab"
			class:tab--active={active === item.id}
			onclick={() => onChange?.(item.id)}
		>
			{item.label}
			{#if item.count != null}
				<span class="tab__count">{item.count}</span>
			{/if}
		</button>
	{/each}
</div>

<style>
	.tabs {
		display: flex;
		gap: 2px;
		border-bottom: 1px solid var(--border-default);
		font-family: var(--font-sans);
	}
	.tab {
		position: relative;
		height: 36px;
		padding: 0 12px;
		display: inline-flex;
		align-items: center;
		gap: 6px;
		background: transparent;
		border: none;
		cursor: pointer;
		font-family: inherit;
		font-size: var(--text-sm); /* 13px */
		font-weight: var(--weight-medium); /* 500 */
		color: var(--text-secondary);
		border-radius: var(--radius-sm) var(--radius-sm) 0 0; /* 4px 4px 0 0 */
		transition:
			color var(--duration-fast) var(--ease-out),
			background var(--duration-fast) var(--ease-out); /* 120ms cubic-bezier(0.2, 0, 0, 1) */
	}
	.tab:hover {
		color: var(--text-primary);
		background: var(--surface-hover);
	}
	.tab:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.tab--active {
		color: var(--text-accent);
	}
	.tab--active::after {
		content: '';
		position: absolute;
		left: 0;
		right: 0;
		bottom: -1px; /* overlaps the tablist hairline */
		height: 2px;
		background: var(--accent);
	}
	.tab__count {
		font-size: var(--text-2xs); /* 11px */
		font-family: var(--font-mono);
		color: var(--text-tertiary);
		background: var(--gray-100);
		border-radius: var(--radius-full); /* 999px */
		padding: 1px 6px;
	}
	.tab--active .tab__count {
		color: var(--accent-fg-on-subtle);
		background: var(--accent-subtle);
	}
</style>
