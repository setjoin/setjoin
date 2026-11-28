<svelte:options runes={true} />

<script lang="ts">
	import { formatRange, pageCount } from './pagination';

	let {
		page,
		pageSize,
		total,
		pageSizeOptions = [25, 50, 100],
		onPageChange,
		onPageSizeChange
	}: {
		page: number;
		pageSize: number;
		total: number;
		pageSizeOptions?: number[];
		onPageChange?: (page: number) => void;
		onPageSizeChange?: (size: number) => void;
	} = $props();

	const uid = $props.id();
	const pages = $derived(pageCount(total, pageSize));
</script>

<div class="sj-pagination">
	<span class="sj-pagination__range">{formatRange(page, pageSize, total)}</span>
	<label class="sj-pagination__label" for="{uid}-size">Rows per page</label>
	<select
		id="{uid}-size"
		class="sj-pagination__select"
		value={String(pageSize)}
		onchange={(e) => onPageSizeChange?.(Number(e.currentTarget.value))}
	>
		{#each pageSizeOptions as opt (opt)}
			<option value={String(opt)}>{opt}</option>
		{/each}
	</select>
	<button
		type="button"
		class="sj-pagination__btn"
		aria-label="Previous page"
		disabled={page <= 1}
		onclick={() => onPageChange?.(page - 1)}
	>
		<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
			<path d="m15 18-6-6 6-6" />
		</svg>
	</button>
	<button
		type="button"
		class="sj-pagination__btn"
		aria-label="Next page"
		disabled={page >= pages}
		onclick={() => onPageChange?.(page + 1)}
	>
		<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
			<path d="m9 18 6-6-6-6" />
		</svg>
	</button>
</div>

<style>
	.sj-pagination {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.sj-pagination__range {
		margin-right: auto;
		font-family: var(--font-mono);
		color: var(--text-tertiary);
	}
	.sj-pagination__label {
		color: var(--text-secondary);
	}
	.sj-pagination__select {
		height: var(--control-height-sm);
		padding: 0 6px;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: border-color var(--duration-fast) var(--ease-out), box-shadow var(--duration-fast) var(--ease-out);
	}
	.sj-pagination__select:hover:not(:disabled, :focus) {
		border-color: var(--border-strong);
	}
	.sj-pagination__select:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.sj-pagination__btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex: none;
		width: var(--control-height-sm);
		height: var(--control-height-sm);
		background: transparent;
		border: 1px solid transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
		transition: background var(--duration-fast) var(--ease-out), color var(--duration-fast) var(--ease-out);
	}
	.sj-pagination__btn:hover:not(:disabled) {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.sj-pagination__btn:active:not(:disabled) {
		background: var(--gray-200);
	}
	.sj-pagination__btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-pagination__btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
