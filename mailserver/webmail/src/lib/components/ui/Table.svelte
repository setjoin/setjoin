<svelte:options runes={true} />

<script lang="ts" generics="T extends Record<string, unknown>">
	import type { Snippet } from 'svelte';
	import { nextSort, ariaSort, type TableColumn, type SortDir } from './table';

	let {
		columns,
		rows,
		sortKey,
		sortDir = 'asc',
		onSort,
		cell,
		footer,
		rowClass,
	}: {
		columns: TableColumn[];
		rows: T[];
		sortKey?: string;
		sortDir?: SortDir;
		onSort?: (key: string, dir: SortDir) => void;
		/** Optional custom cell renderer; default renders String(row[col.key]). */
		cell?: Snippet<[T, TableColumn]>;
		/** Footer slot — typically hosts <Pagination />. */
		footer?: Snippet;
		/** Optional per-row CSS class callback. Return a class string or '' for no class. */
		rowClass?: (row: T) => string;
	} = $props();

	function handleSort(col: TableColumn) {
		if (!col.sortable) return;
		const next = nextSort(sortKey, sortDir, col.key);
		onSort?.(next.key, next.dir);
	}
</script>

<div class="sj-table-scroll">
	<table class="sj-table">
		<thead>
			<tr>
				{#each columns as col (col.key)}
					<th style:width={col.width} aria-sort={ariaSort(col, sortKey, sortDir)}>
						{#if col.sortable}
							<button type="button" class="sj-table__sort" onclick={() => handleSort(col)}>
								{col.label}
								<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<path d="m21 16-4 4-4-4" />
									<path d="M17 20V4" />
									<path d="m3 8 4-4 4 4" />
									<path d="M7 4v16" />
								</svg>
							</button>
						{:else}
							{col.label}
						{/if}
					</th>
				{/each}
			</tr>
		</thead>
		<tbody>
			{#each rows as row, i (i)}
				<tr class={rowClass?.(row) || undefined}>
					{#each columns as col (col.key)}
						<td class:sj-table__td--mono={col.mono}>
							{#if cell}
								{@render cell(row, col)}
							{:else}
								{String(row[col.key] ?? '')}
							{/if}
						</td>
					{/each}
				</tr>
			{/each}
		</tbody>
	</table>
</div>
{#if footer}
	<div class="sj-table__footer">{@render footer()}</div>
{/if}

<style>
	.sj-table-scroll {
		overflow-x: auto;
	}
	.sj-table {
		width: 100%;
		border-collapse: collapse;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.sj-table th {
		height: var(--row-height);
		padding: 0 12px;
		text-align: left;
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		border-bottom: 1px solid var(--border-subtle);
		white-space: nowrap;
	}
	.sj-table td {
		height: var(--row-height);
		padding: 0 12px;
		border-bottom: 1px solid var(--border-subtle);
		white-space: nowrap;
	}
	.sj-table tbody tr {
		transition: background var(--duration-fast) var(--ease-out);
	}
	.sj-table tbody tr:hover {
		background: var(--surface-hover);
	}
	.sj-table__td--mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
	}
	.sj-table__sort {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		border: none;
		background: transparent;
		padding: 0;
		cursor: pointer;
		font: inherit;
		color: inherit;
		letter-spacing: inherit;
		text-transform: inherit;
		border-radius: var(--radius-sm);
	}
	.sj-table__sort:hover {
		color: var(--text-primary);
	}
	.sj-table__sort:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-table__sort svg {
		flex: none;
	}
	.sj-table__footer {
		border-top: 1px solid var(--border-subtle);
	}
</style>
