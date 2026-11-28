// Table sorting contract — caller-side sorting. The Table component never
// reorders rows; it emits onSort(key, dir) and the caller re-queries/re-sorts.

export type SortDir = 'asc' | 'desc';

export interface TableColumn {
	key: string;
	label: string;
	sortable?: boolean;
	/** Render this column's cells in --font-mono (ids, sizes, hashes). */
	mono?: boolean;
	/** Optional CSS width (e.g. "120px", "20%"). */
	width?: string;
}

/** Next sort state after clicking `clickedKey`: new column → asc; active column → flip. */
export function nextSort(
	currentKey: string | undefined,
	currentDir: SortDir,
	clickedKey: string
): { key: string; dir: SortDir } {
	if (currentKey === clickedKey) {
		return { key: clickedKey, dir: currentDir === 'asc' ? 'desc' : 'asc' };
	}
	return { key: clickedKey, dir: 'asc' };
}

/** aria-sort value for a header cell; undefined means "omit the attribute". */
export function ariaSort(
	column: TableColumn,
	sortKey: string | undefined,
	sortDir: SortDir
): 'ascending' | 'descending' | 'none' | undefined {
	if (!column.sortable) return undefined;
	if (column.key !== sortKey) return 'none';
	return sortDir === 'asc' ? 'ascending' : 'descending';
}
