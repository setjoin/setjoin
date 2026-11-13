import { describe, it, expect } from 'vitest';
import { nextSort, ariaSort, type TableColumn } from './table';

describe('nextSort', () => {
	it('starts ascending on a new column', () => {
		expect(nextSort('name', 'asc', 'size')).toEqual({ key: 'size', dir: 'asc' });
		expect(nextSort(undefined, 'asc', 'size')).toEqual({ key: 'size', dir: 'asc' });
	});

	it('flips direction on the active column', () => {
		expect(nextSort('name', 'asc', 'name')).toEqual({ key: 'name', dir: 'desc' });
		expect(nextSort('name', 'desc', 'name')).toEqual({ key: 'name', dir: 'asc' });
	});
});

describe('ariaSort', () => {
	const sortable: TableColumn = { key: 'name', label: 'Name', sortable: true };
	const plain: TableColumn = { key: 'id', label: 'ID' };

	it('reports the active sort direction', () => {
		expect(ariaSort(sortable, 'name', 'asc')).toBe('ascending');
		expect(ariaSort(sortable, 'name', 'desc')).toBe('descending');
	});

	it('reports none for sortable inactive columns', () => {
		expect(ariaSort(sortable, 'size', 'asc')).toBe('none');
	});

	it('omits aria-sort for non-sortable columns', () => {
		expect(ariaSort(plain, 'id', 'asc')).toBeUndefined();
	});
});
