import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import Table from './Table.svelte';
import type { TableColumn } from './table';

const columns: TableColumn[] = [
	{ key: 'name', label: 'Name', sortable: true },
	{ key: 'id', label: 'ID', mono: true },
	{ key: 'size', label: 'Size', sortable: true }
];
const rows = [
	{ name: 'alpha.txt', id: 'b-001', size: '12 KB' },
	{ name: 'beta.txt', id: 'b-002', size: '7 KB' }
];

describe('Table', () => {
	it('renders column headers and row data', () => {
		render(Table, { columns, rows });
		expect(screen.getByText('Name')).toBeTruthy();
		expect(screen.getByText('ID')).toBeTruthy();
		expect(screen.getByText('alpha.txt')).toBeTruthy();
		expect(screen.getByText('b-002')).toBeTruthy();
	});

	it('marks mono columns with the mono modifier', () => {
		const { container } = render(Table, { columns, rows });
		const monoCells = container.querySelectorAll('td.sj-table__td--mono');
		expect(monoCells.length).toBe(2);
		expect(monoCells[0].textContent?.trim()).toBe('b-001');
	});

	it('renders non-sortable headers without a button', () => {
		render(Table, { columns, rows });
		expect(screen.getByText('ID').closest('button')).toBeNull();
		expect(screen.getByText('Name').closest('button')).not.toBeNull();
	});

	it('emits onSort asc for a new column and desc when already ascending', async () => {
		const onSort = vi.fn();
		render(Table, { columns, rows, sortKey: 'name', sortDir: 'asc', onSort });
		await fireEvent.click(screen.getByText('Size'));
		expect(onSort).toHaveBeenLastCalledWith('size', 'asc');
		await fireEvent.click(screen.getByText('Name'));
		expect(onSort).toHaveBeenLastCalledWith('name', 'desc');
	});

	it('sets aria-sort on the active column and none on inactive sortable columns', () => {
		const { container } = render(Table, { columns, rows, sortKey: 'name', sortDir: 'desc' });
		const ths = container.querySelectorAll('th');
		expect(ths[0].getAttribute('aria-sort')).toBe('descending');
		expect(ths[1].getAttribute('aria-sort')).toBeNull();
		expect(ths[2].getAttribute('aria-sort')).toBe('none');
	});

	it('renders the footer snippet', () => {
		const footer = createRawSnippet(() => ({ render: () => '<span>footer-content</span>' }));
		render(Table, { columns, rows, footer });
		expect(screen.getByText('footer-content')).toBeTruthy();
	});

	it('applies rowClass to matching rows and leaves others unclassed', () => {
		const { container } = render(Table, {
			columns,
			rows,
			rowClass: (row: Record<string, unknown>) => (row['id'] === 'b-001' ? 'row--danger' : ''),
		});
		const trs = container.querySelectorAll('tbody tr');
		expect(trs[0].classList.contains('row--danger')).toBe(true);
		expect(trs[1].classList.contains('row--danger')).toBe(false);
	});
});
