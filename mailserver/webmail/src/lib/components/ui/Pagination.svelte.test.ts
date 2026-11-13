import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import Pagination from './Pagination.svelte';

describe('Pagination', () => {
	it('shows the range label in start–end of total form', () => {
		render(Pagination, { page: 1, pageSize: 50, total: 1283 });
		expect(screen.getByText('1–50 of 1,283')).toBeTruthy();
	});

	it('disables Previous on the first page only', () => {
		render(Pagination, { page: 1, pageSize: 50, total: 1283 });
		expect((screen.getByLabelText('Previous page') as HTMLButtonElement).disabled).toBe(true);
		expect((screen.getByLabelText('Next page') as HTMLButtonElement).disabled).toBe(false);
	});

	it('disables Next on the last page and shows the partial range', () => {
		render(Pagination, { page: 26, pageSize: 50, total: 1283 });
		expect(screen.getByText('1,251–1,283 of 1,283')).toBeTruthy();
		expect((screen.getByLabelText('Next page') as HTMLButtonElement).disabled).toBe(true);
	});

	it('emits page changes from the arrows', async () => {
		const onPageChange = vi.fn();
		render(Pagination, { page: 2, pageSize: 50, total: 1283, onPageChange });
		await fireEvent.click(screen.getByLabelText('Previous page'));
		expect(onPageChange).toHaveBeenLastCalledWith(1);
		await fireEvent.click(screen.getByLabelText('Next page'));
		expect(onPageChange).toHaveBeenLastCalledWith(3);
	});

	it('emits the numeric page size from the select', async () => {
		const onPageSizeChange = vi.fn();
		render(Pagination, { page: 1, pageSize: 50, total: 1283, onPageSizeChange });
		await fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '100' } });
		expect(onPageSizeChange).toHaveBeenCalledWith(100);
	});
});
