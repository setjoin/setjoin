import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import CsvImportModal from './CsvImportModal.svelte';

function jsonResponse(body: unknown, ok = true, status = 200): Response {
	return {
		ok,
		status,
		json: async () => body,
		text: async () => JSON.stringify(body)
	} as unknown as Response;
}

function selectCsvFile(container: HTMLElement, text = 'First Name,E-mail Address\nAlice,a@x.test\n') {
	const input = container.querySelector('#csv-file-input') as HTMLInputElement;
	const file = new File([text], 'contacts.csv', { type: 'text/csv' });
	// jsdom: files is read-only; define it then fire change.
	Object.defineProperty(input, 'files', { value: [file], configurable: true });
	return { input, fire: () => fireEvent.change(input) };
}

function selectVcfFile(container: HTMLElement, text = 'BEGIN:VCARD\nFN:Alice\nEMAIL:a@x.test\nEND:VCARD\n') {
	const input = container.querySelector('#csv-file-input') as HTMLInputElement;
	const file = new File([text], 'contacts.vcf', { type: 'text/vcard' });
	Object.defineProperty(input, 'files', { value: [file], configurable: true });
	return { input, fire: () => fireEvent.change(input) };
}

describe('CsvImportModal', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('renders nothing visible when closed', () => {
		const { container } = render(CsvImportModal, {
			open: false,
			addressBookId: '1',
			onClose: () => {}
		});
		expect(container.querySelector('#csv-file-input')).toBeNull();
	});

	it('shows the file chooser when open', () => {
		const { container } = render(CsvImportModal, {
			open: true,
			addressBookId: '1',
			onClose: () => {}
		});
		expect(container.querySelector('#csv-file-input')).not.toBeNull();
	});

	it('moves to the mapping step after a successful preview', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
			jsonResponse({
				headers: ['First Name', 'E-mail Address'],
				mapping: { firstName: 0, email: 1 },
				sample: [['Alice', 'a@x.test']]
			})
		);
		const { container, findByText } = render(CsvImportModal, {
			open: true,
			addressBookId: '1',
			onClose: () => {}
		});

		const { fire } = selectCsvFile(container);
		await fire();

		await waitFor(() =>
			expect(fetchSpy).toHaveBeenCalledWith('/api/contacts/import/csv/preview', expect.anything())
		);
		// Mapping step shows the detected header as a sample column and the import button.
		expect(await findByText('Map columns')).toBeInTheDocument();
		expect(await findByText('Import')).toBeInTheDocument();
		expect(container.textContent).toContain('First Name');
	});

	it('posts to /contacts/import/csv on Import and reports the result', async () => {
		const fetchSpy = vi
			.spyOn(global, 'fetch')
			.mockResolvedValueOnce(
				jsonResponse({
					headers: ['First Name', 'E-mail Address'],
					mapping: { firstName: 0, email: 1 },
					sample: [['Alice', 'a@x.test']]
				})
			)
			.mockResolvedValueOnce(jsonResponse({ imported: 1, skipped: 0, errors: [] }));

		const onDone = vi.fn();
		const { container, findByText, getByText } = render(CsvImportModal, {
			open: true,
			addressBookId: '7',
			onClose: () => {},
			onDone
		});

		const { fire } = selectCsvFile(container);
		await fire();
		await findByText('Import');

		await fireEvent.click(getByText('Import'));

		await waitFor(() => {
			const importCall = fetchSpy.mock.calls.find((c) => c[0] === '/api/contacts/import/csv');
			expect(importCall).toBeTruthy();
		});
		// The submitted FormData carries the chosen addressBookId.
		const importCall = fetchSpy.mock.calls.find((c) => c[0] === '/api/contacts/import/csv')!;
		const fd = (importCall[1] as RequestInit).body as FormData;
		expect(fd.get('addressBookId')).toBe('7');
		expect(onDone).toHaveBeenCalled();
		expect(await findByText(/Imported 1/)).toBeInTheDocument();
	});

	it('skips the preview/column-map step for a .vcf file', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue(jsonResponse({}));
		fetchSpy.mockClear(); // isolate from prior tests' shared global.fetch history
		const { container, findByText } = render(CsvImportModal, {
			open: true,
			addressBookId: '1',
			onClose: () => {}
		});

		const { fire } = selectVcfFile(container);
		await fire();

		// No preview fetch — vCard is self-describing — but the Import button shows.
		expect(fetchSpy).not.toHaveBeenCalled();
		expect(await findByText('Import')).toBeInTheDocument();
		expect(container.querySelector('.csv-map')).toBeNull();
	});

	it('posts to /contacts/import/vcf without a mapping field', async () => {
		const fetchSpy = vi
			.spyOn(global, 'fetch')
			.mockResolvedValueOnce(jsonResponse({ imported: 2, skipped: 0, errors: [] }));

		const { container, findByText, getByText } = render(CsvImportModal, {
			open: true,
			addressBookId: '9',
			onClose: () => {}
		});

		const { fire } = selectVcfFile(container);
		await fire();
		await findByText('Import');

		await fireEvent.click(getByText('Import'));

		await waitFor(() => {
			const call = fetchSpy.mock.calls.find((c) => c[0] === '/api/contacts/import/vcf');
			expect(call).toBeTruthy();
		});
		const call = fetchSpy.mock.calls.find((c) => c[0] === '/api/contacts/import/vcf')!;
		const fd = (call[1] as RequestInit).body as FormData;
		expect(fd.get('addressBookId')).toBe('9');
		expect(fd.get('strategy')).toBe('skip');
		expect(fd.get('mapping')).toBeNull();
		expect(await findByText(/Imported 2/)).toBeInTheDocument();
	});
});
