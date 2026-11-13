import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import NewHrRequestDialog from '$lib/components/NewHrRequestDialog.svelte';
import { t } from '$lib/i18n';
import en from '$lib/i18n/en';
import de from '$lib/i18n/de';
import zh from '$lib/i18n/zh';

vi.mock('$lib/jmap/client', () => ({
	uploadBlob: vi.fn().mockResolvedValue({ blobId: 'deadbeef00000000000000000000000000000000000000000000000000aa', size: 12 }),
	resetJmapAuthContext: vi.fn()
}));

const HR_APPROVAL_KEYS = [
	'approvals.hr.new_request_title',
	'approvals.hr.kind_label',
	'approvals.hr.kind_leave',
	'approvals.hr.kind_expense',
	'approvals.hr.leave_type_label',
	'approvals.hr.leave_type.annual',
	'approvals.hr.leave_type.sick',
	'approvals.hr.leave_type.personal',
	'approvals.hr.leave_type.marriage',
	'approvals.hr.leave_type.maternity',
	'approvals.hr.leave_type.paternity',
	'approvals.hr.leave_type.bereavement',
	'approvals.hr.leave_type.other',
	'approvals.hr.start_date_label',
	'approvals.hr.end_date_label',
	'approvals.hr.reason_label',
	'approvals.hr.currency_label',
	'approvals.hr.description_label',
	'approvals.hr.category_label',
	'approvals.hr.category.travel',
	'approvals.hr.category.meals',
	'approvals.hr.category.lodging',
	'approvals.hr.category.supplies',
	'approvals.hr.category.other',
	'approvals.hr.amount_label',
	'approvals.hr.receipt_label',
	'approvals.hr.add_item',
	'approvals.hr.total_label',
	'approvals.hr.submit',
	'approvals.consumer.hr_leave',
	'approvals.consumer.hr_expense',
];

function mockSubmitFetch(opts: { ok?: boolean; status?: number; body?: unknown } = {}) {
	const { ok = true, status = 201, body = { id: 42 } } = opts;
	let capturedBody: unknown = null;
	vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		if (url.includes('/me/approvals/hr')) {
			capturedBody = init?.body ? JSON.parse(init.body as string) : null;
			return { ok, status, json: async () => body, text: async () => JSON.stringify(body) };
		}
		return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
	}));
	return () => capturedBody;
}

describe('NewHrRequestDialog', () => {
	beforeEach(() => {
		resetStores();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('leave form: submit is disabled until start/end/reason are filled, then posts the exact payload contract', async () => {
		const getBody = mockSubmitFetch();
		const onSubmitted = vi.fn();
		await renderAsUser(NewHrRequestDialog, { open: true, onClose: vi.fn(), onSubmitted });

		const submitBtn = screen.getByRole('button', { name: t('approvals.hr.submit') });
		expect(submitBtn).toBeDisabled();

		const startInput = screen.getByLabelText(t('approvals.hr.start_date_label'));
		const endInput = screen.getByLabelText(t('approvals.hr.end_date_label'));
		const reasonInput = screen.getByLabelText(t('approvals.hr.reason_label'));

		await fireEvent.input(startInput, { target: { value: '2026-07-10' } });
		await fireEvent.input(endInput, { target: { value: '2026-07-12' } });
		await fireEvent.input(reasonInput, { target: { value: 'family trip' } });

		await waitFor(() => expect(submitBtn).not.toBeDisabled());
		await fireEvent.click(submitBtn);

		await waitFor(() => expect(onSubmitted).toHaveBeenCalled());
		const body = getBody() as { kind: string; form: Record<string, unknown> };
		expect(body.kind).toBe('hr.leave');
		expect(body.form).toEqual({
			leave_type: 'annual',
			start_date: '2026-07-10',
			end_date: '2026-07-12',
			days: 3,
			reason: 'family trip',
		});
	});

	it('leave form: end before start keeps the total invalid (days = 0, submit stays disabled)', async () => {
		mockSubmitFetch();
		await renderAsUser(NewHrRequestDialog, { open: true, onClose: vi.fn(), onSubmitted: vi.fn() });

		await fireEvent.input(screen.getByLabelText(t('approvals.hr.start_date_label')), { target: { value: '2026-07-12' } });
		await fireEvent.input(screen.getByLabelText(t('approvals.hr.end_date_label')), { target: { value: '2026-07-10' } });
		await fireEvent.input(screen.getByLabelText(t('approvals.hr.reason_label')), { target: { value: 'x' } });

		expect(screen.getByRole('button', { name: t('approvals.hr.submit') })).toBeDisabled();
	});

	it('expense form: add/remove line items, total auto-sums, and receipt upload attaches the sha', async () => {
		const getBody = mockSubmitFetch();
		const onSubmitted = vi.fn();
		await renderAsUser(NewHrRequestDialog, { open: true, onClose: vi.fn(), onSubmitted });

		await fireEvent.change(screen.getByLabelText(t('approvals.hr.kind_label')), { target: { value: 'hr.expense' } });

		const descriptionInputs = () => screen.getAllByLabelText(t('approvals.hr.description_label'));
		const amountInputs = () => screen.getAllByLabelText(t('approvals.hr.amount_label'));

		await fireEvent.input(descriptionInputs()[0], { target: { value: 'Taxi' } });
		await fireEvent.input(amountInputs()[0], { target: { value: '80.00' } });

		// upload a receipt on the first row
		const file = new File(['x'], 'receipt.pdf', { type: 'application/pdf' });
		const fileInput = screen.getByLabelText(t('approvals.hr.receipt_label')) as HTMLInputElement;
		await fireEvent.change(fileInput, { target: { files: [file] } });
		await waitFor(() => expect(screen.getByText(/receipt\.pdf/)).toBeInTheDocument());

		// add a second row
		await fireEvent.click(screen.getByRole('button', { name: t('approvals.hr.add_item') }));
		await fireEvent.input(descriptionInputs()[1], { target: { value: 'Hotel' } });
		await fireEvent.input(amountInputs()[1], { target: { value: '120.00' } });

		expect(screen.getByText(/200\.00/)).toBeInTheDocument(); // running total = 80 + 120

		await fireEvent.click(screen.getByRole('button', { name: t('approvals.hr.submit') }));
		await waitFor(() => expect(onSubmitted).toHaveBeenCalled());

		const body = getBody() as { kind: string; form: { currency: string; total_cents: number; line_items: Array<Record<string, unknown>> } };
		expect(body.kind).toBe('hr.expense');
		expect(body.form.total_cents).toBe(20000);
		expect(body.form.line_items).toHaveLength(2);
		expect(body.form.line_items[0]).toMatchObject({
			description: 'Taxi',
			amount_cents: 8000,
			receipt_sha256: 'deadbeef00000000000000000000000000000000000000000000000000aa',
			receipt_filename: 'receipt.pdf',
		});
		expect(body.form.line_items[1]).toMatchObject({ description: 'Hotel', amount_cents: 12000 });
	});

	it('a 400 response surfaces the reducer detail inline instead of throwing', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input.toString();
			if (url.includes('/me/approvals/hr')) {
				return { ok: false, status: 400, json: async () => ({ detail: 'reason required (1..2000 chars)' }), text: async () => '' };
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));
		await renderAsUser(NewHrRequestDialog, { open: true, onClose: vi.fn(), onSubmitted: vi.fn() });

		await fireEvent.input(screen.getByLabelText(t('approvals.hr.start_date_label')), { target: { value: '2026-07-10' } });
		await fireEvent.input(screen.getByLabelText(t('approvals.hr.end_date_label')), { target: { value: '2026-07-12' } });
		await fireEvent.input(screen.getByLabelText(t('approvals.hr.reason_label')), { target: { value: 'x' } });
		await fireEvent.click(screen.getByRole('button', { name: t('approvals.hr.submit') }));

		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('reason required'));
	});

	it('i18n keys resolve in en, de, zh — no missing-key fallback', () => {
		for (const key of HR_APPROVAL_KEYS) {
			expect(en[key], `en missing key: ${key}`).toBeDefined();
			expect(en[key], `en key falls back: ${key}`).not.toBe(key);
			expect(de[key], `de missing key: ${key}`).toBeDefined();
			expect(de[key], `de key falls back: ${key}`).not.toBe(key);
			expect(zh[key], `zh missing key: ${key}`).toBeDefined();
			expect(zh[key], `zh key falls back: ${key}`).not.toBe(key);
		}
	});
});
