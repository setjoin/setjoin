// mailserver/webmail/src/routes/admin/(logs)/audit/audit.test.ts
// Task 8: verify-integrity view — TDD (RED → GREEN)
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, waitFor, screen } from '@testing-library/svelte';
import { renderAsUser, resetStores } from '$lib/test-utils';

// ── module mocks (hoisted — same pattern as welcomeForm.svelte.test.ts) ──
const mockFetchAuditLog = vi.fn();
const mockExportAuditCSV = vi.fn();
const mockVerifyAuditChain = vi.fn();
const mockGetAuditPolicy = vi.fn();
const mockPutAuditPolicy = vi.fn();

vi.mock('$lib/admin/client', () => ({
	fetchAuditLog: (...a: unknown[]) => mockFetchAuditLog(...a),
	exportAuditCSV: (...a: unknown[]) => mockExportAuditCSV(...a),
	verifyAuditChain: (...a: unknown[]) => mockVerifyAuditChain(...a),
	getAuditPolicy: (...a: unknown[]) => mockGetAuditPolicy(...a),
	putAuditPolicy: (...a: unknown[]) => mockPutAuditPolicy(...a),
	// Passthrough for any other named exports the component might import
}));

import AuditPage from './+page.svelte';

// ── helpers ───────────────────────────────────────────────────────────

function makeAuditItem(id: number) {
	return {
		id,
		occurredAt: `2026-06-24T10:00:${String(id % 60).padStart(2, '0')}Z`,
		userId: 1,
		userEmail: 'admin@test.local',
		ip: '127.0.0.1',
		action: 'user.create',
		targetType: 'user',
		targetId: id,
		notes: `note ${id}`,
	};
}

function setAuditItems(items: ReturnType<typeof makeAuditItem>[]) {
	mockFetchAuditLog.mockResolvedValue({ items, total: items.length });
}

// ── tests ──────────────────────────────────────────────────────────────

describe('Audit page — verify integrity', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		mockExportAuditCSV.mockResolvedValue(new Blob(['csv'], { type: 'text/csv' }));
		mockVerifyAuditChain.mockResolvedValue({ chain: [] });
	});

	it('shows Verify integrity button when log has entries', async () => {
		setAuditItems([makeAuditItem(10), makeAuditItem(11)]);
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => {
			expect(screen.getByRole('button', { name: /verify integrity/i })).toBeInTheDocument();
		});
	});

	it('disables Verify integrity button when log is empty', async () => {
		setAuditItems([]);
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => {
			const btn = screen.getByRole('button', { name: /verify integrity/i });
			expect(btn).toBeDisabled();
		});
	});

	it('clicking Verify calls verifyAuditChain with the id-range of displayed rows', async () => {
		const items = [makeAuditItem(5), makeAuditItem(8), makeAuditItem(12)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({ chain: [] });

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => {
			expect(mockVerifyAuditChain).toHaveBeenCalledWith(5, 12); // min(id)=5, max(id)=12
		});
	});

	it('shows Verifying spinner text while in-flight', async () => {
		const items = [makeAuditItem(1), makeAuditItem(2)];
		setAuditItems(items);
		let resolveVerify!: (v: object) => void;
		mockVerifyAuditChain.mockReturnValue(new Promise((res) => { resolveVerify = res; }));

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => {
			expect(screen.getByText(/verifying rows/i)).toBeInTheDocument();
		});

		resolveVerify({ chain: [] });
	});

	it('intact result — shows success banner and ✓ validity labels on rows', async () => {
		const items = [makeAuditItem(3), makeAuditItem(4)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({
			chain: [
				{ id: 3, valid: true, occurredAt: items[0].occurredAt, action: 'user.create' },
				{ id: 4, valid: true, occurredAt: items[1].occurredAt, action: 'user.create' },
			],
		});

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => {
			expect(screen.getByText(/chain intact/i)).toBeInTheDocument();
		});
		// ✓ labels (aria-label="valid") present for each row
		const validLabels = screen.getAllByLabelText('valid');
		expect(validLabels.length).toBe(2);
	});

	it('tamper result — danger banner names the first broken row', async () => {
		const items = [makeAuditItem(20), makeAuditItem(21), makeAuditItem(22)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({
			chain: [
				{ id: 20, valid: true,  occurredAt: items[0].occurredAt, action: 'user.create' },
				{ id: 21, valid: false, occurredAt: items[1].occurredAt, action: 'user.create' },
				{ id: 22, valid: false, occurredAt: items[2].occurredAt, action: 'user.create' },
			],
		});

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => {
			expect(screen.getByText(/tamper detected/i)).toBeInTheDocument();
			expect(screen.getByText(/row 21/i)).toBeInTheDocument();
		});
	});

	it('tamper result — banner has aria-live="assertive"', async () => {
		const items = [makeAuditItem(30), makeAuditItem(31)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({
			chain: [
				{ id: 30, valid: true,  occurredAt: items[0].occurredAt, action: 'user.create' },
				{ id: 31, valid: false, occurredAt: items[1].occurredAt, action: 'user.create' },
			],
		});

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => screen.getByText(/tamper detected/i));

		const banner = screen.getByText(/tamper detected/i).closest('[aria-live]');
		expect(banner).not.toBeNull();
		expect(banner!.getAttribute('aria-live')).toBe('assertive');
	});

	it('tamper result — Export evidence button is present', async () => {
		const items = [makeAuditItem(40), makeAuditItem(41)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({
			chain: [
				{ id: 40, valid: true,  occurredAt: items[0].occurredAt, action: 'user.create' },
				{ id: 41, valid: false, occurredAt: items[1].occurredAt, action: 'user.create' },
			],
		});

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => {
			expect(screen.getByRole('button', { name: /export evidence/i })).toBeInTheDocument();
		});
	});

	it('tamper result — INVALID aria-labels on broken rows', async () => {
		const items = [makeAuditItem(50), makeAuditItem(51)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({
			chain: [
				{ id: 50, valid: true,  occurredAt: items[0].occurredAt, action: 'user.create' },
				{ id: 51, valid: false, occurredAt: items[1].occurredAt, action: 'user.create' },
			],
		});

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => screen.getByText(/tamper detected/i));

		expect(screen.getByLabelText('valid')).toBeInTheDocument();
		expect(screen.getByLabelText('INVALID')).toBeInTheDocument();
	});

	it('verify uses id-range not filters — calls with min/max id of loaded rows', async () => {
		// Non-contiguous ids to prove we use min/max not count/offset
		const items = [makeAuditItem(100), makeAuditItem(200), makeAuditItem(300)];
		setAuditItems(items);
		mockVerifyAuditChain.mockResolvedValue({ chain: [] });

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('button', { name: /verify integrity/i }));

		fireEvent.click(screen.getByRole('button', { name: /verify integrity/i }));

		await waitFor(() => expect(mockVerifyAuditChain).toHaveBeenCalledWith(100, 300));
	});
});

// ── Policy editor tests (Task 9) ──────────────────────────────────────────────

describe('Audit page — policy editor', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		mockExportAuditCSV.mockResolvedValue(new Blob(['csv'], { type: 'text/csv' }));
		mockVerifyAuditChain.mockResolvedValue({ chain: [] });
		setAuditItems([makeAuditItem(1)]);
		// Default: lean policy, no reason-required areas
		mockGetAuditPolicy.mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		mockPutAuditPolicy.mockResolvedValue(undefined);
	});

	it('renders the policy editor card', async () => {
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => {
			expect(screen.getByText(/audit policy/i)).toBeInTheDocument();
		});
	});

	it('shows the prominent reassurance line', async () => {
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => {
			expect(screen.getByText(/lean still logs/i)).toBeInTheDocument();
		});
	});

	it('shows lean and full level controls', async () => {
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => {
			expect(screen.getByRole('radio', { name: /lean/i })).toBeInTheDocument();
			expect(screen.getByRole('radio', { name: /full/i })).toBeInTheDocument();
		});
	});

	it('Save button is disabled when policy is unmodified (not dirty)', async () => {
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByText(/audit policy/i));
		// The save button should not be present / disabled when policy matches server
		const saves = screen.queryAllByRole('button', { name: /save/i });
		// Either absent or disabled
		for (const save of saves) {
			expect(save).toBeDisabled();
		}
	});

	it('switching level to full makes policy dirty and enables Save', async () => {
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('radio', { name: /full/i }));

		fireEvent.click(screen.getByRole('radio', { name: /full/i }));

		await waitFor(() => {
			const saveBtn = screen.getByRole('button', { name: /save/i });
			expect(saveBtn).not.toBeDisabled();
		});
	});

	it('raising from lean to full saves directly (no confirm dialog)', async () => {
		// lean → full is a coverage raise, should save without a dialog
		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('radio', { name: /full/i }));

		fireEvent.click(screen.getByRole('radio', { name: /full/i }));
		await waitFor(() => screen.getByRole('button', { name: /save/i }));
		fireEvent.click(screen.getByRole('button', { name: /save/i }));

		await waitFor(() => {
			expect(mockPutAuditPolicy).toHaveBeenCalledWith({
				level: 'full',
				reasonRequiredAreas: [],
				reason: '',
			});
		});
		// No confirm dialog should appear
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('lowering from full to lean opens a confirm dialog with a required reason', async () => {
		mockGetAuditPolicy.mockResolvedValue({ level: 'full', reasonRequiredAreas: [] });

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('radio', { name: /lean/i }));

		fireEvent.click(screen.getByRole('radio', { name: /lean/i }));
		await waitFor(() => screen.getByRole('button', { name: /save/i }));
		fireEvent.click(screen.getByRole('button', { name: /save/i }));

		await waitFor(() => {
			expect(screen.getByRole('dialog')).toBeInTheDocument();
			// Reason field must be present in the dialog
			expect(screen.getByLabelText(/reason/i)).toBeInTheDocument();
		});
	});

	it('confirm dialog: submit disabled while reason is empty', async () => {
		mockGetAuditPolicy.mockResolvedValue({ level: 'full', reasonRequiredAreas: [] });

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('radio', { name: /lean/i }));

		fireEvent.click(screen.getByRole('radio', { name: /lean/i }));
		await waitFor(() => screen.getByRole('button', { name: /save/i }));
		fireEvent.click(screen.getByRole('button', { name: /save/i }));

		await waitFor(() => screen.getByRole('dialog'));

		// "Confirm" / "Save" submit inside dialog is disabled because reason is empty
		const confirmBtns = screen.getAllByRole('button', { name: /confirm|apply/i });
		for (const b of confirmBtns) {
			expect(b).toBeDisabled();
		}
	});

	it('confirm dialog: providing a reason enables submit and calls putAuditPolicy', async () => {
		mockGetAuditPolicy.mockResolvedValue({ level: 'full', reasonRequiredAreas: [] });

		await renderAsUser(AuditPage, {}, { isAdmin: true });
		await waitFor(() => screen.getByRole('radio', { name: /lean/i }));

		fireEvent.click(screen.getByRole('radio', { name: /lean/i }));
		await waitFor(() => screen.getByRole('button', { name: /save/i }));
		fireEvent.click(screen.getByRole('button', { name: /save/i }));

		await waitFor(() => screen.getByRole('dialog'));

		const reasonField = screen.getByLabelText(/reason/i);
		await fireEvent.input(reasonField, { target: { value: 'reducing verbosity per ops request' } });

		const confirmBtn = screen.getByRole('button', { name: /confirm|apply/i });
		expect(confirmBtn).not.toBeDisabled();
		await fireEvent.click(confirmBtn);

		await waitFor(() => {
			expect(mockPutAuditPolicy).toHaveBeenCalledWith({
				level: 'lean',
				reasonRequiredAreas: [],
				reason: 'reducing verbosity per ops request',
			});
		});
	});
});
