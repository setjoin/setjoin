import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import CompliancePanel from './CompliancePanel.svelte';
import type { DriveSpace } from '$lib/drive/api';

const patchSpace = vi.fn();
const verifyAuditChain = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		patchSpace: (...a: unknown[]) => patchSpace(...a),
		verifyAuditChain: (...a: unknown[]) => verifyAuditChain(...a),
	};
});

function space(overrides: Partial<DriveSpace> = {}): DriveSpace {
	return {
		id: 7,
		name: 'Quality Records',
		isPersonal: false,
		classification: 'regular',
		role: 'admin',
		usedBytes: 0,
		quotaBytes: null,
		changeSeq: 1,
		...overrides,
	};
}

const noop = vi.fn();

describe('CompliancePanel', () => {
	beforeEach(() => {
		patchSpace.mockReset();
		verifyAuditChain.mockReset();
	});

	it('offers only strictly higher classifications for upgrade (regular -> secure/gxp)', () => {
		render(CompliancePanel, { space: space({ classification: 'regular' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		const select = screen.getByLabelText('Upgrade classification to') as HTMLSelectElement;
		const values = Array.from(select.options).map((o) => o.value);
		expect(values).toEqual(['', 'secure', 'gxp']);
	});

	it('offers nothing to upgrade to when already gxp (no-downgrade UI)', () => {
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		expect(screen.queryByLabelText('Upgrade classification to')).toBeNull();
		expect(screen.getByText('This space is already at the highest classification.')).toBeTruthy();
	});

	it('hides upgrade and knob controls entirely when the caller lacks drive.manage', () => {
		render(CompliancePanel, { space: space({ classification: 'regular' }), wormPending: 0, canManage: false, canView: true, onchanged: noop });
		expect(screen.queryByLabelText('Upgrade classification to')).toBeNull();
	});

	it('reveals retention/worm-mode knobs only once gxp is chosen, and requires both before Upgrade is enabled', async () => {
		render(CompliancePanel, { space: space({ classification: 'regular' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		const select = screen.getByLabelText('Upgrade classification to') as HTMLSelectElement;
		expect(screen.queryByLabelText('Retention period (days)')).toBeNull();

		await fireEvent.change(select, { target: { value: 'gxp' } });
		expect(screen.getByLabelText('Retention period (days)')).toBeTruthy();
		const upgradeBtn = screen.getByRole('button', { name: 'Upgrade' });
		expect(upgradeBtn).toBeDisabled();

		await fireEvent.input(screen.getByLabelText('Retention period (days)'), { target: { value: '30' } });
		expect(upgradeBtn).not.toBeDisabled();
	});

	it('upgrade goes through a confirm dialog before calling patchSpace, with retentionDays/wormMode for a gxp target', async () => {
		patchSpace.mockResolvedValue(undefined);
		const onchanged = vi.fn();
		render(CompliancePanel, { space: space({ classification: 'regular' }), wormPending: 0, canManage: true, canView: true, onchanged });

		await fireEvent.change(screen.getByLabelText('Upgrade classification to'), { target: { value: 'gxp' } });
		await fireEvent.input(screen.getByLabelText('Retention period (days)'), { target: { value: '90' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Upgrade' }));

		// Confirm dialog must appear; patchSpace must NOT have fired yet.
		expect(screen.getByText(/Upgrade to .* classification\?/)).toBeTruthy();
		expect(patchSpace).not.toHaveBeenCalled();

		await fireEvent.click(screen.getByRole('button', { name: 'Confirm upgrade' }));
		await vi.waitFor(() =>
			expect(patchSpace).toHaveBeenCalledWith(7, { classification: 'gxp', retentionDays: 90, wormMode: 'governance' }),
		);
		await vi.waitFor(() => expect(onchanged).toHaveBeenCalled());
	});

	it('shows the worm-pending count with an icon (never color alone) and the retry/backend-note copy on a gxp space', () => {
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 3, canManage: true, canView: true, onchanged: noop });
		expect(screen.getByText('3')).toBeTruthy();
		expect(screen.getByText('WORM locks pending')).toBeTruthy();
		expect(screen.getByText('Retried automatically every 5 minutes')).toBeTruthy();
		expect(screen.getByText(/Object-Lock support/)).toBeTruthy();
	});

	it('shows the all-clear state at zero pending', () => {
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		expect(screen.getByText('All object locks applied')).toBeTruthy();
	});

	it('verify-chain: verifying -> clean state reports the checked count', async () => {
		verifyAuditChain.mockResolvedValue({ checked: 12, broken: [] });
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		await fireEvent.click(screen.getByRole('button', { name: 'Verify audit chain' }));
		await vi.waitFor(() => expect(screen.getByText('Chain intact — 12 rows checked')).toBeTruthy());
	});

	it('verify-chain: broken state lists the broken row ids', async () => {
		verifyAuditChain.mockResolvedValue({ checked: 5, broken: [3, 4] });
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		await fireEvent.click(screen.getByRole('button', { name: 'Verify audit chain' }));
		await vi.waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
		expect(screen.getByText(/5 rows checked/)).toBeTruthy();
		expect(screen.getByText(/3, 4/)).toBeTruthy();
	});

	it('hides the verify-chain button when the caller lacks drive.view', () => {
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 0, canManage: true, canView: false, onchanged: noop });
		expect(screen.queryByRole('button', { name: 'Verify audit chain' })).toBeNull();
	});

	it('shows the Part-11-CAPABLE sentence on a gxp space, and NEVER claims "compliant"', () => {
		render(CompliancePanel, { space: space({ classification: 'gxp' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		const text = document.body.textContent ?? '';
		expect(text).toContain('Part-11-CAPABLE');
		expect(text.toLowerCase()).not.toContain('part-11 compliant');
		expect(text.toLowerCase()).not.toContain('part 11 compliant');
	});

	it('does not show the Part-11 sentence for a non-gxp space', () => {
		render(CompliancePanel, { space: space({ classification: 'secure' }), wormPending: 0, canManage: true, canView: true, onchanged: noop });
		expect(screen.queryByText(/Part-11-CAPABLE/)).toBeNull();
	});
});
