import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import { jmapSession } from '$lib/stores/session';
import { t } from '$lib/i18n';
import DriveAdminPage from './+page.svelte';
import type { DriveSpace, DriveLockRow } from '$lib/drive/api';

const listSpacesAdmin = vi.fn();
const listLocks = vi.fn();
const unlockFile = vi.fn();
const verifyAuditChain = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		listSpacesAdmin: (...a: unknown[]) => listSpacesAdmin(...a),
		listLocks: (...a: unknown[]) => listLocks(...a),
		unlockFile: (...a: unknown[]) => unlockFile(...a),
		verifyAuditChain: (...a: unknown[]) => verifyAuditChain(...a),
	};
});

const SPACES: DriveSpace[] = [
	{ id: 1, name: 'My Drive', isPersonal: true, classification: 'regular', role: 'manager', usedBytes: 0, quotaBytes: null, changeSeq: 0 },
];

function lockRow(overrides: Partial<DriveLockRow> = {}): DriveLockRow {
	return {
		nodeId: 501,
		name: 'report.docx',
		holderId: 9,
		holderName: 'Bob',
		mode: 'hard',
		branchId: null,
		acquiredAt: '2026-07-10T07:00:00Z',
		expiresAt: '2026-07-10T15:00:00Z',
		deviceLabel: null,
		...overrides,
	};
}

async function renderWithPerms(perms: string[]) {
	const result = await renderAsUser(DriveAdminPage, {}, { isAdmin: true });
	jmapSession.set({
		accounts: { a1: { name: 'alice@test.local', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: { consoles: ['mail', 'system', 'logs', 'auth'], permissions: perms },
			},
		},
	} as any);
	return result;
}

describe('Admin Drive page — lock list (P4 Task 15)', () => {
	beforeEach(() => {
		resetStores();
		listSpacesAdmin.mockReset();
		listLocks.mockReset();
		unlockFile.mockReset();
		verifyAuditChain.mockReset();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('renders nothing (gated) without drive.view', async () => {
		listSpacesAdmin.mockResolvedValue(SPACES);
		await renderWithPerms([]);
		await new Promise((r) => setTimeout(r, 10));
		expect(listSpacesAdmin).not.toHaveBeenCalled();
	});

	it('lists active checkouts for the first (auto-selected) space and shows Break for drive.manage', async () => {
		listSpacesAdmin.mockResolvedValue(SPACES);
		listLocks.mockResolvedValue({ locks: [lockRow()] });
		await renderWithPerms(['drive.view', 'drive.manage']);
		await waitFor(() => expect(screen.getByText('report.docx')).toBeInTheDocument());
		expect(screen.getByText('Bob')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: t('drive.admin.lockList.break') })).toBeInTheDocument();
	});

	it('hides the Break action for drive.view-only (no drive.manage)', async () => {
		listSpacesAdmin.mockResolvedValue(SPACES);
		listLocks.mockResolvedValue({ locks: [lockRow()] });
		await renderWithPerms(['drive.view']);
		await waitFor(() => expect(screen.getByText('report.docx')).toBeInTheDocument());
		expect(screen.queryByRole('button', { name: t('drive.admin.lockList.break') })).not.toBeInTheDocument();
	});

	it('breaking a checkout confirms then calls unlockFile with break:true', async () => {
		listSpacesAdmin.mockResolvedValue(SPACES);
		listLocks.mockResolvedValue({ locks: [lockRow()] });
		unlockFile.mockResolvedValue(undefined);
		await renderWithPerms(['drive.view', 'drive.manage']);
		await waitFor(() => expect(screen.getByText('report.docx')).toBeInTheDocument());

		await fireEvent.click(screen.getByRole('button', { name: t('drive.admin.lockList.break') }));
		expect(screen.getByText(t('drive.admin.lockList.confirmBreak', { name: 'report.docx' }))).toBeInTheDocument();
		await fireEvent.click(screen.getAllByRole('button', { name: t('drive.admin.lockList.break') })[1]);
		await waitFor(() => expect(unlockFile).toHaveBeenCalledWith(501, { break: true }));
	});

	it('shows the spaces table with a classification badge and a wormPending count, and mounts the compliance panel for the selected space', async () => {
		listSpacesAdmin.mockResolvedValue([
			{ id: 1, name: 'Quality Records', isPersonal: false, classification: 'gxp', role: 'admin', usedBytes: 0, quotaBytes: null, changeSeq: 0, wormPending: 2 },
		]);
		listLocks.mockResolvedValue({ locks: [] });
		await renderWithPerms(['drive.view', 'drive.manage']);
		await waitFor(() => expect(screen.getByText('Quality Records')).toBeInTheDocument());
		expect(screen.getByText('GxP')).toBeInTheDocument();
		// One "2" in the spaces-table wormPending column, one in the
		// compliance panel's own worm-pending row (same count, two renders).
		expect(screen.getAllByText('2').length).toBeGreaterThanOrEqual(1);
		// The compliance panel auto-mounts for the first space (auto-selected).
		expect(screen.getByText('Compliance')).toBeInTheDocument();
	});

	it('clicking Manage on a different row switches the selected space', async () => {
		listSpacesAdmin.mockResolvedValue([
			{ id: 1, name: 'My Drive', isPersonal: true, classification: 'regular', role: 'manager', usedBytes: 0, quotaBytes: null, changeSeq: 0 },
			{ id: 2, name: 'Quality Records', isPersonal: false, classification: 'gxp', role: 'admin', usedBytes: 0, quotaBytes: null, changeSeq: 0 },
		]);
		listLocks.mockResolvedValue({ locks: [] });
		await renderWithPerms(['drive.view', 'drive.manage']);
		await waitFor(() => expect(screen.getByText('Quality Records')).toBeInTheDocument());
		const manageButtons = screen.getAllByRole('button', { name: t('drive.compliance.spacesTable.manage') });
		await fireEvent.click(manageButtons[1]);
		await waitFor(() => expect(listLocks).toHaveBeenCalledWith(2));
	});
});
