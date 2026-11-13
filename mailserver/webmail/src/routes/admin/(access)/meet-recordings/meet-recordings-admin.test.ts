// meet-recordings-admin.test.ts — whole-pipeline review UX #11: the minimal
// read-only registry read over GET /admin/meet/recordings, drive.view-gated
// (the Drive admin page precedent — same perm, same $adminConsoles shape).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, waitFor } from '@testing-library/svelte/svelte5';
import { jmapSession } from '$lib/stores/session';
import { t } from '$lib/i18n';
import MeetRecordingsAdminPage from './+page.svelte';
import type { AdminMeetRecordingRow } from '$lib/admin/client';

const adminListMeetRecordings = vi.fn();

vi.mock('$lib/admin/client', async () => {
	const actual = await vi.importActual<typeof import('$lib/admin/client')>('$lib/admin/client');
	return {
		...actual,
		adminListMeetRecordings: (...a: unknown[]) => adminListMeetRecordings(...a),
	};
});

function row(over: Partial<AdminMeetRecordingRow> = {}): AdminMeetRecordingRow {
	return {
		id: 1,
		meetingId: 42,
		meetingTitle: 'Standup',
		state: 'ready',
		startedBy: 9,
		startedAt: '2026-07-10T07:00:00Z',
		stoppedAt: '2026-07-10T07:30:00Z',
		durationMs: 1_800_000,
		sizeBytes: 52_428_800,
		fileNodeId: 501,
		versionId: 900,
		...over,
	};
}

async function renderWithPerms(perms: string[]) {
	const result = await renderAsUser(MeetRecordingsAdminPage, {}, { isAdmin: true });
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

describe('Admin Meet recordings page (whole-pipeline review UX #11)', () => {
	beforeEach(() => {
		resetStores();
		adminListMeetRecordings.mockReset();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('renders the no-access empty state and never fetches without drive.view', async () => {
		await renderWithPerms([]);
		await waitFor(() => expect(screen.getByText(t('admin.meetRecordings.noAccess'))).toBeInTheDocument());
		expect(adminListMeetRecordings).not.toHaveBeenCalled();
	});

	it('renders an empty state when the registry has no rows', async () => {
		adminListMeetRecordings.mockResolvedValue([]);
		await renderWithPerms(['drive.view']);
		await waitFor(() => expect(screen.getByText(t('admin.meetRecordings.empty'))).toBeInTheDocument());
	});

	it('lists a recording row: meeting title/id, state badge, started/ended, size', async () => {
		adminListMeetRecordings.mockResolvedValue([row()]);
		await renderWithPerms(['drive.view']);
		await waitFor(() => expect(screen.getByText('Standup')).toBeInTheDocument());
		expect(screen.getByText('#42')).toBeInTheDocument();
		expect(screen.getByText(t('meet.recording.ready'))).toBeInTheDocument();
		expect(screen.getByText('50.0 MB')).toBeInTheDocument();
	});

	it('an in-flight state (requested/active/stopping) collapses into ONE "in progress" chip', async () => {
		adminListMeetRecordings.mockResolvedValue([row({ state: 'active', stoppedAt: undefined, sizeBytes: undefined })]);
		await renderWithPerms(['drive.view']);
		await waitFor(() => expect(screen.getByText(t('meet.recording.inProgress'))).toBeInTheDocument());
		// no end time / no size yet — both render the placeholder dash.
		expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2);
	});

	it('a failed row shows the failed badge', async () => {
		adminListMeetRecordings.mockResolvedValue([row({ state: 'failed', error: 'egress_busy' })]);
		await renderWithPerms(['drive.view']);
		await waitFor(() => expect(screen.getByText(t('meet.recording.failed'))).toBeInTheDocument());
	});

	it('a load failure surfaces an inline error message', async () => {
		adminListMeetRecordings.mockRejectedValue(new Error('Could not list recordings'));
		await renderWithPerms(['drive.view']);
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not list recordings'));
	});
});
