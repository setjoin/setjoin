// AttendancePanel.test.ts — Meet B2 Task 10, spec §9: host/cohost-only
// ended-meeting attendance, client-computed duration, CSV export.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import AttendancePanel from './AttendancePanel.svelte';
import { formatDateTime } from '$lib/i18n';
import type { AttendanceRow } from '$lib/meet/api';

function row(over: Partial<AttendanceRow>): AttendanceRow {
	return {
		identity: 'u:1',
		displayName: 'Alice',
		role: 'host',
		isGuest: false,
		joinedAt: '2026-07-15T10:00:00Z',
		leftAt: '2026-07-15T10:30:00Z',
		...over,
	};
}

afterEach(() => vi.restoreAllMocks());

describe('AttendancePanel', () => {
	it('rows render name/joined/left via formatDateTime (not a raw ISO string)', () => {
		const r = row({});
		render(AttendancePanel, { attendance: [r] });
		expect(screen.getByText('Alice')).toBeTruthy();
		expect(screen.getByText(formatDateTime(r.joinedAt!))).toBeTruthy();
		expect(screen.getByText(formatDateTime(r.leftAt!))).toBeTruthy();
		expect(screen.queryByText(r.joinedAt!)).toBeNull();
	});

	it('duration is computed client-side from the two stamps', () => {
		render(AttendancePanel, { attendance: [row({ joinedAt: '2026-07-15T10:00:00Z', leftAt: '2026-07-15T10:30:00Z' })] });
		expect(screen.getByText('30m')).toBeTruthy();
	});

	it('duration renders — when joinedAt is null', () => {
		render(AttendancePanel, { attendance: [row({ joinedAt: null, leftAt: null })] });
		expect(screen.getAllByText('—').length).toBeGreaterThan(0);
	});

	it('a guest row shows the guest Badge', () => {
		render(AttendancePanel, { attendance: [row({ identity: 'g:1', displayName: 'Gary Guest', isGuest: true })] });
		expect(screen.getByText('Guest')).toBeTruthy();
	});

	it('the export button produces a CSV Blob whose header row is name,role,guest,joined,left,duration', async () => {
		let capturedBlob: Blob | null = null;
		vi.spyOn(URL, 'createObjectURL').mockImplementation((b: Blob | MediaSource) => {
			capturedBlob = b as Blob;
			return 'blob:mock';
		});
		vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
		render(AttendancePanel, { attendance: [row({})] });
		await fireEvent.click(screen.getByText('Export CSV'));
		expect(capturedBlob).toBeTruthy();
		const text = await (capturedBlob as unknown as Blob).text();
		expect(text.split('\n')[0]).toBe('name,role,guest,joined,left,duration');
	});

	it('renders nothing when attendance is empty (the anti-oracle)', () => {
		const { container } = render(AttendancePanel, { attendance: [] });
		expect(container.textContent?.trim()).toBe('');
	});
});
