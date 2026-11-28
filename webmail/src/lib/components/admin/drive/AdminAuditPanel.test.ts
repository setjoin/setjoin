import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import AdminAuditPanel from './AdminAuditPanel.svelte';

const mocks = vi.hoisted(() => ({
	getAuditActions: vi.fn(),
	queryAudit: vi.fn(),
	listAuditAlarms: vi.fn(),
	auditCsvUrl: vi.fn(() => '/api/drive/audit?format=csv'),
	createAuditAlarm: vi.fn(),
	updateAuditAlarm: vi.fn(),
	deleteAuditAlarm: vi.fn(),
	subscribeEvent: vi.fn(),
	alarmHandler: undefined as undefined | ((event: Record<string, unknown>) => void),
}));

vi.mock('$lib/drive/api', async () => ({
	...(await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api')),
	getAuditActions: mocks.getAuditActions,
	queryAudit: mocks.queryAudit,
	listAuditAlarms: mocks.listAuditAlarms,
	auditCsvUrl: mocks.auditCsvUrl,
	createAuditAlarm: mocks.createAuditAlarm,
	updateAuditAlarm: mocks.updateAuditAlarm,
	deleteAuditAlarm: mocks.deleteAuditAlarm,
}));

vi.mock('$lib/jmap/websocket', async () => ({
	...(await vi.importActual<typeof import('$lib/jmap/websocket')>('$lib/jmap/websocket')),
	subscribeEvent: mocks.subscribeEvent,
}));

const rows = [
	{ id: 12, occurredAt: '2026-07-20T10:05:00Z', userId: 5, userEmail: 'alice@example.test', ip: '192.0.2.5', action: 'node.read', notes: 'opened' },
	{ id: 11, occurredAt: '2026-07-20T10:00:00Z', userId: 5, userEmail: 'alice@example.test', ip: '192.0.2.5', action: 'node.read' },
];
const alarm = { id: 3, spaceId: null, actionPattern: 'node.*', threshold: 5, windowMinutes: 10, enabled: true, createdBy: 1, createdAt: '2026-07-20T09:00:00Z' };

describe('AdminAuditPanel', () => {
	beforeEach(() => {
		mocks.getAuditActions.mockReset().mockResolvedValue(['node.read', 'node.download']);
		mocks.queryAudit.mockReset().mockImplementation((params: { action?: string }) => Promise.resolve(params.action === 'alarm.fire' ? { items: [rows[0]], hasMore: false } : { items: rows, hasMore: true }));
		mocks.listAuditAlarms.mockReset().mockResolvedValue([alarm]);
		mocks.createAuditAlarm.mockReset().mockResolvedValue({ id: 4 });
		mocks.updateAuditAlarm.mockReset().mockResolvedValue(undefined);
		mocks.deleteAuditAlarm.mockReset().mockResolvedValue(undefined);
		mocks.subscribeEvent.mockReset().mockImplementation((_type, handler) => {
			mocks.alarmHandler = handler;
			return vi.fn();
		});
	});

	it('loads rows, groups a session, exposes CSV, and expands the raw evidence', async () => {
		render(AdminAuditPanel, { spaceId: 7, canManage: true });
		await vi.waitFor(() => expect(screen.getByText(/alice@example\.test/)).toBeTruthy());
		expect(mocks.queryAudit).toHaveBeenCalledWith(expect.objectContaining({ spaceId: 7, max: 50 }));
		expect(screen.getByRole('link', { name: /Export CSV/ })).toHaveAttribute('href', '/api/drive/audit?format=csv');

		await fireEvent.click(screen.getByRole('button', { name: /alice@example\.test/ }));
		expect(screen.getAllByText('node.read').length).toBeGreaterThan(0);
		await fireEvent.click(screen.getByRole('button', { name: 'Raw events' }));
		expect(screen.getAllByText('alice@example.test').length).toBeGreaterThan(0);
		await fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
		await vi.waitFor(() => expect(mocks.queryAudit).toHaveBeenCalledWith(expect.objectContaining({ beforeId: 11 })));
	});

	it('creates, toggles, and deletes an alarm only for a manager', async () => {
		render(AdminAuditPanel, { spaceId: 7, canManage: true });
		await vi.waitFor(() => expect(screen.getByText('node.*')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'New alarm rule' }));
		const createButtons = screen.getAllByRole('button', { name: 'New alarm rule' });
		await fireEvent.click(createButtons.at(-1)!);
		await vi.waitFor(() => expect(mocks.createAuditAlarm).toHaveBeenCalledWith({
			spaceId: 7,
			actionPattern: 'node.read',
			threshold: 5,
			windowMinutes: 10,
		}));

		await fireEvent.click(screen.getByRole('switch', { name: 'Enabled' }));
		await vi.waitFor(() => expect(mocks.updateAuditAlarm).toHaveBeenCalledWith(3, { enabled: false }));
		await fireEvent.click(screen.getByRole('button', { name: 'Delete rule' }));
		const deleteButtons = screen.getAllByRole('button', { name: 'Delete rule' });
		await fireEvent.click(deleteButtons.at(-1)!);
		await vi.waitFor(() => expect(mocks.deleteAuditAlarm).toHaveBeenCalledWith(3));
	});

	it('subscribes only for managers and refreshes after a live alarm', async () => {
		render(AdminAuditPanel, { spaceId: 7, canManage: true });
		await vi.waitFor(() => expect(mocks.alarmHandler).toBeTypeOf('function'));
		mocks.alarmHandler?.({ pattern: 'node.read', hits: 8 });
		await vi.waitFor(() => expect(screen.getByRole('status').textContent).toContain('node.read'));
		expect(mocks.queryAudit).toHaveBeenCalledWith(expect.objectContaining({ action: 'alarm.fire' }));
	});

	it('renders read-only and error states without management actions', async () => {
		mocks.getAuditActions.mockRejectedValueOnce(new Error('catalog unavailable'));
		mocks.queryAudit.mockRejectedValue(new Error('audit unavailable'));
		mocks.listAuditAlarms.mockResolvedValue([]);
		render(AdminAuditPanel, { spaceId: 8, canManage: false });
		await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toContain('An error occurred'));
		expect(screen.queryByRole('button', { name: 'New alarm rule' })).toBeNull();
		expect(mocks.subscribeEvent).not.toHaveBeenCalled();
	});
});
