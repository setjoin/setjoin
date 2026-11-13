import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render } from '@testing-library/svelte/svelte5';
import MailWorkRail from './MailWorkRail.svelte';
import { user } from '$lib/stores/auth';

const mocks = vi.hoisted(() => ({
	get: vi.fn(), set: vi.fn(), commentGet: vi.fn(), commentSet: vi.fn(),
	prefsGet: vi.fn(), prefSet: vi.fn(), metricsGet: vi.fn(), action: vi.fn(),
	conversations: vi.fn(), spaces: vi.fn(), tree: vi.fn(), collaborators: vi.fn(),
	policyGet: vi.fn(), policySet: vi.fn(),
}));

vi.mock('$lib/mail/mailWork', () => ({
	mailWorkGet: mocks.get,
	mailWorkSet: mocks.set,
	mailCommentGet: mocks.commentGet,
	mailCommentSet: mocks.commentSet,
	mailWorkNotificationPreferencesGet: mocks.prefsGet,
	mailWorkNotificationPreferenceSet: mocks.prefSet,
	mailWorkMetricsGet: mocks.metricsGet,
	mailWorkAction: mocks.action,
	mailWorkCollaboratorsGet: mocks.collaborators,
	mailWorkPolicyGet: mocks.policyGet,
	mailWorkPolicySet: mocks.policySet,
}));

vi.mock('$lib/chat/api', () => ({ listConversations: mocks.conversations }));
vi.mock('$lib/drive/api', () => ({ listSpaces: mocks.spaces, tree: mocks.tree }));
beforeEach(() => {
	vi.clearAllMocks();
	user.set({ email: 'agent@example.test', displayName: 'Agent', isAdmin: false, hasMailbox: true, userId: 7 });
	mocks.get.mockResolvedValue({ accountId: '99', state: '0', list: [] });
	mocks.set.mockResolvedValue({ id: 'thread-1', generation: '1', status: 'owned' });
	mocks.commentGet.mockResolvedValue([]);
	mocks.commentSet.mockResolvedValue(undefined);
	mocks.prefsGet.mockResolvedValue([{ category: 'due', delivery: 'digest', timezone: 'UTC', digestHour: 9, generation: '0' }]);
	mocks.prefSet.mockResolvedValue({ category: 'due', delivery: 'immediate', timezone: 'UTC', digestHour: 9, generation: '1' });
	mocks.metricsGet.mockResolvedValue({ accountId: '99', available: false, minimumActors: 5, minimumConversations: 20 });
	mocks.action.mockResolvedValue({ eventId: 'event-1', outboxId: '1', generation: '4', replayed: false });
	mocks.conversations.mockResolvedValue({ conversations: [{ channelId: 11, name: 'Escalations' }], attachmentsEnabled: true });
	mocks.spaces.mockResolvedValue([{ id: 12, name: 'Support' }]);
	mocks.tree.mockResolvedValue([{ id: 13, name: 'Runbook', capabilities: ['read_metadata'] }]);
	mocks.collaborators.mockResolvedValue([{ id: '8', displayName: 'Ada', email: 'ada@example.test', capability: 'comment' }]);
	mocks.policyGet.mockResolvedValue({ accountId: '99', canManage: false, policy: {
		version: 1, timezone: 'UTC', weekdayMask: 62, workdayStart: '09:00:00', workdayEnd: '17:00:00',
		holidays: [], slaMinutes: 480, source: 'organization_default',
	} });
	mocks.policySet.mockResolvedValue({ accountId: '99', canManage: true, policy: {
		version: 1, timezone: 'Asia/Shanghai', weekdayMask: 62, workdayStart: '09:00:00', workdayEnd: '18:00:00',
		holidays: ['2026-10-01'], slaMinutes: 240, generation: '2', source: 'mailbox',
	}, operationId: 'policy-op', replayed: false });
});

describe('MailWorkRail', () => {
	it('claims an unassigned thread only after an explicit click', async () => {
		const { getByText } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: false, onClose: vi.fn(),
		});
		await vi.waitFor(() => expect(getByText('Claim conversation')).toBeTruthy());
		expect(mocks.set).not.toHaveBeenCalled();
		await fireEvent.click(getByText('Claim conversation'));
		expect(mocks.set).toHaveBeenCalledWith(expect.objectContaining({
			accountId: '99', threadId: 'thread-1', action: 'claim', expectedGeneration: '0',
		}));
	});

	it('keeps read-only delegates on a non-mutating surface', async () => {
		const { container } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: false,
			commentsEnabled: false, onClose: vi.fn(),
		});
		await vi.waitFor(() => expect(container.textContent).toContain('View only'));
		expect(container.textContent).not.toContain('Claim conversation');
		expect(mocks.set).not.toHaveBeenCalled();
	});

	it('submits private comments with the current work generation', async () => {
		mocks.get.mockResolvedValue({ accountId: '99', state: '4', list: [{
			id: 'thread-1', threadId: 'thread-1', status: 'owned', assigneeUserId: '7',
			dueAt: null, generation: '3',
		}] });
		const { getByLabelText, getByText } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: true, onClose: vi.fn(),
		});
		const input = await vi.waitFor(() => getByLabelText('Private comment'));
		await fireEvent.input(input, { target: { value: 'Only delegates see this' } });
		await fireEvent.click(getByText('Add comment'));
		expect(mocks.commentSet).toHaveBeenCalledWith({
			accountId: '99', threadId: 'thread-1', expectedGeneration: '3', body: 'Only delegates see this',
		});
	});

	it('polls the delegated mailbox while visible and stops after unmount', async () => {
		vi.useFakeTimers();
		const { unmount } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: false, onClose: vi.fn(),
		});
		await vi.advanceTimersByTimeAsync(0);
		expect(mocks.get).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(10_000);
		expect(mocks.get).toHaveBeenCalledTimes(2);
		unmount();
		await vi.advanceTimersByTimeAsync(10_000);
		expect(mocks.get).toHaveBeenCalledTimes(2);
		vi.useRealTimers();
	});

	it('shows calm notification defaults and cohort-safe analytics without individual scores', async () => {
		const { getByLabelText, getByText, container } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: false, notificationsEnabled: true, analyticsEnabled: true, onClose: vi.fn(),
		});
		const due = await vi.waitFor(() => getByLabelText('Due soon'));
		expect((due as HTMLSelectElement).value).toBe('digest');
		expect(getByText(/at least 5 eligible people and 20 external conversations/)).toBeTruthy();
		expect(container.textContent).not.toContain('actorUserId');
		await fireEvent.change(due, { target: { value: 'immediate' } });
		expect(mocks.prefSet).toHaveBeenCalledWith(expect.objectContaining({
			accountId: '99', category: 'due', delivery: 'immediate', expectedGeneration: '0',
		}));
	});

	it('queues only a selected, authorized internal target and never accepts a raw typed id', async () => {
		mocks.get.mockResolvedValue({ accountId: '99', state: '4', list: [{
			id: 'thread-1', threadId: 'thread-1', status: 'owned', assigneeUserId: '7',
			dueAt: null, generation: '3',
		}] });
		const { getByLabelText, getByText } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: false, integrationsEnabled: true, onClose: vi.fn(),
		});
		const chat = await vi.waitFor(() => getByLabelText('Chat conversation'));
		expect(getByText('Post link to Chat').closest('button')?.hasAttribute('disabled')).toBe(true);
		await fireEvent.change(chat, { target: { value: '11' } });
		await fireEvent.click(getByText('Post link to Chat'));
		expect(mocks.action).toHaveBeenCalledWith({
			accountId: '99', threadId: 'thread-1', expectedGeneration: '3', actionKind: 'chat', targetId: '11',
		});
	});

	it('selects eligible mention recipients instead of accepting raw identity ids', async () => {
		mocks.get.mockResolvedValue({ accountId: '99', state: '4', list: [{
			id: 'thread-1', threadId: 'thread-1', status: 'owned', assigneeUserId: '7', dueAt: null, generation: '3',
		}] });
		const { getByLabelText, getByText } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: true, onClose: vi.fn(),
		});
		const search = await vi.waitFor(() => getByLabelText('Mention people'));
		await fireEvent.input(search, { target: { value: 'Ada' } });
		await fireEvent.click(await vi.waitFor(() => getByText('Ada')));
		expect(mocks.collaborators).toHaveBeenCalledWith('99', 'Ada', 8);
		await fireEvent.input(getByLabelText('Private comment'), { target: { value: 'Please review' } });
		await fireEvent.click(getByText('Add comment'));
		expect(mocks.commentSet).toHaveBeenCalledWith(expect.objectContaining({
			accountId: '99', threadId: 'thread-1', body: 'Please review', mentionUserIds: ['8'],
		}));
	});

	it('revises an own comment by appending a replacement and retaining mentions', async () => {
		mocks.get.mockResolvedValue({ accountId: '99', state: '4', list: [{
			id: 'thread-1', threadId: 'thread-1', status: 'owned', assigneeUserId: '7', dueAt: null, generation: '3',
		}] });
		mocks.commentGet.mockResolvedValue([{
			kind: 'comment', id: 'comment-1', authorUserId: '7', authorDisplay: 'Agent', body: 'Old note',
			mentions: [{ userId: '8', capability: 'comment' }], tombstoned: false,
		}]);
		const { container, getByLabelText, getByText } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: true, onClose: vi.fn(),
		});
		await fireEvent.click(await vi.waitFor(() => getByText('Edit comment')));
		const editor = getByLabelText('Edit comment');
		expect((editor as HTMLTextAreaElement).value).toBe('Old note');
		await fireEvent.input(editor, { target: { value: 'Corrected note' } });
		await fireEvent.click(container.querySelector('.comment-actions button') as HTMLButtonElement);
		expect(mocks.commentSet).toHaveBeenCalledWith(expect.objectContaining({
			body: 'Corrected note', replacesCommentId: 'comment-1', mentionUserIds: ['8'],
		}));
	});

	it('renders only bounded aggregate daily metrics, never actor identities', async () => {
		mocks.metricsGet.mockResolvedValue({ accountId: '99', available: true, list: [{
			metric_day: '2026-08-10', policy_version: 1, conversation_count: 12,
			first_response_count: 2, first_response_seconds: 600, completed_count: 4,
			breached_count: 1, actor_cohort_count: 5, rebuilt_at: '2026-08-10T00:00:00Z',
		}] });
		const { container } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: false, analyticsEnabled: true, onClose: vi.fn(),
		});
		await vi.waitFor(() => expect(container.textContent).toContain('2026-08-10'));
		expect(container.textContent).toContain('5m');
		expect(container.textContent).toContain('4 / 1');
		expect(container.textContent).not.toContain('actorUserId');
	});

	it('lets only a policy manager save a generation-bound business calendar', async () => {
		mocks.policyGet.mockResolvedValue({ accountId: '99', canManage: true, policy: {
			version: 1, timezone: 'UTC', weekdayMask: 62, workdayStart: '09:00:00', workdayEnd: '17:00:00',
			holidays: [], slaMinutes: 480, generation: '1', source: 'mailbox',
		} });
		const { getByLabelText, getByText } = render(MailWorkRail, {
			accountId: '99', threadId: 'thread-1', canCollaborate: true,
			commentsEnabled: false, onClose: vi.fn(),
		});
		const timezone = await vi.waitFor(() => getByLabelText('IANA time zone'));
		await fireEvent.input(timezone, { target: { value: 'Asia/Shanghai' } });
		await fireEvent.input(getByLabelText('Workday ends'), { target: { value: '18:00' } });
		await fireEvent.input(getByLabelText('First response target (business minutes)'), { target: { value: '240' } });
		await fireEvent.input(getByLabelText('Holidays (YYYY-MM-DD, comma separated)'), { target: { value: '2026-10-01' } });
		await fireEvent.click(getByText('Save'));
		expect(mocks.policySet).toHaveBeenCalledWith(expect.objectContaining({
			accountId: '99', expectedGeneration: '1', timezone: 'Asia/Shanghai',
			weekdayMask: 62, workdayEnd: '18:00', holidays: ['2026-10-01'], slaMinutes: 240,
		}));
	});
});
