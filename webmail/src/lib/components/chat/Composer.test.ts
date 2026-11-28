import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import Composer from './Composer.svelte';
import { chatStore, pendingKey, type PendingAttachment } from '$lib/chat/store.svelte';
import type { RosterMember } from '$lib/chat/api';
import { toasts, clearToasts } from '$lib/components/ui';

const searchMembers = vi.fn();
const sendTyping = vi.fn();
const createPoll = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		searchMembers: (...a: unknown[]) => searchMembers(...a),
		sendTyping: (...a: unknown[]) => sendTyping(...a),
		createPoll: (...a: unknown[]) => createPoll(...a),
	};
});

function member(over: Partial<RosterMember> = {}): RosterMember {
	return { userId: 43, displayName: 'Bob', avatarSha256: null, role: 'member', external: false, removed: false, ...over };
}

// ── voice recording (A3 QoL Task 15) — jsdom has neither MediaRecorder nor
// getUserMedia; these fakes are the minimum shape Composer's recording code
// touches (start/stop/ondataavailable/onstop), mirroring how a real browser
// fires them synchronously enough for a test double.
class FakeMediaRecorder {
	static isTypeSupported = vi.fn(() => true);
	ondataavailable: ((e: { data: Blob }) => void) | null = null;
	onstop: (() => void) | null = null;
	constructor(
		public stream: MediaStream,
		public options?: Record<string, unknown>,
	) {}
	start(): void {
		/* no-op: chunk emission is simulated by stop() below */
	}
	stop(): void {
		this.ondataavailable?.({ data: new Blob(['x'], { type: 'audio/webm' }) });
		this.onstop?.();
	}
}
function fakeStream(): MediaStream {
	return { getTracks: () => [{ stop: vi.fn() }] } as unknown as MediaStream;
}

beforeEach(() => {
	searchMembers.mockReset();
	searchMembers.mockResolvedValue([]);
	sendTyping.mockReset();
	sendTyping.mockResolvedValue(undefined);
	createPoll.mockReset();
	createPoll.mockResolvedValue({ messageId: 1, pollId: 1, seq: 1 });
	chatStore.activeChannelId = 1;
	chatStore.send = vi.fn().mockResolvedValue(undefined);
	chatStore.sendVoice = vi.fn().mockResolvedValue(undefined);
	chatStore.attachmentsEnabled = true;
	chatStore.pendingAttachments = {};
	chatStore.addAttachments = vi.fn().mockReturnValue([]);
	chatStore.removeAttachment = vi.fn();
	chatStore.retryAttachment = vi.fn();
	chatStore.scheduled = [];
	chatStore.loadScheduled = vi.fn().mockResolvedValue(undefined);
	chatStore.scheduleSend = vi.fn().mockResolvedValue(undefined);
	chatStore.cancelScheduled = vi.fn().mockResolvedValue(undefined);
	chatStore.backfillSince = vi.fn().mockResolvedValue(undefined);
	clearToasts();
	vi.stubGlobal('MediaRecorder', FakeMediaRecorder as unknown as typeof MediaRecorder);
	Object.defineProperty(navigator, 'mediaDevices', {
		value: { getUserMedia: vi.fn().mockResolvedValue(fakeStream()) },
		configurable: true,
	});
});

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

function pending(over: Partial<PendingAttachment> = {}): PendingAttachment {
	return {
		clientId: 'p1',
		file: new File(['x'], 'report.pdf', { type: 'application/pdf' }),
		status: 'ready',
		progress: 10,
		size: 10,
		name: 'report.pdf',
		contentType: 'application/pdf',
		...over,
	};
}

function getTextarea(): HTMLTextAreaElement {
	return screen.getByTestId('composer-input') as HTMLTextAreaElement;
}

describe('Composer', () => {
	it('Enter sends the trimmed body and clears the input; focus returns to the textarea', async () => {
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		ta.focus();
		await fireEvent.input(ta, { target: { value: '  hello  ' } });
		await fireEvent.keyDown(ta, { key: 'Enter' });

		expect(chatStore.send).toHaveBeenCalledWith('hello', null, [], null);
		expect(ta.value).toBe('');
		expect(document.activeElement).toBe(ta);
	});

	it('Shift+Enter never sends (newline stays local)', async () => {
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: 'line one' } });
		await fireEvent.keyDown(ta, { key: 'Enter', shiftKey: true });

		expect(chatStore.send).not.toHaveBeenCalled();
	});

	it('an empty/whitespace-only body never sends', async () => {
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: '   ' } });
		await fireEvent.keyDown(ta, { key: 'Enter' });

		expect(chatStore.send).not.toHaveBeenCalled();
	});

	it('@mention autocomplete: typing "@bo" searches channel members; Enter inserts the name and records the userId for send', async () => {
		searchMembers.mockResolvedValue([member({ userId: 43, displayName: 'Bob' })]);
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		ta.value = '@bo';
		ta.selectionStart = 3;
		ta.selectionEnd = 3;
		await fireEvent.input(ta);

		await waitFor(() => expect(searchMembers).toHaveBeenCalledWith(1, 'bo'));
		await waitFor(() => expect(screen.getByText('@Bob')).toBeTruthy());

		await fireEvent.keyDown(ta, { key: 'Enter' });
		expect(ta.value).toBe('@Bob ');

		// Sending now must carry the recorded mention userId.
		ta.selectionStart = ta.value.length;
		ta.selectionEnd = ta.value.length;
		await fireEvent.input(ta, { target: { value: ta.value + 'hi' } });
		await fireEvent.keyDown(ta, { key: 'Enter' });
		expect(chatStore.send).toHaveBeenCalledWith('@Bob hi', null, [43], null);
	});

	it('renders External for an active external mention candidate from the server flag', async () => {
		searchMembers.mockResolvedValue([member({ displayName: 'Partner', external: true })]);
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		ta.value = '@par';
		ta.selectionStart = ta.selectionEnd = ta.value.length;
		await fireEvent.input(ta);

		const candidate = (await screen.findByText('@Partner')).closest('button');
		expect(candidate?.textContent).toContain('External');
		expect(candidate?.textContent).not.toContain('Removed');
	});

	it('renders External and Removed independently when both server flags are true', async () => {
		searchMembers.mockResolvedValue([member({ displayName: 'Former partner', external: true, removed: true })]);
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		ta.value = '@former';
		ta.selectionStart = ta.selectionEnd = ta.value.length;
		await fireEvent.input(ta);

		const candidate = (await screen.findByText('@Former partner')).closest('button');
		expect(candidate?.textContent).toContain('Removed');
		expect(candidate?.textContent).toContain('External');
	});

	it('does not infer an External mention badge for a member from their email-shaped name', async () => {
		searchMembers.mockResolvedValue([member({ displayName: 'external@example.com' })]);
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		ta.value = '@external';
		ta.selectionStart = ta.selectionEnd = ta.value.length;
		await fireEvent.input(ta);

		const candidate = (await screen.findByText('@external@example.com')).closest('button');
		expect(candidate?.textContent).not.toContain('External');
		expect(candidate?.textContent).not.toContain('Removed');
	});

	it('arrow keys navigate suggestions without stealing focus from the textarea (focus trap); Escape closes the popup', async () => {
		searchMembers.mockResolvedValue([member({ userId: 43, displayName: 'Bob' }), member({ userId: 44, displayName: 'Carol' })]);
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		ta.value = '@';
		ta.selectionStart = 1;
		ta.selectionEnd = 1;
		await fireEvent.input(ta);
		await waitFor(() => expect(screen.getByText('@Carol')).toBeTruthy());

		await fireEvent.keyDown(ta, { key: 'ArrowDown' });
		expect(document.activeElement).toBe(ta);

		await fireEvent.keyDown(ta, { key: 'Escape' });
		expect(screen.queryByText('@Carol')).toBeNull();
		expect(document.activeElement).toBe(ta);
	});

	it('@channel/@all are offered only when canBroadcast, and set the broadcast field on send', async () => {
		render(Composer, { channelId: 1, canBroadcast: true });
		const ta = getTextarea();
		ta.value = '@ch';
		ta.selectionStart = 3;
		ta.selectionEnd = 3;
		await fireEvent.input(ta);
		await waitFor(() => expect(screen.getByText('@channel')).toBeTruthy());

		await fireEvent.click(screen.getByText('@channel'));
		await fireEvent.input(ta, { target: { value: ta.value + 'urgent' } });
		await fireEvent.keyDown(ta, { key: 'Enter' });

		expect(chatStore.send).toHaveBeenCalledWith('@channel urgent', null, [], 'channel');
	});

	it('without canBroadcast, "@channel"/"@all" are not offered as candidates', async () => {
		render(Composer, { channelId: 1, canBroadcast: false });
		const ta = getTextarea();
		ta.value = '@ch';
		ta.selectionStart = 3;
		ta.selectionEnd = 3;
		await fireEvent.input(ta);
		await waitFor(() => expect(searchMembers).toHaveBeenCalled());
		expect(screen.queryByText('@channel')).toBeNull();
	});

	it('a minimal emoji popover inserts the chosen emoji at the cursor', async () => {
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.click(screen.getByLabelText('Insert emoji'));
		const emojiBtn = screen.getByText('🎉');
		await fireEvent.click(emojiBtn);
		expect(ta.value).toContain('🎉');
	});

	it('announcement-disabled state shows explanatory text and no composer input', () => {
		render(Composer, { channelId: 1, disabled: true });
		expect(screen.getByText('Only admins can post here')).toBeTruthy();
		expect(screen.queryByTestId('composer-input')).toBeNull();
	});

	it('typing signal is throttled to <=1/3s', async () => {
		vi.useFakeTimers();
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: 'a' } });
		await fireEvent.input(ta, { target: { value: 'ab' } });
		expect(sendTyping).toHaveBeenCalledTimes(1);

		vi.advanceTimersByTime(3001);
		await fireEvent.input(ta, { target: { value: 'abc' } });
		expect(sendTyping).toHaveBeenCalledTimes(2);
	});

	it('passes parentId through to send() for a thread reply composer', async () => {
		render(Composer, { channelId: 1, parentId: 9 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: 'reply text' } });
		await fireEvent.keyDown(ta, { key: 'Enter' });
		expect(chatStore.send).toHaveBeenCalledWith('reply text', 9, [], null);
	});
});

describe('Composer — Chat A2 Task 8 attachments', () => {
	it('the whole attach surface is ABSENT when attachmentsEnabled is false', () => {
		chatStore.attachmentsEnabled = false;
		render(Composer, { channelId: 1 });
		expect(screen.queryByLabelText('Attach files')).toBeNull();
		expect(screen.queryByRole('list', { name: 'Attachments' })).toBeNull();
	});

	it('clicking the attach button opens the hidden file input; picking files calls store.addAttachments', async () => {
		render(Composer, { channelId: 1 });
		const input = document.querySelector('input[type="file"]') as HTMLInputElement;
		expect(input).toBeTruthy();
		const file = new File(['x'], 'photo.png', { type: 'image/png' });
		Object.defineProperty(input, 'files', { value: [file], configurable: true });
		await fireEvent.change(input);
		expect(chatStore.addAttachments).toHaveBeenCalledWith(1, null, [file]);
		// M16: the input value resets so picking the SAME file again re-fires change.
		expect(input.value).toBe('');
	});

	it('renders a chip per pending attachment (name + size), keyed off the store\'s composite key', () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = { [key]: [pending({ name: 'report.pdf', size: 2048 })] };
		render(Composer, { channelId: 1 });
		expect(screen.getByText('report.pdf')).toBeTruthy();
		expect(screen.getByText('2.0 KB')).toBeTruthy();
	});

	it('a failed chip shows its error and a retry button wired to the store', async () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = { [key]: [pending({ status: 'failed', error: 'Quota exceeded', clientId: 'c9' })] };
		render(Composer, { channelId: 1 });
		expect(screen.getByText('Quota exceeded')).toBeTruthy();
		await fireEvent.click(screen.getByLabelText('Retry report.pdf'));
		expect(chatStore.retryAttachment).toHaveBeenCalledWith(1, null, 'c9');
	});

	it('remove button on a chip calls store.removeAttachment', async () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = { [key]: [pending({ clientId: 'c7' })] };
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Remove report.pdf'));
		expect(chatStore.removeAttachment).toHaveBeenCalledWith(1, null, 'c7');
	});

	it('surfaces the 8-cap: attach button disables at 8 pending, and a cap notice appears past it', async () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = {
			[key]: Array.from({ length: 8 }, (_, i) => pending({ clientId: `c${i}`, name: `f${i}.pdf` })),
		};
		render(Composer, { channelId: 1 });
		const attachBtn = screen.getByLabelText('Attach files') as HTMLButtonElement;
		expect(attachBtn.disabled).toBe(true);

		const input = document.querySelector('input[type="file"]') as HTMLInputElement;
		const extra = new File(['x'], 'one-too-many.png', { type: 'image/png' });
		Object.defineProperty(input, 'files', { value: [extra], configurable: true });
		await fireEvent.change(input);
		expect(chatStore.addAttachments).not.toHaveBeenCalled();
		expect(screen.getByText('Maximum 8 attachments per message')).toBeTruthy();
	});

	it('send is disabled + aria-disabled while any pending attachment is hashing/uploading', () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = { [key]: [pending({ status: 'uploading' })] };
		render(Composer, { channelId: 1 });
		const sendBtn = screen.getByRole('button', { name: /Uploading/ }) as HTMLButtonElement;
		expect(sendBtn.disabled).toBe(true);
		expect(sendBtn.getAttribute('aria-disabled')).toBe('true');
	});

	it('Enter is a no-op while uploading (never fires send mid-upload)', async () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = { [key]: [pending({ status: 'uploading' })] };
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: 'hello' } });
		await fireEvent.keyDown(ta, { key: 'Enter' });
		expect(chatStore.send).not.toHaveBeenCalled();
	});

	it('an attachment-only send (empty body, one ready attachment) is allowed', async () => {
		const key = pendingKey(1, null);
		chatStore.pendingAttachments = { [key]: [pending({ status: 'ready' })] };
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.keyDown(ta, { key: 'Enter' });
		expect(chatStore.send).toHaveBeenCalledWith('', null, [], null);
	});

	it('drag-drop onto the composer calls store.addAttachments with the dropped files (enter/leave counter tracked)', async () => {
		const { container } = render(Composer, { channelId: 1 });
		const root = container.querySelector('.composer') as HTMLElement;
		const file = new File(['x'], 'dropped.png', { type: 'image/png' });
		await fireEvent.dragEnter(root, { dataTransfer: { types: ['Files'] } });
		expect(root.className).toContain('composer--dragover');
		await fireEvent.dragLeave(root, { dataTransfer: { types: ['Files'] } });
		expect(root.className).not.toContain('composer--dragover');
		await fireEvent.drop(root, { dataTransfer: { types: ['Files'], files: [file] } });
		expect(chatStore.addAttachments).toHaveBeenCalledWith(1, null, [file]);
	});

	it('pasting an image file synthesizes an image-<ISO>.png name and attaches it (paste of plain text is untouched)', async () => {
		vi.setSystemTime(new Date('2026-07-12T10:00:00Z'));
		vi.useFakeTimers();
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		const file = new File(['x'], '', { type: 'image/png' });
		await fireEvent.paste(ta, { clipboardData: { files: [file] } });
		expect(chatStore.addAttachments).toHaveBeenCalledTimes(1);
		const attached = (chatStore.addAttachments as ReturnType<typeof vi.fn>).mock.calls[0][2] as File[];
		expect(attached[0].name).toMatch(/^image-.*\.png$/);
	});

	it('drag/drop and attach are inert when attachmentsEnabled is false', async () => {
		chatStore.attachmentsEnabled = false;
		const { container } = render(Composer, { channelId: 1 });
		const root = container.querySelector('.composer') as HTMLElement;
		const file = new File(['x'], 'dropped.png', { type: 'image/png' });
		await fireEvent.drop(root, { dataTransfer: { types: ['Files'], files: [file] } });
		expect(chatStore.addAttachments).not.toHaveBeenCalled();
	});
});

describe('Composer — A3 QoL Task 15: voice recording', () => {
	it('clicking the mic button starts recording (getUserMedia + aria-label flips to Stop, announced via aria-live)', async () => {
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Record voice message'));
		expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalledWith({ audio: true });
		await waitFor(() => expect(screen.getByLabelText('Stop recording')).toBeTruthy());
		expect(screen.getByText('Recording voice message')).toBeTruthy();
	});

	it('stopping recording adds the clip as a pending attachment chip; Send calls chatStore.sendVoice (not the text send)', async () => {
		chatStore.addAttachments = vi.fn((cid: number, pid: number | null, files: File[]) => {
			const key = pendingKey(cid, pid);
			const list = chatStore.pendingAttachments[key] ?? (chatStore.pendingAttachments[key] = []);
			list.push({
				clientId: 'voice-1',
				file: files[0],
				status: 'ready',
				progress: files[0].size,
				size: files[0].size,
				name: files[0].name,
				contentType: files[0].type,
			});
			return [];
		});
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Record voice message'));
		await waitFor(() => expect(screen.getByLabelText('Stop recording')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Stop recording'));

		await waitFor(() => expect(chatStore.addAttachments).toHaveBeenCalledTimes(1));
		const attached = (chatStore.addAttachments as ReturnType<typeof vi.fn>).mock.calls[0][2] as File[];
		expect(attached[0].name).toMatch(/^voice-.*\.(webm|m4a)$/);

		await fireEvent.keyDown(getTextarea(), { key: 'Enter' });
		expect(chatStore.sendVoice).toHaveBeenCalledTimes(1);
		expect(chatStore.send).not.toHaveBeenCalled();
	});

	it('a getUserMedia denial shows an inline toast (never silent) and never enters the recording state', async () => {
		Object.defineProperty(navigator, 'mediaDevices', {
			value: { getUserMedia: vi.fn().mockRejectedValue(new DOMException('denied', 'NotAllowedError')) },
			configurable: true,
		});
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Record voice message'));
		await waitFor(() => expect(toasts.some((t) => t.message === 'Microphone access denied')).toBe(true));
		expect(screen.queryByLabelText('Stop recording')).toBeNull();
	});

	it('the cancel affordance discards the recording without ever attaching anything', async () => {
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Record voice message'));
		await waitFor(() => expect(screen.getByLabelText('Cancel recording')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Cancel recording'));
		expect(chatStore.addAttachments).not.toHaveBeenCalled();
		expect(screen.queryByLabelText('Stop recording')).toBeNull();
		expect(screen.getByLabelText('Record voice message')).toBeTruthy();
	});

	it('the mic button is absent when attachmentsEnabled is false (voice rides the A2 rail)', () => {
		chatStore.attachmentsEnabled = false;
		render(Composer, { channelId: 1 });
		expect(screen.queryByLabelText('Record voice message')).toBeNull();
	});
});

describe('Composer — A3 QoL Task 15: poll creation ("+" menu)', () => {
	it('the + menu offers Create poll; a valid submission calls chatApi.createPoll and closes the dialog', async () => {
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Add to message'));
		await fireEvent.click(screen.getByText('Create poll'));
		expect(screen.getByText('Create a poll')).toBeTruthy();

		await fireEvent.input(screen.getByLabelText('Question'), { target: { value: 'Lunch?' } });
		await fireEvent.input(screen.getByLabelText('Option 1'), { target: { value: 'Pizza' } });
		await fireEvent.input(screen.getByLabelText('Option 2'), { target: { value: 'Sushi' } });
		// The plus-menu's own "Create poll" item unmounts once the dialog opens
		// (openPollDialog closes it) — only the dialog footer's button remains.
		await fireEvent.click(screen.getByText('Create poll'));

		expect(createPoll).toHaveBeenCalledWith(1, 'Lunch?', ['Pizza', 'Sushi'], false);
		await waitFor(() => expect(screen.queryByText('Create a poll')).toBeNull());
	});

	it('submit stays disabled with fewer than 2 non-blank options', async () => {
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Add to message'));
		await fireEvent.click(screen.getByText('Create poll'));
		await fireEvent.input(screen.getByLabelText('Question'), { target: { value: 'Lunch?' } });
		await fireEvent.input(screen.getByLabelText('Option 1'), { target: { value: 'Pizza' } });
		const submit = screen.getByText('Create poll') as HTMLButtonElement;
		expect(submit.disabled).toBe(true);
	});

	// [UX #8, whole-pipeline review] submitPoll had no catch at all.
	it('a rejecting createPoll toasts and leaves the dialog open, instead of throwing unhandled', async () => {
		createPoll.mockRejectedValueOnce(new Error('network'));
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByLabelText('Add to message'));
		await fireEvent.click(screen.getByText('Create poll'));
		await fireEvent.input(screen.getByLabelText('Question'), { target: { value: 'Lunch?' } });
		await fireEvent.input(screen.getByLabelText('Option 1'), { target: { value: 'Pizza' } });
		await fireEvent.input(screen.getByLabelText('Option 2'), { target: { value: 'Sushi' } });
		await fireEvent.click(screen.getByText('Create poll'));

		await waitFor(() => expect(toasts.at(-1)?.variant).toBe('danger'));
		expect(screen.getByText('Create a poll')).toBeTruthy(); // dialog still open
	});
});

describe('Composer — A3 QoL Task 15: send-later + scheduled queue', () => {
	it('the schedule caret offers "In 1 hour"; picking it schedules the typed body ~1h ahead and clears the input', async () => {
		vi.setSystemTime(new Date('2026-07-12T10:00:00Z'));
		vi.useFakeTimers();
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: 'later text' } });
		await fireEvent.click(screen.getByLabelText('Send later'));
		await fireEvent.click(screen.getByText('In 1 hour'));

		expect(chatStore.scheduleSend).toHaveBeenCalledWith(1, 'later text', '2026-07-12T11:00:00.000Z', null, [], null);
		expect(ta.value).toBe('');
	});

	// [UX #8, whole-pipeline review] doSchedule used to clear value/mentions/
	// broadcast BEFORE awaiting scheduleSend — a rejection lost the typed
	// message with no way to recover it.
	it('a rejecting scheduleSend leaves the typed draft intact and toasts, instead of losing it', async () => {
		vi.setSystemTime(new Date('2026-07-12T10:00:00Z'));
		vi.useFakeTimers();
		chatStore.scheduleSend = vi.fn().mockRejectedValue(new Error('network'));
		render(Composer, { channelId: 1 });
		const ta = getTextarea();
		await fireEvent.input(ta, { target: { value: 'later text' } });
		await fireEvent.click(screen.getByLabelText('Send later'));
		await fireEvent.click(screen.getByText('In 1 hour'));

		expect(chatStore.scheduleSend).toHaveBeenCalled();
		await waitFor(() => expect(toasts.at(-1)?.variant).toBe('danger'));
		expect(ta.value).toBe('later text');
	});

	it('custom schedule opens a datetime dialog showing the timezone; confirming schedules at the chosen time', async () => {
		render(Composer, { channelId: 1 });
		await fireEvent.input(getTextarea(), { target: { value: 'custom time text' } });
		await fireEvent.click(screen.getByLabelText('Send later'));
		await fireEvent.click(screen.getByText('Custom time…'));
		expect(screen.getByText('Schedule message')).toBeTruthy();

		await fireEvent.input(screen.getByLabelText('Send at'), { target: { value: '2026-08-01T09:30' } });
		await fireEvent.click(screen.getByText('Schedule'));

		expect(chatStore.scheduleSend).toHaveBeenCalledWith(
			1,
			'custom time text',
			new Date('2026-08-01T09:30').toISOString(),
			null,
			[],
			null,
		);
	});

	it('an "N scheduled" chip shows the per-channel count and opens a cancel-only queue; a failed row renders distinctly', async () => {
		chatStore.scheduled = [
			{ actionId: 'a1', channelId: 1, body: 'pending one', fireAt: '2026-08-01T00:00:00Z', status: 'pending', failureCode: null, lastError: null },
			{ actionId: 'a2', channelId: 1, body: 'a doomed send', fireAt: '2026-08-02T00:00:00Z', status: 'failed', failureCode: 'BZ163', lastError: 'no longer a member' },
			{ actionId: 'a3', channelId: 9, body: 'other channel', fireAt: '2026-08-03T00:00:00Z', status: 'pending', failureCode: null, lastError: null },
		];
		render(Composer, { channelId: 1 });
		expect(screen.getByText('2 scheduled')).toBeTruthy(); // channel 9's row excluded

		await fireEvent.click(screen.getByText('2 scheduled'));
		expect(screen.getByText('pending one')).toBeTruthy();
		expect(screen.getByText('a doomed send')).toBeTruthy();
		expect(screen.getByText('Failed')).toBeTruthy();
		// The i18n-mapped reason for a known BZ code, never the raw English
		// PL/pgSQL RAISE text (lastError) and never the bare SQLSTATE.
		expect(screen.getByText("You're no longer a member of this channel")).toBeTruthy();
		expect(screen.queryByText('no longer a member')).toBeNull();
		expect(screen.queryByText('BZ163')).toBeNull();
		expect(screen.queryByText('other channel')).toBeNull();

		await fireEvent.click(screen.getAllByLabelText('Cancel')[0]);
		expect(chatStore.cancelScheduled).toHaveBeenCalledWith('a1');
	});

	it('a failed row with an unmapped failure code falls back to the raw code, never the English lastError text', async () => {
		chatStore.scheduled = [
			{
				actionId: 'a4',
				channelId: 1,
				body: 'weird failure',
				fireAt: '2026-08-04T00:00:00Z',
				status: 'failed',
				failureCode: 'BZ999',
				lastError: 'some未知English internal detail',
			},
		];
		render(Composer, { channelId: 1 });
		await fireEvent.click(screen.getByText('1 scheduled'));
		expect(screen.getByText('BZ999')).toBeTruthy();
		expect(screen.queryByText('some未知English internal detail')).toBeNull();
	});

	it('no scheduled chip when nothing is queued for this channel', () => {
		chatStore.scheduled = [];
		render(Composer, { channelId: 1 });
		expect(screen.queryByText(/scheduled/)).toBeNull();
	});
});

describe('Composer — Pillar C2 Task 7: noAttachments (federated room content-scope, Q11)', () => {
	it('a federated room disables the attach button with a tooltip — the global attachmentsEnabled flag alone would let a user compose an attachment only to hit the BZ212 toast at send time', () => {
		chatStore.attachmentsEnabled = true;
		render(Composer, { channelId: 1, noAttachments: true });
		const button = screen.getByLabelText('Attach files') as HTMLButtonElement;
		expect(button.disabled).toBe(true);
		expect(button.title).toBe('Attachments cannot be sent in a federated room');
	});

	it('an ordinary (non-room) channel keeps the attach button enabled, no tooltip — unchanged pre-C2 behavior', () => {
		chatStore.attachmentsEnabled = true;
		render(Composer, { channelId: 1, noAttachments: false });
		const button = screen.getByLabelText('Attach files') as HTMLButtonElement;
		expect(button.disabled).toBe(false);
		expect(button.title).toBe('');
	});

	// Task 7 review (M2): the Paperclip button was the ONLY intake path
	// gated on noAttachments — paste, drag-drop (composer strip AND
	// ChatApp's pane-level drop via acceptDroppedFiles), the Mic button, and
	// poll creation all still dead-ended in the server's BZ212 refusal.
	// Root-caused into addFiles() (the one choke every intake path routes
	// through) plus the Mic/poll-menu affordances.
	it('a paste in a federated room is blocked (never reaches chatStore.addAttachments) and shows a toast hint', async () => {
		render(Composer, { channelId: 1, noAttachments: true });
		const ta = getTextarea();
		const file = new File(['x'], '', { type: 'image/png' });
		await fireEvent.paste(ta, { clipboardData: { files: [file] } });
		expect(chatStore.addAttachments).not.toHaveBeenCalled();
		await waitFor(() => expect(toasts.some((t) => t.message === 'Attachments cannot be sent in a federated room')).toBe(true));
	});

	it('a drag-drop onto the composer strip is blocked in a federated room', async () => {
		const { container } = render(Composer, { channelId: 1, noAttachments: true });
		const root = container.querySelector('.composer') as HTMLElement;
		const file = new File(['x'], 'dropped.png', { type: 'image/png' });
		await fireEvent.drop(root, { dataTransfer: { types: ['Files'], files: [file] } });
		expect(chatStore.addAttachments).not.toHaveBeenCalled();
	});

	it('ChatApp\'s pane-level drop (acceptDroppedFiles) is blocked in a federated room — the SAME choke as a direct drop', () => {
		const { component } = render(Composer, { channelId: 1, noAttachments: true });
		const file = new File(['x'], 'dropped.png', { type: 'image/png' });
		(component as unknown as { acceptDroppedFiles: (files: File[]) => void }).acceptDroppedFiles([file]);
		expect(chatStore.addAttachments).not.toHaveBeenCalled();
	});

	it('the Mic (voice) button is disabled with the same tooltip in a federated room', () => {
		render(Composer, { channelId: 1, noAttachments: true });
		const mic = screen.getByLabelText('Record voice message') as HTMLButtonElement;
		expect(mic.disabled).toBe(true);
		expect(mic.title).toBe('Attachments cannot be sent in a federated room');
	});

	it('the mic button stays enabled, no tooltip, in an ordinary channel', () => {
		render(Composer, { channelId: 1, noAttachments: false });
		const mic = screen.getByLabelText('Record voice message') as HTMLButtonElement;
		expect(mic.disabled).toBe(false);
		expect(mic.title).toBe('');
	});

	it('the "Create poll" entry in the + menu is disabled with the same tooltip in a federated room', async () => {
		render(Composer, { channelId: 1, noAttachments: true });
		await fireEvent.click(screen.getByLabelText('Add to message'));
		const pollItem = screen.getByText('Create poll').closest('button') as HTMLButtonElement;
		expect(pollItem.disabled).toBe(true);
		expect(pollItem.title).toBe('Attachments cannot be sent in a federated room');
	});
});

describe('Composer — Pillar C2 Task 7: disabledMessage override', () => {
	it('a kicked/scope-revoked federated room mirror shows the dedicated archive-only copy, not the generic admins-only copy', () => {
		render(Composer, { channelId: 1, disabled: true, disabledMessage: 'This room is archive-only — you can no longer post here' });
		expect(screen.getByText('This room is archive-only — you can no longer post here')).toBeTruthy();
		expect(screen.queryByText('Only admins can post here')).toBeNull();
	});

	it('the generic admins-only copy still renders when no disabledMessage is passed — unchanged pre-C2 behavior', () => {
		render(Composer, { channelId: 1, disabled: true });
		expect(screen.getByText('Only admins can post here')).toBeTruthy();
	});
});
