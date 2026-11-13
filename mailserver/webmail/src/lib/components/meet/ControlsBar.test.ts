// ControlsBar.test.ts — Meet B1 Task 16 named tests: host-only controls hide
// for a plain member, and end-for-all is the one destructive action that
// gates behind a confirm Dialog (Leave never does — design #18).
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import ControlsBar from './ControlsBar.svelte';
import type { MeetRoom } from '$lib/meet/room.svelte';

function fakeRoom(): MeetRoom {
	return {
		localMuted: true,
		localCameraOff: true,
		screenSharing: false,
		raisedHandSelf: false,
		toggleMic: vi.fn(),
		toggleCamera: vi.fn(),
		toggleScreenShare: vi.fn(),
		toggleRaiseHand: vi.fn(),
		sendReaction: vi.fn(),
	} as unknown as MeetRoom;
}

const baseProps = {
	room: fakeRoom(),
	locked: false,
	view: 'gallery' as const,
	participants: [],
	onViewChange: vi.fn(),
	onLock: vi.fn(),
	onKick: vi.fn(),
	onSetRole: vi.fn(),
	onLeave: vi.fn(),
	onEndForAll: vi.fn(),
	onToggleWhiteboard: vi.fn(),
	whiteboardOpen: false,
	breakoutsEnabled: false,
	recordingEnabled: false,
	recordingState: 'idle' as const,
	onStartRecording: vi.fn(async () => undefined),
	onStopRecording: vi.fn(),
	onStartCaptions: vi.fn(async () => undefined),
	onStopCaptions: vi.fn(),
};

describe('ControlsBar', () => {
	it('hides host-only controls (lock, end-for-all) for a plain member and shows Leave instead', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member' });
		expect(screen.queryByLabelText('Lock meeting')).toBeNull();
		expect(screen.queryByTestId('end-for-all')).toBeNull();
		expect(screen.getByTestId('leave')).toBeTruthy();
	});

	it('shows host-only controls for the host', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host' });
		expect(screen.getByLabelText('Lock meeting')).toBeTruthy();
		expect(screen.getByTestId('end-for-all')).toBeTruthy();
	});

	it('end-for-all opens the confirm Dialog before calling onEndForAll', async () => {
		const onEndForAll = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'host', onEndForAll });
		await fireEvent.click(screen.getByTestId('end-for-all'));
		expect(screen.getByText('End meeting for everyone?')).toBeTruthy();
		expect(onEndForAll).not.toHaveBeenCalled(); // not yet — only the dialog opened
		await fireEvent.click(screen.getByTestId('end-for-all-confirm'));
		expect(onEndForAll).toHaveBeenCalled();
	});

	it('Leave calls onLeave immediately — no confirm dialog ever renders', async () => {
		const onLeave = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'member', onLeave });
		await fireEvent.click(screen.getByTestId('leave'));
		expect(onLeave).toHaveBeenCalled();
		expect(screen.queryByText('End meeting for everyone?')).toBeNull();
	});
});

// UX #12 (whole-pipeline review): (a) raw p.role rendered untranslated,
// (b) the whole toolbar's aria-label was scoped to "Participants", and
// (c) a guest got a doubled translated+raw badge.
describe('ControlsBar — participants sheet (whole-pipeline review UX #12)', () => {
	it('the toolbar has its own aria-label, distinct from the participants-sheet trigger', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member' });
		expect(document.querySelector('[role="toolbar"]')?.getAttribute('aria-label')).toBe('Meeting controls');
		// the sheet trigger button keeps its own, narrower label
		expect(screen.getByLabelText('Participants')).toBeTruthy();
	});

	it('renders a translated role badge for a member, not the raw enum value', async () => {
		render(ControlsBar, {
			...baseProps,
			selfRole: 'host',
			participants: [{ identity: '1', displayName: 'Alice', role: 'member' }],
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		expect(screen.getByText('Member')).toBeTruthy();
		expect(screen.queryByText('member')).toBeNull(); // the raw enum value must never render
	});

	it('renders exactly ONE badge for a guest — no doubled translated+raw badge', async () => {
		render(ControlsBar, {
			...baseProps,
			selfRole: 'host',
			participants: [{ identity: 'g:1', displayName: 'Bob', role: 'guest' }],
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		const row = screen.getByText('Bob').closest('li');
		expect(row?.querySelectorAll('.badge').length).toBe(1);
		expect(screen.getByText('Guest')).toBeTruthy();
		expect(screen.queryByText('guest')).toBeNull();
	});

	it('adds an External badge for an authenticated guest-account participant', async () => {
		render(ControlsBar, {
			...baseProps,
			selfRole: 'host',
			participants: [{ identity: 'u:9', displayName: 'Pat', role: 'member', external: true }],
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		expect(screen.getByText('Member')).toBeTruthy();
		expect(screen.getByText('External')).toBeTruthy();
	});
});

// B1 live-gate ledger fix 2: the re-admit affordance — no UI existed to
// clear a ban (host/cohost-only, confirm-free since it's reversible, the
// makeCohost precedent rather than kick's confirm-Dialog one).
describe('ControlsBar — banned/re-admit (B1 live-gate ledger fix 2)', () => {
	it('hides the Removed section entirely when nothing is banned', async () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', banned: [] });
		await fireEvent.click(screen.getByLabelText('Participants'));
		expect(screen.queryByText('Removed from this meeting')).toBeNull();
	});

	it('shows a banned row with a Re-admit action for host/cohost, and Re-admit calls onReAdmit with no confirmation', async () => {
		const onReAdmit = vi.fn();
		render(ControlsBar, {
			...baseProps,
			selfRole: 'host',
			banned: [{ identity: 'u:2', displayName: 'Bob' }],
			onReAdmit,
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		expect(screen.getByText('Removed from this meeting')).toBeTruthy();
		expect(screen.getByText('Bob')).toBeTruthy();

		await fireEvent.click(screen.getByText('Re-admit'));
		// confirm-free: no dialog interstitial, onReAdmit fires on the one click.
		expect(onReAdmit).toHaveBeenCalledWith('u:2');
	});

	it('hides the Removed section for a plain member even when banned is non-empty', async () => {
		render(ControlsBar, {
			...baseProps,
			selfRole: 'member',
			banned: [{ identity: 'u:2', displayName: 'Bob' }],
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		expect(screen.queryByText('Removed from this meeting')).toBeNull();
	});
});

describe('ControlsBar — recording (Meet B2 Task 10)', () => {
	it('hides the record button for a host when recordingEnabled is false', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', recordingEnabled: false });
		expect(screen.queryByLabelText('Start recording')).toBeNull();
	});

	it('hides the record button for a plain member even when recordingEnabled is true', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member', recordingEnabled: true });
		expect(screen.queryByLabelText('Start recording')).toBeNull();
	});

	it('shows the record button for a host when recordingEnabled is true', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', recordingEnabled: true });
		expect(screen.getByLabelText('Start recording')).toBeTruthy();
	});

	it('clicking start opens a confirm Dialog naming the consent posture; confirming calls onStartRecording', async () => {
		const onStartRecording = vi.fn(async () => undefined);
		render(ControlsBar, { ...baseProps, selfRole: 'host', recordingEnabled: true, onStartRecording });
		await fireEvent.click(screen.getByLabelText('Start recording'));
		expect(
			screen.getByText(
				'Everyone in the meeting — and everyone who joins later — will see a recording notice and must agree before joining.',
			),
		).toBeTruthy();
		expect(onStartRecording).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByTestId('start-recording-confirm'));
		expect(onStartRecording).toHaveBeenCalled();
	});

	it('the confirm button is disabled while the start POST is in flight', async () => {
		let resolveStart: () => void = () => {};
		const onStartRecording = vi.fn(
			() =>
				new Promise<void>((resolve) => {
					resolveStart = resolve;
				}),
		);
		render(ControlsBar, { ...baseProps, selfRole: 'host', recordingEnabled: true, onStartRecording });
		await fireEvent.click(screen.getByLabelText('Start recording'));
		await fireEvent.click(screen.getByTestId('start-recording-confirm'));

		expect((screen.getByTestId('start-recording-confirm') as HTMLButtonElement).disabled).toBe(true);
		resolveStart();
		// on success the confirm Dialog closes — the confirm button leaves the DOM.
		await vi.waitFor(() => expect(screen.queryByTestId('start-recording-confirm')).toBeNull());
	});

	it('while recordingActive, the button flips to stop -> onStopRecording', async () => {
		const onStopRecording = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'host', recordingEnabled: true, recordingState: 'recording', onStopRecording });
		expect(screen.queryByLabelText('Start recording')).toBeNull();
		await fireEvent.click(screen.getByLabelText('Stop recording'));
		expect(onStopRecording).toHaveBeenCalled();
	});

	it('while the latest recording is stopping, the control renders a disabled "stopping…" state', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', recordingEnabled: true, recordingState: 'stopping' });
		const btn = screen.getByLabelText('Recording is stopping…') as HTMLButtonElement;
		expect(btn.disabled).toBe(true);
		expect(screen.queryByLabelText('Start recording')).toBeNull();
		expect(screen.queryByLabelText('Stop recording')).toBeNull();
	});
});

// B3 Task 8: the Poll button — same visibility rule as the existing Chat
// button (onOpenChat), NOT host-gated: any member may create a poll
// (Composer's "+" menu poll option carries no role check, A3 Task 15).
describe('ControlsBar — Poll button (Meet B3 Task 8)', () => {
	it('hides the Poll button when onOpenPoll is not passed (chat panel unmountable)', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member' });
		expect(screen.queryByLabelText('Poll')).toBeNull();
	});

	it('shows the Poll button for a plain member and calls onOpenPoll on click', async () => {
		const onOpenPoll = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'member', onOpenPoll });
		await fireEvent.click(screen.getByLabelText('Poll'));
		expect(onOpenPoll).toHaveBeenCalled();
	});
});

// B3 Task 7: the Breakouts button — only host/cohost, only when the toggle-read
// signal (meeting_get's breakoutsEnabled) is on.
describe('ControlsBar — breakouts (Meet B3 Task 7)', () => {
	it('hides the Breakouts button for a host when breakoutsEnabled is false', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', breakoutsEnabled: false });
		expect(screen.queryByLabelText('Breakout rooms')).toBeNull();
	});

	it('hides the Breakouts button for a plain member even when breakoutsEnabled is true', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member', breakoutsEnabled: true });
		expect(screen.queryByLabelText('Breakout rooms')).toBeNull();
	});

	it('shows the Breakouts button for a cohost when breakoutsEnabled is true, and calls onOpenBreakouts', async () => {
		const onOpenBreakouts = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'cohost', breakoutsEnabled: true, onOpenBreakouts });
		await fireEvent.click(screen.getByLabelText('Breakout rooms'));
		expect(onOpenBreakouts).toHaveBeenCalled();
	});
});

// UX #9 (whole-pipeline review): the Lobby toggle button — host/cohost only
// like breakouts, but unconditional (no feature-toggle gate), with a
// pending-count badge.
describe('ControlsBar — Lobby toggle (whole-pipeline review UX #9)', () => {
	it('hides the Lobby button entirely when onOpenLobby is not provided (e.g. a plain member)', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member' });
		expect(screen.queryByLabelText('Waiting to join')).toBeNull();
	});

	it('shows the Lobby button for a host and calls onOpenLobby on click', async () => {
		const onOpenLobby = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'host', onOpenLobby });
		await fireEvent.click(screen.getByLabelText('Waiting to join'));
		expect(onOpenLobby).toHaveBeenCalled();
	});

	it('shows a pending-count badge in the label and visibly when pendingLobbyCount > 0', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', onOpenLobby: vi.fn(), pendingLobbyCount: 3 });
		expect(screen.getByLabelText('Waiting to join (3)')).toBeTruthy();
		expect(screen.getByText('3')).toBeTruthy();
	});

	it('renders no badge when pendingLobbyCount is 0', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', onOpenLobby: vi.fn(), pendingLobbyCount: 0 });
		expect(screen.getByLabelText('Waiting to join')).toBeTruthy();
		expect(screen.queryByText('0')).toBeNull();
	});
});

// B3 Task 9 (D2/DN6): the Whiteboard button — unconditional (no server
// toggle), never role-gated (any participant may open it).
describe('ControlsBar — whiteboard (Meet B3 Task 9)', () => {
	it('shows the Whiteboard button for a plain member (no gate) and calls onToggleWhiteboard on click', async () => {
		const onToggleWhiteboard = vi.fn();
		render(ControlsBar, { ...baseProps, selfRole: 'member', onToggleWhiteboard });
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		expect(onToggleWhiteboard).toHaveBeenCalled();
	});

	it('reflects whiteboardOpen as the button\'s active/pressed state', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member', whiteboardOpen: true });
		expect(screen.getByLabelText('Whiteboard')).toHaveAttribute('aria-pressed', 'true');
	});
});

// B3 Task 15: the captions toggle — host/cohost only, requires BOTH
// captionsEnabled (feature.meet_captions) and captionsConfigured (Task 14's
// join-envelope signal, the recordingEnabled genre).
describe('ControlsBar — captions (Meet B3 Task 15)', () => {
	it('hides the captions button when captionsEnabled is false', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', captionsEnabled: false, captionsConfigured: true });
		expect(screen.queryByLabelText('Turn on live captions')).toBeNull();
	});

	it('hides the captions button when captionsConfigured is false (no ASR sidecar deployed)', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'host', captionsEnabled: true, captionsConfigured: false });
		expect(screen.queryByLabelText('Turn on live captions')).toBeNull();
	});

	it('hides the captions button for a plain member even when both signals are true', () => {
		render(ControlsBar, { ...baseProps, selfRole: 'member', captionsEnabled: true, captionsConfigured: true });
		expect(screen.queryByLabelText('Turn on live captions')).toBeNull();
	});

	it('shows the captions button for a cohost when both signals are true, and calls onStartCaptions on click', async () => {
		const onStartCaptions = vi.fn(async () => undefined);
		render(ControlsBar, { ...baseProps, selfRole: 'cohost', captionsEnabled: true, captionsConfigured: true, onStartCaptions });
		await fireEvent.click(screen.getByLabelText('Turn on live captions'));
		expect(onStartCaptions).toHaveBeenCalled();
	});

	it('while captionsOn, the button flips to "off" wording and calls onStopCaptions on click', async () => {
		const onStopCaptions = vi.fn();
		render(ControlsBar, {
			...baseProps,
			selfRole: 'host',
			captionsEnabled: true,
			captionsConfigured: true,
			captionsOn: true,
			onStopCaptions,
		});
		expect(screen.queryByLabelText('Turn on live captions')).toBeNull();
		await fireEvent.click(screen.getByLabelText('Turn off live captions'));
		expect(onStopCaptions).toHaveBeenCalled();
	});

	it('disables the button while the start call is in flight — never a second START from a double-click', async () => {
		let resolveStart: () => void = () => {};
		const onStartCaptions = vi.fn(() => new Promise<void>((resolve) => (resolveStart = resolve)));
		render(ControlsBar, { ...baseProps, selfRole: 'host', captionsEnabled: true, captionsConfigured: true, onStartCaptions });
		const btn = screen.getByLabelText('Turn on live captions') as HTMLButtonElement;
		await fireEvent.click(btn);
		expect(btn.disabled).toBe(true);
		await fireEvent.click(btn); // ignored — still in flight
		expect(onStartCaptions).toHaveBeenCalledTimes(1);
		resolveStart();
		await vi.waitFor(() => expect(btn.disabled).toBe(false));
	});
});
