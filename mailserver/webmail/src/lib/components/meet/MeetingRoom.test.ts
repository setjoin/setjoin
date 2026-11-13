// MeetingRoom.test.ts — Meet B1 Task 16 named tests: gallery caps at 12 +
// overflow tile; the live region announces join/leave.
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import MeetingRoom from './MeetingRoom.svelte';
import type { Participant } from 'livekit-client';

function fakeParticipant(identity: string): Participant {
	return {
		identity,
		name: identity,
		isCameraEnabled: false,
		isMicrophoneEnabled: true,
		isScreenShareEnabled: false,
		videoTrackPublications: new Map(),
		audioTrackPublications: new Map(),
	} as unknown as Participant;
}

const local = fakeParticipant('u:1');

describe('MeetingRoom gallery cap', () => {
	it('caps the gallery at 12 visible tiles total (11 remotes + local) with a "+N more" overflow tile', () => {
		// 15 remotes + 1 local = 16 total → 11 remotes rendered + local + an
		// overflow tile standing in for the other 4 remotes.
		const remotes = Array.from({ length: 15 }, (_, i) => fakeParticipant(`u:${i + 2}`));
		render(MeetingRoom, { localParticipant: local, remoteParticipants: remotes, view: 'gallery' });

		const gallery = screen.getByTestId('gallery');
		const tiles = gallery.querySelectorAll('[data-testid^="tile-"]');
		expect(tiles.length).toBe(12); // 11 remote tiles + local tile
		expect(screen.getByTestId('gallery-overflow').textContent).toContain('+4');
	});

	it('renders no overflow tile when everyone fits', () => {
		const remotes = Array.from({ length: 5 }, (_, i) => fakeParticipant(`u:${i + 2}`));
		render(MeetingRoom, { localParticipant: local, remoteParticipants: remotes, view: 'gallery' });
		expect(screen.queryByTestId('gallery-overflow')).toBeNull();
		expect(screen.getByTestId('gallery').querySelectorAll('[data-testid^="tile-"]').length).toBe(6);
	});
});

describe('MeetingRoom a11y live region', () => {
	it('announces when a participant joins', async () => {
		const { rerender } = render(MeetingRoom, { localParticipant: local, remoteParticipants: [], view: 'gallery' });
		expect(screen.getByRole('status', { name: '' }).textContent).toBe('');

		await rerender({ localParticipant: local, remoteParticipants: [fakeParticipant('u:2')], view: 'gallery' });
		await vi.waitFor(() => expect(screen.getAllByRole('status')[0].textContent).toContain('joined'));
	});

	it('announces when a participant leaves', async () => {
		const { rerender } = render(MeetingRoom, {
			localParticipant: local,
			remoteParticipants: [fakeParticipant('u:2')],
			view: 'gallery',
		});
		await rerender({ localParticipant: local, remoteParticipants: [], view: 'gallery' });
		await vi.waitFor(() => expect(screen.getAllByRole('status')[0].textContent).toContain('left'));
	});

	// B1 live-gate ledger fix 3: the leave announcement used to render the
	// raw LiveKit wire identity ("u:1 left the meeting") instead of the
	// participant's display name — `id` was used directly instead of looking
	// the participant up (the "joined" branch, right above, always resolved
	// `.name`). A leaving participant is already gone from remoteParticipants
	// by the time this fires, so the fix caches names while participants are
	// still present.
	it('uses the display name, never the raw wire identity, in the leave announcement', async () => {
		const bob = fakeParticipant('u:2');
		bob.name = 'Bob Remote';
		const { rerender } = render(MeetingRoom, {
			localParticipant: local,
			remoteParticipants: [bob],
			view: 'gallery',
		});
		await rerender({ localParticipant: local, remoteParticipants: [], view: 'gallery' });
		await vi.waitFor(() => expect(screen.getAllByRole('status')[0].textContent).toContain('Bob Remote left the meeting'));
		expect(screen.getAllByRole('status')[0].textContent).not.toContain('u:2 left');
	});

	it('falls back to a generic label, never the raw wire identity, when the participant never set a display name', async () => {
		const noName = fakeParticipant('u:3');
		noName.name = '';
		const { rerender } = render(MeetingRoom, {
			localParticipant: local,
			remoteParticipants: [noName],
			view: 'gallery',
		});
		await rerender({ localParticipant: local, remoteParticipants: [], view: 'gallery' });
		await vi.waitFor(() => expect(screen.getAllByRole('status')[0].textContent).toContain('A participant left the meeting'));
		expect(screen.getAllByRole('status')[0].textContent).not.toContain('u:3');
	});
});

// B3 Task 15: the CaptionsOverlay mount (chip + transcript + always-mounted
// log region) and its participantNames attribution map.
describe('MeetingRoom — captions mount (B3 Task 15)', () => {
	it('mounts CaptionsOverlay\'s role=log region unconditionally, even with captionsOn omitted (default false)', () => {
		render(MeetingRoom, { localParticipant: local, remoteParticipants: [], view: 'gallery' });
		expect(screen.getByRole('log', { hidden: true })).toBeTruthy();
	});

	it('shows the captions chip when captionsOn is true', () => {
		render(MeetingRoom, { localParticipant: local, remoteParticipants: [], view: 'gallery', captionsOn: true });
		expect(screen.getByText('Live captions on')).toBeTruthy();
	});

	it('hides the captions chip when captionsOn is false', () => {
		render(MeetingRoom, { localParticipant: local, remoteParticipants: [], view: 'gallery', captionsOn: false });
		expect(screen.queryByText('Live captions on')).toBeNull();
	});

	it('builds the participant name map from local + remote participants for per-speaker attribution', () => {
		const remote = fakeParticipant('u:2');
		remote.name = 'Bob Remote';
		render(MeetingRoom, {
			localParticipant: local,
			remoteParticipants: [remote],
			view: 'gallery',
			captionsOn: true,
			captionSegments: [{ sid: 's1', identity: 'u:2', text: 'hi from bob', final: true }],
			captionsFinalsLog: [{ sid: 's1', identity: 'u:2', text: 'hi from bob', final: true }],
		});
		// "Bob Remote" appears twice (the sr-only log entry AND the styled
		// transcript's speaker span) — both are real per-speaker attribution,
		// not a display name-lookup fallback to the raw identity 'u:2'.
		expect(screen.queryAllByText('Bob Remote').length).toBeGreaterThan(0);
		expect(screen.queryByText('u:2')).toBeNull();
	});

	// B3 retro fix (eng #13 / design D7-break): the sr-only region reads
	// captionsFinalsLog, not captionSegments — a caller that forwards only
	// captionSegments must still see the region mount (empty is fine; this
	// pins that the NEW prop is what actually feeds it).
	it('forwards captionsFinalsLog to the sr-only region independently of captionSegments', () => {
		render(MeetingRoom, {
			localParticipant: local,
			remoteParticipants: [],
			view: 'gallery',
			captionsOn: true,
			captionSegments: [],
			captionsFinalsLog: [{ sid: 's9', identity: 'u:9', text: 'from the log', final: true }],
		});
		expect(screen.getByRole('log', { hidden: true }).textContent).toContain('from the log');
	});

	it('forwards captionsHideTranscript to CaptionsOverlay', () => {
		render(MeetingRoom, {
			localParticipant: local,
			remoteParticipants: [],
			view: 'gallery',
			captionsOn: true,
			captionSegments: [{ sid: 's1', identity: 'u:1', text: 'visible?', final: true }],
			captionsHideTranscript: true,
		});
		expect(screen.queryByText('visible?')).toBeNull();
		expect(screen.getByText('Live captions on')).toBeTruthy();
	});
});
