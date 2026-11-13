// ParticipantTile.test.ts — Meet B1 Task 16, design #8 (guest badge is the
// trust boundary — a spoofable display name is never the authority) and
// design #4 (the connection-quality dot).
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import ParticipantTile from './ParticipantTile.svelte';
import { ConnectionQuality, type Participant } from 'livekit-client';

function fakeParticipant(identity: string, over: Partial<Participant> = {}): Participant {
	return {
		identity,
		name: identity,
		isCameraEnabled: false,
		isMicrophoneEnabled: true,
		isScreenShareEnabled: false,
		videoTrackPublications: new Map(),
		audioTrackPublications: new Map(),
		...over,
	} as unknown as Participant;
}

describe('ParticipantTile', () => {
	it('shows a Guest badge for a g: identity and none for a u: identity', () => {
		const { rerender } = render(ParticipantTile, { participant: fakeParticipant('g:42') });
		expect(screen.getByText('Guest')).toBeTruthy();

		rerender({ participant: fakeParticipant('u:42') });
		expect(screen.queryByText('Guest')).toBeNull();
	});

	it('shows External only for a signed u: participant attribute and keeps g: identities Guest', () => {
		const { rerender } = render(ParticipantTile, {
			participant: fakeParticipant('u:42', { attributes: { 'setjoin.external': 'true' } }),
		});
		expect(screen.getByText('External')).toBeTruthy();
		expect(screen.queryByText('Guest')).toBeNull();

		rerender({ participant: fakeParticipant('g:42', { attributes: { 'setjoin.external': 'true' } }) });
		expect(screen.getByText('Guest')).toBeTruthy();
		expect(screen.queryByText('External')).toBeNull();
	});

	it('shows the mute badge when the participant is not publishing audio', () => {
		render(ParticipantTile, { participant: fakeParticipant('u:1', { isMicrophoneEnabled: false }) });
		expect(screen.getByLabelText('Unmute')).toBeTruthy();
	});

	it('renders the avatar (not a <video>) when the camera is off', () => {
		const { container } = render(ParticipantTile, { participant: fakeParticipant('u:1') });
		expect(container.querySelector('video')).toBeFalsy();
		expect(container.querySelector('.avatar')).toBeTruthy();
	});

	it('renders a connection-quality dot labeled for the given ConnectionQuality', () => {
		render(ParticipantTile, { participant: fakeParticipant('u:1'), quality: ConnectionQuality.Poor });
		expect(screen.getByLabelText('Connection: poor')).toBeTruthy();
	});
});
