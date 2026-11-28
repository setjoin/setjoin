// guestReconnect.ts — Meet B1 Task 17, design #7: classifies a LiveKit
// `Disconnected` event received while a guest is in-room. A Disconnected
// event is terminal (LiveKit's own internal Reconnecting/Reconnected pair
// handles transient network blips WITHOUT ever firing it), so reaching this
// path means something ended the session — but "something" could be a real
// kick, the host ending the meeting, or (rarely) a hard network drop that
// never got a chance to Reconnect. Rather than guess from the client side,
// this does ONE poll of the guest's ORIGINAL join-request and reads what the
// server actually recorded:
//
//   - denied  → meeting_kick flips a guest's join_request row to 'denied'
//               in the same statement as the ban (meeting_control.sql) —
//               this IS "you were removed".
//   - expired → meeting_join_request_poll synthesizes 'expired' on the wire
//               for an admitted row once meetings.state leaves
//               scheduled/live (meeting_lobby.sql) — this IS "the meeting
//               ended". A 404-class error (nonexistent slug) reads the same
//               under the BZ185 anti-oracle.
//   - admitted → a genuinely transient disconnect; the same grant is still
//               live, so reconnect with the fresh token rather than treating
//               it as a revocation. The poll's recordingActive admission
//               fact (D5/D-7) rides along so the caller can re-run the
//               recording consent gate before reconnecting — med-shard3-021:
//               discarding it here let a mid-recording reconnect bypass
//               RecordingConsentGate entirely (the member surface re-gates).
//   - anything else (pending, or any other transport error) → not a
//               revocation either, but not immediately reconnectable — the
//               caller shows a manual reconnect UI instead of guessing.
import { guestPoll, MeetError, type MeetToken } from './api';

export type PostDisconnectOutcome =
	| { kind: 'removed' }
	| { kind: 'ended' }
	| { kind: 'admitted'; token: MeetToken; recordingActive: boolean }
	| { kind: 'reconnect' };

export async function classifyPostDisconnect(
	slug: string,
	requestId: number,
	secret: string,
): Promise<PostDisconnectOutcome> {
	try {
		const res = await guestPoll(slug, requestId, secret);
		if (res.state === 'denied') return { kind: 'removed' };
		if (res.state === 'expired') return { kind: 'ended' };
		if (res.state === 'admitted') {
			return {
				kind: 'admitted',
				token: { token: res.token, wsPath: res.wsPath, expiresAt: res.expiresAt },
				// med-shard3-021: the SAME admission fact LobbyWaiting hands
				// onAdmitted (!!-normalized, false when the admitted arm
				// carries none) — the caller gates on it before reconnecting.
				recordingActive: !!res.recordingActive,
			};
		}
		return { kind: 'reconnect' }; // 'pending' shouldn't happen post-admission — never treated as a revocation
	} catch (err) {
		if (err instanceof MeetError && err.status === 404) return { kind: 'ended' };
		return { kind: 'reconnect' };
	}
}
