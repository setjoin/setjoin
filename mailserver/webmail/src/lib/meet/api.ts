// Meet B1 client transport — thin typed fetch wrappers over the locked HTTP
// surface (plan §HTTP surface, Tasks 10/11). Reuses $lib/http's timeout/auth/
// DPoP machinery (httpRequest/typedFetch) via problemFetch rather than
// re-implementing it.
import { problemFetch, ProblemError } from '$lib/http';

const BASE = '/api/meet';
const PUBLIC_BASE = '/api/public/meet';

// ── MeetError ────────────────────────────────────────────────────────────
//
// Arch review #A1: ChatError/MeetError/DriveError were three verbatim copies
// of the same RFC-7807-via-encoded-message transport (`$lib/http.ts`'s
// problemFetch). MeetError is now a plain alias onto the one shared
// `ProblemError` class — every existing call site (`instanceof MeetError`,
// `.status`/`.code`/`.detail`) keeps working unchanged.
export const MeetError = ProblemError;
export type MeetError = ProblemError;

const { fetch: meetFetch, fetchVoid: meetFetchVoid } = problemFetch(BASE);
const { fetch: meetPublicFetch } = problemFetch(PUBLIC_BASE);

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// ── wire types (mirrors meeting_read.sql / meeting_create.sql / meeting_join.sql projections) ──

export type MeetingState = 'scheduled' | 'live' | 'ended';
export type MeetingRole = 'host' | 'cohost' | 'member' | 'guest';

/** MEET plan M2: the live presentation summary meeting_get projects for a
 *  CURRENT participant (NULL for a non-participant — the anti-oracle
 *  posture). Exactly the committed checkpoint facts a late joiner validates
 *  against; never page bytes, notes, or source-derived content. */
export interface MeetingPresentationSummary {
	presentationId: number;
	status: string;
	checkpointSeq: number;
	presenterGeneration: number;
	presenterParticipantId: number | null;
	pageIndex: number;
	manifestGeneration: number;
	manifestDigest: string;
	driveNodeId: number;
	driveVersionId: number;
}

export interface PendingJoinRequest {
	requestId: number;
	displayName: string;
	isMemberKnock: boolean;
	createdAt: string;
	expiresAt: string;
}

/** meeting_recordings row projection (meeting_get's `recordings[]`, gated by
 *  meeting_attendee_role — populated only for a historical attendee, an
 *  empty array otherwise, never an absent key — the pendingJoinRequests
 *  anti-oracle shape). */
export interface MeetingRecording {
	recordingId: number;
	state: 'requested' | 'active' | 'stopping' | 'pending_ingest' | 'ready' | 'failed';
	startedAt: string;
	stoppedAt: string | null;
	durationMs: number | null;
	sizeBytes: number | null;
	versionId: number | null;
	fileNodeId: number | null;
	error: string | null;
}

/** meeting_get's `attendance[]` row — host/cohost attendee-only (§9), an
 *  empty array for everyone else (the same anti-oracle shape). */
export interface AttendanceRow {
	identity: string;
	displayName: string;
	role: MeetingRole;
	isGuest: boolean;
	joinedAt: string | null;
	leftAt: string | null;
}

/** A/B leftover item 1: meeting_get's `banned[]` row — the durable
 *  re-admit-list projection, host/cohost attendee-only (same gate/shape as
 *  AttendanceRow above; an empty array, never an absent key, for anyone
 *  else). Replaces the session-only push-built map 5ae8e665's webmail fix
 *  had to fall back to for lack of this projection. */
export interface BannedRow {
	identity: string;
	displayName: string;
	bannedAt: string;
}

/** meeting_get's per-breakout `assignees[]` entry — host/cohost only. */
export interface BreakoutAssignee {
	identity: string;
	displayName: string;
}

/** B3 Task 2/7: `meeting_breakouts` row projection (meeting_get's `breakouts[]`,
 *  ALWAYS present — anti-oracle). `title` is NULL for a host-left-default
 *  room name (D5) — the client renders `meet.breakouts.defaultName` with
 *  `{n: idx}` in that case. `roomName` only appears in the `openBreakouts`
 *  response shape (Go pre-creates each child room from it); `meeting_get`'s
 *  projection omits it (no client use for the raw LiveKit room name there).
 *  `assignees` (Task 7 step 0) exists ONLY on a host/cohost's projection —
 *  a plain member's row has no such key at all, so it stays `undefined`
 *  there rather than an empty array (the anti-oracle: a member can never
 *  learn who else is assigned). MeetApp seeds its own live identity->room
 *  map from this once per meeting load/refetch; BreakoutsPanel itself reads
 *  that live map, not this field, so a `breakout_assigned` push never needs
 *  a full re-fetch to stay current. */
export interface Breakout {
	breakoutId: number;
	idx: number;
	title: string | null;
	roomName?: string;
	assignees?: BreakoutAssignee[];
}

/** meeting_get/meeting_list/meeting_get_by_slug's shared projection.
 *  `pendingJoinRequests` is always present (an empty array for anyone below
 *  host/cohost — the reducer's own anti-oracle, meeting_read.sql). */
export interface Meeting {
	meetingId: number;
	slug: string;
	title: string;
	roomName: string;
	state: MeetingState;
	locked: boolean;
	guestAllowed: boolean;
	scheduledStart: string | null;
	scheduledEnd: string | null;
	chatChannelId: number | null;
	/** V131 huddle chat-bridge fix: whether the CALLER is actually a member of
	 *  `chatChannelId` — a huddle bound to a pre-existing private channel/DM
	 *  only auto-joins a joiner when `meetings.chat_channel_provisioned` is
	 *  true (a fresh channel created FOR the meeting); `chatChannelId` being
	 *  present no longer implies membership. Optional/defaulted `true` by
	 *  `normalizeMeeting` (see below) so a pre-V131 server response — where
	 *  every bound channel WAS auto-join — still behaves exactly as before. */
	chatChannelMember?: boolean;
	calendarEventId: number | null;
	ownerUserId: number;
	createdAt: string;
	endedAt: string | null;
	/** null when the caller is neither owner nor an active participant. */
	myRole: MeetingRole | null;
	pendingJoinRequests: PendingJoinRequest[];
	/** D5: rides every admission envelope. Also on `meeting_list` items. */
	recordingActive: boolean;
	/** Task 10 step 0: the button-visibility signal — BOTH
	 *  feature.meet_recording and feature.drive must be ON. meeting_get only
	 *  (not meeting_list). */
	recordingEnabled: boolean;
	/** meeting_attendee_role-gated; empty for a non-attendee (anti-oracle). */
	recordings: MeetingRecording[];
	/** host/cohost attendee-only (§9); empty for everyone else. */
	attendance: AttendanceRow[];
	/** A/B leftover item 1: host/cohost attendee-only, same shape/gate as
	 *  attendance above — the re-admit list, durable across a reload. */
	banned: BannedRow[];
	/** B3 Task 2/7 keys — typed now, additive-safe (see `normalizeMeeting`
	 *  below: a pre-Task-7 server response is missing these entirely, and
	 *  they are defaulted client-side so every B3 consumer reads a real
	 *  boolean/array/null, never `undefined`). `breakoutsEnabled` mirrors the
	 *  `recordingEnabled` toggle-read genre (`feature.meet_breakouts`).
	 *  `breakouts` is ALWAYS present (anti-oracle, `pendingJoinRequests`
	 *  genre); `myBreakoutId` is the caller's own assignment (NULL when
	 *  unassigned/non-participant). */
	breakoutsEnabled: boolean;
	breakouts: Breakout[];
	myBreakoutId: number | null;
	/** B3 Task 13/14 keys, same defaulting posture. */
	captionsEnabled: boolean;
	captionsOn: boolean;
	/** MEET plan M3: the "Present a document" button-visibility signal —
	 *  meeting_get's presentationEnabled (feature.meet_document_presentation
	 *  AND feature.drive). Optional/additive-safe like its
	 *  breakouts/captions siblings: normalizeMeeting defaults it false, so
	 *  a pre-M2 server response keeps every presentation surface hidden
	 *  (the default-OFF flag posture, mirrored client-side). */
	presentationEnabled?: boolean;
	/** MEET plan M2: the live presentation summary — ALWAYS present as a
	 *  key on an M2 server (NULL for a non-participant); normalizeMeeting
	 *  defaults it null for a pre-M2 response. The store's sync() reauthorizes
	 *  from this + the authorized checkpoint read. */
	presentation?: MeetingPresentationSummary | null;
}

/** Defaults the B3 breakout/captions keys until the server actually ships
 *  them (Task 7 lands `breakouts`/`myBreakoutId`/`breakoutsEnabled` on
 *  `meeting_get`; Task 13/14 lands `captionsEnabled`/`captionsOn`) — without
 *  this, a `Meeting` object built from a pre-B3 response would type-check as
 *  `breakouts: Breakout[]` while actually holding `undefined` at runtime, a
 *  footgun for every B3 consumer (Tasks 7/9/15). Applied to every route that
 *  returns a `Meeting` shape. */
function normalizeMeeting(m: Meeting): Meeting {
	return {
		...m,
		breakoutsEnabled: m.breakoutsEnabled ?? false,
		breakouts: m.breakouts ?? [],
		myBreakoutId: m.myBreakoutId ?? null,
		captionsEnabled: m.captionsEnabled ?? false,
		captionsOn: m.captionsOn ?? false,
		// MEET M3: absent on a pre-M2 server response — default OFF hides the
		// whole presentation surface (never half-visible).
		presentationEnabled: m.presentationEnabled ?? false,
		// MEET M2: the live presentation summary (null = none / non-participant).
		presentation: m.presentation ?? null,
		// A/B leftover item 1: absent on a pre-item-1 server response.
		banned: m.banned ?? [],
		// V131: absent on a pre-V131 server response, where every bound
		// channel WAS auto-join — default true so provisioned meetings (the
		// overwhelming common case) are unaffected.
		chatChannelMember: m.chatChannelMember ?? true,
	};
}

/** meeting_create's narrower return shape (meeting_create.sql) — not the
 *  full Meeting projection; callers that need the rest re-fetch via getMeeting. */
export interface CreateMeetingResult {
	meetingId: number;
	slug: string;
	roomName: string;
	chatChannelId: number | null;
}

export interface CreateMeetingBody {
	title: string;
	scheduledStart?: string | null;
	scheduledEnd?: string | null;
	chatChannelId?: number | null;
	calendarEventId?: number | null;
	guestAllowed?: boolean | null;
}

/** The LiveKit connection credentials handed back by every route that mints
 *  a token (join, the public poll's admitted leg) — shared shape. */
export interface MeetToken {
	token: string;
	wsPath: string;
	expiresAt: string;
}

export interface JoinResult extends MeetToken {
	meeting: Meeting;
	/** D5 "rides EVERY admission envelope" (E-F3): the join grant spec's OWN
	 *  recordingActive — the admission fact, not a second getMeeting read.
	 *  MeetApp seeds the in-room banner from THIS key, never `meeting.
	 *  recordingActive`. */
	recordingActive: boolean;
	/** B3 Task 14: whether the captions sidecar pair is deployed/reachable —
	 *  the button-visibility signal, the `recordingEnabled` genre. Optional:
	 *  absent on a pre-Task-14 server response (normalizeMeeting only
	 *  defaults `Meeting`-shaped keys; `JoinResult` is its own narrower
	 *  wire shape, so callers treat an absent key as `false`). */
	captionsConfigured?: boolean;
}

// ── authed routes (Task 10) ───────────────────────────────────────────────

export const createMeeting = (body: CreateMeetingBody) =>
	meetFetch<CreateMeetingResult>('', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });

/** "My meetings" — owner or participant, not ended-older-than-24h (meeting_list). */
export const listMeetings = () => meetFetch<Meeting[]>('').then((list) => list.map(normalizeMeeting));

export const getMeeting = (meetingId: number) => meetFetch<Meeting>(`/${meetingId}`).then(normalizeMeeting);

/** The member deep-link resolve (GET /meet/by-slug/{slug}). */
export const resolveSlug = (slug: string) =>
	meetFetch<Meeting>(`/by-slug/${encodeURIComponent(slug)}`).then(normalizeMeeting);

export const join = (meetingId: number) =>
	meetFetch<JoinResult>(`/${meetingId}/join`, { method: 'POST' }).then((r) => ({
		...r,
		meeting: normalizeMeeting(r.meeting),
	}));

export const lock = (meetingId: number, locked: boolean) =>
	meetFetchVoid(`/${meetingId}/lock`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ locked }) });

/** CEO #4 — flip guest access mid-meeting; affects FUTURE knocks only, never evicts. */
export const setGuestAllowed = (meetingId: number, guestAllowed: boolean) =>
	meetFetchVoid(`/${meetingId}/settings`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ guestAllowed }),
	});

/** Also the re-admit path: assigning a role to a banned identity clears
 *  banned_at server-side (meeting_set_role.sql) — no separate route. */
export const setRole = (meetingId: number, identity: string, role: 'cohost' | 'member') =>
	meetFetchVoid(`/${meetingId}/role`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ identity, role }),
	});

/** Authorizes + bans in one reducer call, then evicts (RemoveParticipant) —
 *  DES-011: the DB state is correct even if eviction itself 502s. */
export const kick = (meetingId: number, identity: string) =>
	meetFetchVoid(`/${meetingId}/kick`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ identity }) });

export const end = (meetingId: number) => meetFetchVoid(`/${meetingId}/end`, { method: 'POST' });

/** POST /meet/{id}/requests/{reqId} {action}. The "admit" arm's reducer
 *  (meeting_admit) hands back `{identity}` on the wire, but the caller
 *  (LobbyPanel) already has the requestId it needs to remove the row from
 *  its own pending list — so this stays void-returning for both arms rather
 *  than typing two different response shapes for a value nothing reads. */
export const decideRequest = (meetingId: number, requestId: number, action: 'admit' | 'deny') =>
	meetFetchVoid(`/${meetingId}/requests/${requestId}`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ action }),
	});

/** A member knocking on a locked meeting — returns the SAME
 *  {requestId, secret} shape the public create route does; completion rides
 *  the public poll route below (eng #5 / plan Task 11). */
export const knock = (meetingId: number, slug?: string) =>
	meetFetch<{ requestId: number; secret: string }>(`/${meetingId}/knock`, {
		method: 'POST',
		...(slug === undefined ? {} : { headers: JSON_HEADERS, body: JSON.stringify({ slug }) }),
	});

// ── public lobby (the ONE unauthenticated surface, Task 11) ──────────────

/** MEET-002 (CWE-598): the guest lobby poll's {requestId, secret} pair
 *  carries its secret half on this request HEADER, never the URL — a query
 *  string leaks into access logs, proxies and referrers. Matches the
 *  gateway's `lobbySecretHeader` (internal/meet/lobby.go); requestId stays
 *  in the path. */
export const LOBBY_SECRET_HEADER = 'X-Meet-Lobby-Secret';

export const guestJoinRequest = (slug: string, displayName: string) =>
	meetPublicFetch<{ requestId: number; secret: string }>(`/${encodeURIComponent(slug)}/join-request`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ displayName }),
	});

/** D5's flicker-window belt (D-7): `recordingActive` rides the `pending` and
 *  `admitted` arms only — a `denied`/`expired` request has no consent
 *  decision left to make, so the key is absent there. Each state is its own
 *  union member (not `'denied' | 'expired'` combined) so a caller's
 *  sequential `if (res.state === 'denied') return; if (res.state ===
 *  'expired') return;` narrows cleanly down to the `pending` member.
 *  B3 Task 13/15: `captionsOn` rides the `admitted` arm ONLY
 *  (`meeting_lobby.sql`'s two admitted branches, both — DN3: the captions
 *  indicator is visible to guests too) — the `pending` arm never carries it
 *  (the reducer doesn't project it there; nothing to seed a chip from before
 *  admission anyway). B3 retro fix (design finding #4/#5): `ccIdentity`
 *  (`'cc:' || meetingId`) now rides BOTH admitted arms too, unconditionally
 *  on `captionsOn` — it dissolves the guest-captions attestation ceiling
 *  (Task 7/15's documented gap): the guest join page can attest `cc` frames
 *  regardless of whether captions happen to be live at admit time. */
export type GuestPollResult =
	| { state: 'pending'; recordingActive?: boolean }
	| { state: 'denied' }
	| { state: 'expired' }
	| ({ state: 'admitted'; recordingActive?: boolean; captionsOn?: boolean; ccIdentity?: string } & MeetToken);

export const guestPoll = (slug: string, requestId: number, secret: string) =>
	meetPublicFetch<GuestPollResult>(`/${encodeURIComponent(slug)}/join-request/${requestId}`, {
		headers: { [LOBBY_SECRET_HEADER]: secret },
	});

// ── recording (Task 10) ───────────────────────────────────────────────────

export const startRecording = (meetingId: number) =>
	meetFetch<{ recordingId: number }>(`/${meetingId}/recording`, { method: 'POST' });

export const stopRecording = (meetingId: number) => meetFetchVoid(`/${meetingId}/recording`, { method: 'DELETE' });

// ── breakouts (Task 6; Go: breakouts.go, F11 open-only gate, D11 create-on-mint) ──

/** Host/cohost only — `feature.meet_breakouts` 404s BEFORE the path id parses
 *  (F11/E-F9); assign/close/join below are UNCONDITIONAL (the drain
 *  posture). `count` 1..20, `titles`/`autoAssign` optional. */
export const openBreakouts = (meetingId: number, count: number, titles?: string[], autoAssign?: boolean) =>
	meetFetch<{ breakouts: Breakout[] }>(`/${meetingId}/breakouts`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ count, titles, autoAssign }),
	});

/** Host/cohost only. `breakoutId: null` returns the target to the main room. */
export const assignBreakout = (meetingId: number, targetUserId: number, breakoutId: number | null) =>
	meetFetchVoid(`/${meetingId}/breakouts/assign`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ targetUserId, breakoutId }),
	});

/** Host/cohost only. Idempotent — a no-op 204 when nothing is open. */
export const closeBreakouts = (meetingId: number) => meetFetchVoid(`/${meetingId}/breakouts/close`, { method: 'POST' });

/** `breakoutId` omitted/null joins the caller's own assignment (member) or
 *  main (host/cohost roaming). D11: the server pre-creates the child room
 *  before minting — the returned token is always connectable. */
export const joinBreakout = (meetingId: number, breakoutId?: number | null) =>
	meetFetch<MeetToken & { recordingActive: boolean }>(`/${meetingId}/breakouts/join`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ breakoutId: breakoutId ?? null }),
	});

// ── captions (Task 14/15; captions.go, F11/D11 toggle-gated-start/drain-stop) ──

/** Host/cohost only — `feature.meet_captions` 404s BEFORE the path id parses
 *  (E-F9), same as recording's start. 204 either on a fresh bind or the
 *  already-on idempotent no-op (D8) — nothing in the response body to type. */
export const startCaptions = (meetingId: number) => meetFetchVoid(`/${meetingId}/captions`, { method: 'POST' });

/** UNCONDITIONAL — no toggle gate (F11/D11 drain posture): a session started
 *  before a toggle flip OFF must still be stoppable. Idempotent either way. */
export const stopCaptions = (meetingId: number) => meetFetchVoid(`/${meetingId}/captions`, { method: 'DELETE' });
