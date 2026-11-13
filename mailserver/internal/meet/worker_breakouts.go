// worker_breakouts.go — B3 Task 5: the two breakout worker arms
// (gcClosedBreakoutRooms, reconcileBreakoutPresence) on the shared Worker
// (worker.go). Both run INSIDE the SAME `feature.meet && Configured()` gate
// as the original Task-12 lifecycle legs (see worker.go's file-header "TWO
// GATING POSTURES" block — they need liveSet/RoomController the same way
// deleteEndedButLiveRooms does) but are NEVER gated on feature.meet_breakouts
// (F11): a toggle flip must never strand anyone in a breakout room nobody
// can close or leave.
package meet

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// openBreakoutRoom is one drained meeting_breakouts row, scoped to
// reconcileBreakoutPresence's candidate set (an OPEN breakout on a
// currently-live meeting) — mainRoom carries the parent's room name so the
// NULL-assignment ("belongs in main") case resolves without a second query.
type openBreakoutRoom struct {
	id        int64
	meetingID int64
	roomName  uuid.UUID
	mainRoom  uuid.UUID
}

// breakoutAssignment is one drained meeting_participants row — MEMBER role
// only. Host/cohost roam any open breakout by design (D7) and are never
// tracked by breakout_id (it stays NULL for them even while they sit in a
// child room) — comparing them against "assigned room" here would evict a
// roaming host on their very next tick. Guests are never assignable at all
// (meeting_breakout_assign's target select requires a 'u:' identity).
type breakoutAssignment struct {
	meetingID  int64
	identity   string
	breakoutID *int64
}

// absentEntry is one absentSince value (Worker.absentSince, worker.go) — the
// meeting/identity a grace-map key belongs to, so sweepStaleAbsentEntries can
// settle it without re-parsing the "meetingID/identity" key string.
type absentEntry struct {
	meetingID int64
	identity  string
}

// reconcileBreakouts is the B3 Task 5 worker pair, called from tick() right
// after deleteEndedButLiveRooms (reusing its liveSet): leg 1
// (gcClosedBreakoutRooms) is the deleteEndedButLiveRooms shape cloned onto
// meeting_breakouts; leg 2 (reconcileBreakoutPresence) is the spec's F2
// assignment↔presence healer. Neither is ever gated on
// feature.meet_breakouts (F11) — only on feature.meet/Configured(), the
// same gate deleteEndedButLiveRooms itself sits behind in tick().
func (w *Worker) reconcileBreakouts(ctx context.Context, liveSet map[string]bool) {
	w.gcClosedBreakoutRooms(ctx, liveSet)
	w.reconcileBreakoutPresence(ctx)
}

// gcClosedBreakoutRooms retries DeleteRoom for a child breakout room the SFU
// still lists after (a) its OWN row closed, or (b) its PARENT meeting ended
// — the open/close-all/end 502-retry backstop (Task 10's deleteEndedButLiveRooms)
// extended to child rooms. Bounded to the last 24h, the identical window
// deleteEndedButLiveRooms already uses.
func (w *Worker) gcClosedBreakoutRooms(ctx context.Context, liveSet map[string]bool) {
	w.retryDeleteForRooms(ctx, liveSet, "meet worker: breakout child-room", `
		SELECT b.room_name FROM meeting_breakouts b JOIN meetings m ON m.id = b.meeting_id
		 WHERE (b.state = 'closed' AND b.closed_at > now() - interval '24 hours')
		    OR (m.state = 'ended' AND m.ended_at > now() - interval '24 hours')`)
}

// drainOpenBreakoutRooms is leg 2's first query: every open breakout room on
// a currently-live meeting, joined to its parent's room name so the
// NULL-assignment ("main room") case resolves without a second query. F2:
// fully drained (rows.Close'd) before any RoomController call below.
func (w *Worker) drainOpenBreakoutRooms(ctx context.Context) ([]openBreakoutRoom, error) {
	rows, err := w.pool.Query(ctx, `
		SELECT b.id, b.meeting_id, b.room_name, m.room_name
		  FROM meeting_breakouts b JOIN meetings m ON m.id = b.meeting_id
		 WHERE b.state = 'open' AND m.state = 'live'`)
	if err != nil {
		return nil, err
	}
	var out []openBreakoutRoom
	for rows.Next() {
		var r openBreakoutRoom
		if err := rows.Scan(&r.id, &r.meetingID, &r.roomName, &r.mainRoom); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	return out, rows.Err()
}

// drainBreakoutAssignments is leg 2's second query — MEMBER-role rows only
// (see breakoutAssignment), scoped to meetings that currently have at least
// one open breakout. Drained fully before any RoomController call (F2).
func (w *Worker) drainBreakoutAssignments(ctx context.Context) ([]breakoutAssignment, error) {
	rows, err := w.pool.Query(ctx, `
		SELECT meeting_id, identity, breakout_id FROM meeting_participants
		 WHERE role = 'member' AND left_at IS NULL AND banned_at IS NULL
		   AND meeting_id IN (SELECT DISTINCT meeting_id FROM meeting_breakouts WHERE state = 'open')`)
	if err != nil {
		return nil, err
	}
	var out []breakoutAssignment
	for rows.Next() {
		var a breakoutAssignment
		if err := rows.Scan(&a.meetingID, &a.identity, &a.breakoutID); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	rows.Close()
	return out, rows.Err()
}

// reconcileBreakoutPresence is the spec's F2 assignment↔presence healer: it
// compares meeting_participants.breakout_id (reducer truth for where a
// member BELONGS) against what the SFU actually reports live in each room,
// and heals both directions of drift in one pass — a client that ignored a
// breakout_assigned push or reused a stale main-room token to sneak back
// (present in a room they are not assigned to → RemoveParticipant, their
// client re-runs the join choreography and lands where assigned), and a
// participant the SFU silently dropped, e.g. a failed RemoveParticipant
// after the reducer already committed a move, or a crash mid-move (assigned
// but absent from EVERY room, past a one-tick grace → left_at stamped).
//
// Scoped to meetings with ≥1 open breakout (a meeting with none adds ZERO
// ListParticipants calls) and to MEMBER-role assignment rows only — see
// breakoutAssignment's doc for why host/cohost/guests are out of scope here.
func (w *Worker) reconcileBreakoutPresence(ctx context.Context) {
	// F2: both reads below are fully drained before any RoomController call.
	children, err := w.drainOpenBreakoutRooms(ctx)
	if err != nil {
		w.logger.Warn("meet worker: breakout open-rooms query failed", "error", err)
		return
	}

	candidateMeetings := make(map[int64]bool, len(children))
	for _, c := range children {
		candidateMeetings[c.meetingID] = true
	}
	// eng retro finding #4: settle every absentSince entry whose meeting has
	// left this tick's candidate set BEFORE anything else — see absentSince's
	// own doc comment for what this fixes (growth/staleness/phantom).
	w.sweepStaleAbsentEntries(ctx, candidateMeetings)

	if len(children) == 0 {
		return // no live meeting has an open breakout — zero ListParticipants calls
	}
	assignments, err := w.drainBreakoutAssignments(ctx)
	if err != nil {
		w.logger.Warn("meet worker: breakout assignments query failed", "error", err)
		return
	}

	mainRoomByMeeting := map[int64]string{}
	childrenByMeeting := map[int64][]string{}
	roomByBreakoutID := map[int64]string{}
	for _, c := range children {
		mainRoomByMeeting[c.meetingID] = c.mainRoom.String()
		childrenByMeeting[c.meetingID] = append(childrenByMeeting[c.meetingID], c.roomName.String())
		roomByBreakoutID[c.id] = c.roomName.String()
	}

	// presence[meetingID][identity] = every room that identity was reported
	// present in this tick (normally at most one; a stale second connection
	// can in principle leave someone present in two rooms at once).
	presence := map[int64]map[string][]string{}
	for meetingID, mainRoom := range mainRoomByMeeting {
		p := map[string][]string{}
		w.fillBreakoutPresence(ctx, meetingID, mainRoom, p)
		for _, room := range childrenByMeeting[meetingID] {
			w.fillBreakoutPresence(ctx, meetingID, room, p)
		}
		presence[meetingID] = p
	}

	for _, a := range assignments {
		var assignedRoom string
		if a.breakoutID == nil {
			assignedRoom = mainRoomByMeeting[a.meetingID]
		} else if rn, ok := roomByBreakoutID[*a.breakoutID]; ok {
			assignedRoom = rn
		} else {
			continue // assigned to a breakout no longer open — nothing to reconcile this tick
		}

		key := fmt.Sprintf("%d/%s", a.meetingID, a.identity)
		rooms := presence[a.meetingID][a.identity]
		if len(rooms) == 0 {
			w.markBreakoutAbsentOrStamp(ctx, key, a.meetingID, a.identity)
			continue
		}
		delete(w.absentSince, key) // present somewhere — reappeared, never stamp (delta 8)
		for _, room := range rooms {
			if room == assignedRoom {
				continue
			}
			if err := w.rooms.RemoveParticipant(ctx, room, a.identity); err != nil {
				w.logger.Warn("meet worker: breakout presence-heal RemoveParticipant failed",
					"meeting_id", a.meetingID, "identity", a.identity, "room", room, "error", err)
			}
		}
	}
}

// fillBreakoutPresence ListParticipants a single room and records every
// identity found into presence (identity -> rooms present in this tick).
func (w *Worker) fillBreakoutPresence(ctx context.Context, meetingID int64, room string, presence map[string][]string) {
	identities, err := w.rooms.ListParticipants(ctx, room)
	if err != nil {
		w.logger.Warn("meet worker: breakout ListParticipants failed", "meeting_id", meetingID, "room", room, "error", err)
		return
	}
	for _, id := range identities {
		presence[id] = append(presence[id], room)
	}
}

// markBreakoutAbsentOrStamp is the delta-8 one-interval grace.
// ponytail: absentSince is in-memory — a worker restart extends the grace,
// never fires it early; move to a DB column if multi-instance workers ever
// exist.
//
// Every call to reconcileBreakoutPresence corresponds to one worker tick —
// an identity already present in absentSince means the PRIOR tick already
// found it absent, so this is its second consecutive absent tick and
// left_at stamps now; a fresh absence is recorded but never stamped on the
// same call (no wall-clock arithmetic needed: two ticks are, by
// construction, at least one full interval apart).
func (w *Worker) markBreakoutAbsentOrStamp(ctx context.Context, key string, meetingID int64, identity string) {
	if _, seenLastTick := w.absentSince[key]; !seenLastTick {
		w.absentSince[key] = absentEntry{meetingID: meetingID, identity: identity}
		return
	}
	if _, err := w.pool.Exec(ctx, `UPDATE meeting_participants SET left_at = now()
		 WHERE meeting_id = $1 AND identity = $2 AND left_at IS NULL`, meetingID, identity); err != nil {
		w.logger.Warn("meet worker: breakout absence left_at stamp failed",
			"meeting_id", meetingID, "identity", identity, "error", err)
		return
	}
	delete(w.absentSince, key)
}

// sweepStaleAbsentEntries settles every absentSince entry whose meeting is
// NOT in this tick's candidateMeetings set — a breakout session that closed
// (or a meeting that ended) since the entry was recorded. One parent-room
// presence check per stale entry settles it either way: still absent from
// the parent → the identity really did leave (the phantom-participant fix —
// the normal per-tick loop below never runs again for this meeting once its
// last open breakout closes, since drainBreakoutAssignments only selects
// meetings with an open breakout, so without this sweep left_at would never
// stamp and gcLostWebhooks' NOT EXISTS(open participants) predicate would
// block forever); present in the parent → a legitimate return-to-main, no
// stamp. Either way the entry is DELETED ONLY on a definitive answer —
// never on a transient error (B3 confirm-pass fix, eng #5/#6): a
// ListParticipants/meetings-query failure retains the entry for a retry
// next tick instead of deleting it (which used to silently re-open the very
// phantom-participant hole this sweep exists to close, for that one
// identity, on every transient hiccup). The one exception is
// pgx.ErrNoRows on the meetings lookup — the meeting row is definitively
// gone, so there is nothing left to ever retry against; drop rather than
// leak forever.
func (w *Worker) sweepStaleAbsentEntries(ctx context.Context, candidateMeetings map[int64]bool) {
	type stale struct {
		key   string
		entry absentEntry
	}
	var entries []stale
	for key, entry := range w.absentSince {
		if candidateMeetings[entry.meetingID] {
			continue // still a candidate this tick — the normal loop below owns it
		}
		entries = append(entries, stale{key: key, entry: entry})
	}
	for _, s := range entries {
		var mainRoom uuid.UUID
		err := w.pool.QueryRow(ctx, `SELECT room_name FROM meetings WHERE id = $1`, s.entry.meetingID).Scan(&mainRoom)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// definitive: the meeting row itself no longer exists — no
				// future tick can ever resolve this, so drop it now.
				delete(w.absentSince, s.key)
				continue
			}
			// transient query error (connection blip, timeout, ...) — keep
			// the entry and retry next tick rather than dropping it and
			// silently losing the left_at stamp forever.
			w.logger.Warn("meet worker: absent-sweep meetings query failed, retaining entry for retry",
				"meeting_id", s.entry.meetingID, "identity", s.entry.identity, "error", err)
			continue
		}
		present, err := w.rooms.ListParticipants(ctx, mainRoom.String())
		if err != nil {
			// transient SFU error — same posture: retain, retry next tick.
			w.logger.Warn("meet worker: absent-sweep ListParticipants failed, retaining entry for retry",
				"meeting_id", s.entry.meetingID, "identity", s.entry.identity, "error", err)
			continue
		}
		stillAbsent := true
		for _, id := range present {
			if id == s.entry.identity {
				stillAbsent = false
				break
			}
		}
		if stillAbsent {
			if _, err := w.pool.Exec(ctx, `UPDATE meeting_participants SET left_at = now()
				 WHERE meeting_id = $1 AND identity = $2 AND left_at IS NULL`,
				s.entry.meetingID, s.entry.identity); err != nil {
				w.logger.Warn("meet worker: absent-sweep left_at stamp failed, retaining entry for retry",
					"meeting_id", s.entry.meetingID, "identity", s.entry.identity, "error", err)
				continue // the UPDATE itself failed — not a definitive answer either.
			}
		}
		delete(w.absentSince, s.key)
	}
}
