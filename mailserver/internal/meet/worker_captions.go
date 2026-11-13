// worker_captions.go — B3 Task 14: the bidirectional captions worker arm
// (reconcileCaptions) on the shared Worker (worker.go). Runs INSIDE the
// SAME `feature.meet && Configured()` gate as the original Task-12
// lifecycle legs (see worker.go's file-header "TWO GATING POSTURES" block)
// but is NEVER gated on feature.meet_captions itself (F11/D11 extended): a
// toggle flip must never strand a crashed or orphaned captions session.
package meet

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// captionsGrace mirrors requestedGrace's role for captions: a
// meetings.settings.captionsSince stamp younger than one worker interval
// means a Start (leg a) or an off/end flip (leg b's destructive DeleteRoom)
// might still be racing this tick's snapshot — reconcile must never act on
// a commit it cannot yet fully see (the SAME ListEgress-vs-registry-read
// race class F1 guards in reconcileRecordingsEgress, applied to
// captionsSince/Status() instead of StartedAt/ListEgress).
const captionsGrace = workerInterval

// captionsOnRow is one meetings row with captionsOn=true, drained fully
// (F2) before any per-row worker-plane write or controller call.
type captionsOnRow struct {
	meetingID int64
	room      uuid.UUID
	since     time.Time
}

// reconcileCaptions is the B3 Task 14 bidirectional healer, called from
// tick() unconditionally — w.captions nil-guarded here (an ASR sidecar not
// provisioned on this box means nothing to reconcile), NEVER gated on
// feature.meet_captions itself (F11/D11 extended: a toggle flip must never
// strand a crashed or orphaned captions session). Leg (a)
// (reconcileCaptionsCrashed): a captionsOn=true meeting whose room the ASR
// sidecar no longer lists in Status() — the bot crashed — flips the flag
// off (worker-plane; no host/cohost caller exists here) once captionsSince
// is stale (F5's start-grace: a Start still in flight against a flag
// commit reconcile cannot yet see in Status() must never be killed). Leg
// (b) (reconcileCaptionsOrphaned): a Status()-reported session whose
// meeting is no longer captioning (flag already off — a lost Stop) or has
// ended gets Stop retried unconditionally, with DeleteRoom as the
// grace-guarded backstop for an ended meeting (the bot's own connection can
// keep an otherwise-empty ended room alive past the SFU's EmptyTimeout —
// the deleteEndedButLiveRooms 24h retry window may already be covering it,
// but Status() is an independent, earlier signal that the room is still
// genuinely occupied).
func (w *Worker) reconcileCaptions(ctx context.Context) {
	// eng retro finding #5 (the drain-wedge fix): a nil controller (no ASR
	// sidecar configured on this box) must NOT no-op leg (a) — no controller
	// means no live session can possibly exist by construction (h.captions
	// is the only thing that ever calls Start), so every captionsOn=true
	// row is, by definition, stale and must still converge to OFF once past
	// the captionsSince grace. Only leg (b) is naturally a no-op here: it
	// walks Status()-reported sessions, and there are none to walk. Status()
	// itself is skipped entirely when nil — it would just error.
	var sessions []string
	if w.captions != nil {
		var err error
		sessions, err = w.captions.Status(ctx)
		if err != nil {
			w.logger.Warn("meet worker: captions Status failed", "error", err)
			return
		}
	}
	live := make(map[string]bool, len(sessions))
	for _, room := range sessions {
		live[room] = true
	}
	w.reconcileCaptionsCrashed(ctx, live)
	w.reconcileCaptionsOrphaned(ctx, sessions)
}

// reconcileCaptionsCrashed is leg (a): flip a stale, session-less
// captionsOn=true row's flag off (worker-plane jsonb_set, since no
// host/cohost caller exists in a background sweep) and push the SAME
// captions_state{on:false} event meeting_captions_set's own ON->OFF arm
// pushes, so a live client's chip converges identically whether a human or
// the worker turned it off.
func (w *Worker) reconcileCaptionsCrashed(ctx context.Context, live map[string]bool) {
	rows, err := w.pool.Query(ctx, `
		SELECT id, room_name, (settings->>'captionsSince')::timestamptz
		  FROM meetings
		 WHERE COALESCE((settings->>'captionsOn')::boolean, false) = true`)
	if err != nil {
		w.logger.Warn("meet worker: captions crashed-session query failed", "error", err)
		return
	}
	var stale []captionsOnRow
	for rows.Next() {
		var r captionsOnRow
		if err := rows.Scan(&r.meetingID, &r.room, &r.since); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: captions crashed-session scan failed", "error", err)
			return
		}
		if !live[r.room.String()] && time.Since(r.since) > captionsGrace {
			stale = append(stale, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: captions crashed-session rows error", "error", err)
		return
	}
	for _, r := range stale {
		if _, err := w.pool.Exec(ctx, `
			UPDATE meetings SET settings = jsonb_set(settings, '{captionsOn}', 'false')
			 WHERE id = $1 AND COALESCE((settings->>'captionsOn')::boolean, false) = true`,
			r.meetingID); err != nil {
			w.logger.Warn("meet worker: captions crashed-session flag-off failed", "meeting_id", r.meetingID, "error", err)
			continue
		}
		// Two distinct params (not $1 reused): a repeated $1 used once as
		// bigint (p_meeting_id) and once concatenated as text leaves
		// Postgres unable to deduce one consistent type for it (42P08).
		if _, err := w.pool.Exec(ctx, `
			SELECT notify_meet_state($1, 'captions_state', jsonb_build_object('on', false, 'botIdentity', $2::text))`,
			r.meetingID, fmt.Sprintf("cc:%d", r.meetingID)); err != nil {
			w.logger.Warn("meet worker: captions crashed-session push failed", "meeting_id", r.meetingID, "error", err)
		}
	}
}

// reconcileCaptionsOrphaned is leg (b): every Status()-reported session
// (sessions may be empty — then this is a fast no-op, zero query) whose
// meeting is no longer captioning or has ended gets a retried Stop; an
// ended meeting additionally gets the DeleteRoom backstop once
// captionsSince clears the SAME grace leg (a) uses (the destructive leg
// only — Stop itself is idempotent on the sidecar and safe to retry at any
// age).
func (w *Worker) reconcileCaptionsOrphaned(ctx context.Context, sessions []string) {
	if len(sessions) == 0 {
		return
	}
	rows, err := w.pool.Query(ctx, `
		SELECT id, room_name, state, (settings->>'captionsSince')::timestamptz
		  FROM meetings
		 WHERE room_name::text = ANY($1::text[])
		   AND (COALESCE((settings->>'captionsOn')::boolean, false) = false OR state = 'ended')`,
		sessions)
	if err != nil {
		w.logger.Warn("meet worker: captions orphaned-session query failed", "error", err)
		return
	}
	type orphanRow struct {
		meetingID int64
		room      uuid.UUID
		state     string
		since     time.Time
	}
	var orphans []orphanRow
	for rows.Next() {
		var o orphanRow
		if err := rows.Scan(&o.meetingID, &o.room, &o.state, &o.since); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: captions orphaned-session scan failed", "error", err)
			return
		}
		orphans = append(orphans, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: captions orphaned-session rows error", "error", err)
		return
	}
	for _, o := range orphans {
		room := o.room.String()
		if err := w.captions.Stop(ctx, room); err != nil {
			w.logger.Warn("meet worker: captions retry-Stop failed", "meeting_id", o.meetingID, "room", room, "error", err)
		}
		if o.state == "ended" && time.Since(o.since) > captionsGrace {
			if err := w.rooms.DeleteRoom(ctx, room); err != nil {
				w.logger.Warn("meet worker: captions ended-meeting DeleteRoom backstop failed", "meeting_id", o.meetingID, "room", room, "error", err)
			}
		}
	}
}
