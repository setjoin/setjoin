// drive_history_emitter.go — the MEET Drive-History emitter (the named
// M4/M1 follow-up: "Drive History events", attached at the linkage point
// mailserver/internal/meet/DOX.md documents and
// retired-docs:verification/2026-09-19-old5-wave4.md records).
//
// The mechanism (the Drive lane's own prescription): Drive History stays
// the SOLE timeline owner. Its only surfaces are drive_audit_log (V114
// §9.3, the per-space tamper-evident chain "maintained exclusively by
// Drive's own reducers") and the drive_changes feed — a meet-side writer
// appending into Drive's chain would be the second-coordinator move the
// MEET plan forbids. So this file is only a THIN caller: it finds committed
// meet facts at the three frozen lifecycle points and drives them through
// the DRIVE-side ingest reducer (reducers/drive_meet_history_emit.sql),
// which appends via drive_access_audit — the owning chain writer — and
// records the idempotent receipt in drive_meet_history_events (V269). All
// resolution, the closed action catalog and the chain discipline live in
// the reducer; this leg holds no authority of its own (DES-011, the
// sweepSemanticPackages genre: reads are raw SQL, every write is a reducer
// call).
//
// The three lifecycle points (the closed contract; nothing else emits):
//   - recording.stopped      — a `.sjrec` package whose rec_state flipped
//     'stopped', attachable ONLY when the package has a ready export (the
//     rendition bound into Drive); an unexported package has no Drive home
//     and is receipted 'absent' inside the reducer, never synthesized.
//   - annotation.committed   — a V267 durable annotation ledger row,
//     attached to its session's pinned node/version.
//   - presentation.pinned    — a V265 session's pinned source identity,
//     attached to it.
//
// Gating posture: the B2/M4 drain posture verbatim (worker.go's header) —
// the leg runs BEFORE and OUTSIDE the feature gates, gated only on the pool
// existing, NEVER on a feature toggle: these are committed facts (they exist
// only because reducers committed them), so a toggle gates new intent, never
// the drain. Observational restraint: no bulk backfill (the leg converges
// committed facts FORWARD, one bounded batch per tick), the emitter never
// mutates meet state, and an emit failure logs-and-continues — the next
// tick retries through the receipt's idempotency (a replay re-enters the
// committed receipt instead of minting a second chain entry).
package meet

import (
	"context"
)

// driveHistoryBatchSize bounds each lifecycle leg per tick (the
// semanticBatchSize genre — a bounded worker can never wedge the whole
// sweep on one hot row).
const driveHistoryBatchSize = 16

// emitMeetDriveHistory is the worker tick's Drive-History leg: it drives
// the three lifecycle points through the Drive-side ingest, in the frozen
// contract's order (package stopped → annotation committed → presentation
// pinned). Chain order inside a space stays the chain writer's discipline
// (per-space advisory lock + MAX(id)+1) — the emitter contributes ordered
// human events, never its own ordering authority.
func (w *Worker) emitMeetDriveHistory(ctx context.Context) {
	w.emitDriveHistoryKind(ctx, "recording.stopped", `
		SELECT r.id
		  FROM meeting_semantic_recordings r
		 WHERE r.rec_state = 'stopped'
		   AND NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
		                    WHERE h.source_kind = 'recording.stopped'
		                      AND h.source_id = r.id)
		 ORDER BY r.id
		 LIMIT $1`)
	w.emitDriveHistoryKind(ctx, "annotation.committed", `
		SELECT a.id
		  FROM meeting_presentation_annotations a
		 WHERE NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
		                    WHERE h.source_kind = 'annotation.committed'
		                      AND h.source_id = a.id)
		 ORDER BY a.id
		 LIMIT $1`)
	w.emitDriveHistoryKind(ctx, "presentation.pinned", `
		SELECT p.id
		  FROM meeting_presentations p
		 WHERE NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
		                    WHERE h.source_kind = 'presentation.pinned'
		                      AND h.source_id = p.id)
		 ORDER BY p.id
		 LIMIT $1`)
}

// emitDriveHistoryKind drives one lifecycle point's un-emitted facts
// through the Drive-side ingest. A refused emit (unknown fact, transient DB
// error) is logged and left for the next tick — the receipt ledger's
// UNIQUE (source_kind, source_id) makes every retry re-enter the committed
// receipt, so no path can mint a second chain entry for one fact.
func (w *Worker) emitDriveHistoryKind(ctx context.Context, kind, query string) {
	rows, err := w.pool.Query(ctx, query, driveHistoryBatchSize)
	if err != nil {
		w.logger.Warn("meet worker: drive-history candidate query failed",
			"kind", kind, "error", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: drive-history candidate scan failed",
				"kind", kind, "error", err)
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: drive-history candidate rows error",
			"kind", kind, "error", err)
		return
	}

	for _, id := range ids {
		var out []byte
		if err := w.pool.QueryRow(ctx,
			`SELECT drive_meet_history_emit($1, $2)`, kind, id).Scan(&out); err != nil {
			w.logger.Warn("meet worker: drive-history emit refused",
				"kind", kind, "source_id", id, "error", err)
			continue
		}
		// The ingest's receipt JSON ({status, replayed, auditId, …}) is its
		// own bounded answer (a ~150-byte object, never payload bytes); the
		// emitted/absent/replayed disposition is committed state, so a
		// compact info line suffices.
		w.logger.Info("meet worker: drive-history fact ingested",
			"kind", kind, "source_id", id, "receipt", string(out))
	}
}
