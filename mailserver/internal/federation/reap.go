// reap.go — Pillar C2 Task 8 Step 3: the federation_inbox/federation_outbox
// residue reaper. Lives in its OWN file/type deliberately — NOT folded into
// service.go (Task 5's production Service, in-flight edits from the
// parallel Tasks 4-7 this task must not collide with): the reaper has zero
// dependency on the s2s transport (Dial/Listen/Sender/Receiver) — it only
// calls one DB reducer on a ticker, the exact shape of drive.NewWorker/
// meet.NewWorker (their own files, wired independently in
// cmd/mailserverd/main.go alongside — never inside — the packages whose
// transport they're adjacent to).
//
// D11 unconditional-drain posture (the same law recording/breakout/captions
// worker legs follow, mailserver/internal/meet/AGENTS.md): this runs
// regardless of feature.federation — residue reaps even while the toggle is
// OFF, and regardless of whether THIS box even has the s2s Service
// constructed (outbox/inbox rows can persist from federation traffic
// accepted before an admin removed this box's FEDERATION_LOCAL_DOMAIN/
// _CERT/_KEY env, or before feature.federation was flipped off) — so
// main.go wires ReapWorker unconditionally, NOT gated on
// federation.NewService's own static env gate.
//
// federation_reap.sql's header names the cursor-regression guard (Step 2,
// now landed in all three federation_apply_chat/_room/_inbound reducers)
// that makes this reaper safe against a malicious replay of a reaped
// sequence number — the cursor, not federation_inbox row presence, is the
// arbiter of "already applied."
package federation

import (
	"context"
	"log/slog"
	"time"

	"setjoin.com/shared/pgxutil"
)

// ReapInterval is the reap cadence — the plan's "a 1-hour ticker" (Task 8
// Step 3). Residue rows only ever grow slowly (at most one federation_inbox
// row per applied inbound frame, one federation_outbox row per enqueued
// outbound frame), so hourly is ample — the drive.NewWorker/meet.NewWorker
// precedent of "modest, not aggressive."
const ReapInterval = time.Hour

// reapKeep is federation_reap's own p_keep default (7 days) — named here so
// a future per-org tunable (none exists today; ponytail: a fixed retention
// window is enough until a customer's compliance policy asks for
// something else) has one place to change.
const reapKeep = "7 days"

// ReapWorker drains federation_inbox/federation_outbox residue past its
// retention window (federation_reap.sql) — envelope-only bookkeeping rows,
// never chat content (chat_purge_expired is the one place chat content
// dies; federation_outbox_redact_purged.sql is how a purge scrubs the
// outbox BEFORE this reaper would otherwise reap it late, on its own
// 1-hour-vs-7-day-later cadence).
type ReapWorker struct {
	pool   pgxutil.WorkerPool
	logger *slog.Logger
}

// NewReapWorker builds the reap worker. Unconditional construction+start in
// main.go (the drive.NewWorker/meet.NewWorker posture) — never gated on the
// s2s Service's own static config gate (see the package doc comment above).
func NewReapWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *ReapWorker {
	return &ReapWorker{pool: pool, logger: logger}
}

// Run starts the ticker loop; exits cleanly when ctx is cancelled. Reaps
// once immediately at startup too (not just after the first hour elapses —
// a box that was down past the retention window for a while shouldn't wait
// another hour to catch up).
func (w *ReapWorker) Run(ctx context.Context) {
	w.logger.Info("federation reap worker started", "interval", ReapInterval)
	w.tick(ctx)
	ticker := time.NewTicker(ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("federation reap worker stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *ReapWorker) tick(ctx context.Context) {
	var result []byte
	if err := w.pool.QueryRow(ctx, `SELECT federation_reap($1::interval)`, reapKeep).Scan(&result); err != nil {
		w.logger.Error("federation: reap tick failed", "error", err)
		return
	}
	w.logger.Debug("federation: reap tick", "result", string(result))
}
